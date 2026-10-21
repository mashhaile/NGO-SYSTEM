const Expense = require("../../models/Expense");

const {
    EXPENSE_STATUS
} = require("../../models/Expense");

const Donation = require("../../models/donation");

const {
    buildPeriodFilter
} = require("./reportFilters");

const {
    roundMoney,
    percent,
    toObjectId,
    organizationObjectId,
    assertBudgetAccess
} = require("./financeReportHelpers");


// =====================================================
// SPENDING BY DONOR
// =====================================================
//
// Approved expenses in the period, by donor and by
// donation (the "Paid from donation" link). Expenses with
// no donation link are reported separately as
// "Not linked to a donation", so untraced spending is
// visible rather than hidden.
//
// Amounts are in each budget's currency; a donation's
// "used" share is only computed when its currency matches.
//
// =====================================================

const generate = async (filters = {}, context) => {

    assertBudgetAccess(context);

    const match = {
        organization: organizationObjectId(context),
        status: EXPENSE_STATUS.APPROVED,
        isDeleted: false,
        ...buildPeriodFilter(filters, "expenseDate")
    };

    if (toObjectId(filters.program)) match.program = toObjectId(filters.program);
    if (toObjectId(filters.project)) match.project = toObjectId(filters.project);

    // Donor filter: only expenses paid from that donor's donations
    if (toObjectId(filters.donor)) {
        const donationIds =
            await Donation.find({ organization: match.organization, donor: toObjectId(filters.donor) }).distinct("_id");
        match.donation = { $in: donationIds };
    }

    const expenses =
        await Expense.find(match)
            .populate({
                path: "donation",
                select: "donationCode title amount currency donor",
                populate: { path: "donor", select: "name donorCode" }
            })
            .populate("project", "projectCode name")
            .sort({ expenseDate: 1 })
            .lean();


    const byDonation = new Map();
    const byDonor = new Map();
    let unlinked = { count: 0, totals: {} };

    const addTotal = (bucket, currency, amount) => {
        bucket[currency] = roundMoney((bucket[currency] || 0) + amount);
    };

    for (const expense of expenses) {

        const donation = expense.donation;

        if (!donation) {
            unlinked.count += 1;
            addTotal(unlinked.totals, expense.budgetCurrency, expense.budgetAmount);
            continue;
        }

        const key = String(donation._id);

        if (!byDonation.has(key)) {
            byDonation.set(key, { donation, count: 0, totals: {} });
        }
        const entry = byDonation.get(key);
        entry.count += 1;
        addTotal(entry.totals, expense.budgetCurrency, expense.budgetAmount);

        const donorKey = String(donation.donor?._id || "none");
        if (!byDonor.has(donorKey)) {
            byDonor.set(donorKey, { donor: donation.donor, donations: new Set(), count: 0, totals: {} });
        }
        const donorEntry = byDonor.get(donorKey);
        donorEntry.donations.add(key);
        donorEntry.count += 1;
        addTotal(donorEntry.totals, expense.budgetCurrency, expense.budgetAmount);

    }

    const formatTotals = (totals) =>
        Object.entries(totals)
            .map(([currency, amount]) => `${currency} ${amount.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`)
            .join(" + ") || "-";


    const donationRows =
        [...byDonation.values()].map(({ donation, count, totals }) => {
            const sameCurrency = totals[donation.currency];
            const onlyThatCurrency = Object.keys(totals).length === 1 && sameCurrency !== undefined;
            return {
                donationCode: donation.donationCode,
                donation: donation.title,
                donor: donation.donor?.name || "",
                donationAmount: roundMoney(donation.amount),
                donationCurrency: donation.currency,
                expenses: count,
                spent: formatTotals(totals),
                remaining: onlyThatCurrency ? roundMoney(donation.amount - sameCurrency) : "n/a (other currency)",
                percentUsed: onlyThatCurrency ? percent(sameCurrency, donation.amount) : "n/a"
            };
        });

    const donorRows =
        [...byDonor.values()].map(({ donor, donations, count, totals }) => ({
            donor: donor?.name || "(no donor)",
            donations: donations.size,
            expenses: count,
            spent: formatTotals(totals)
        }));

    const linkedTotals = {};
    for (const entry of byDonation.values()) {
        for (const [currency, amount] of Object.entries(entry.totals)) addTotal(linkedTotals, currency, amount);
    }

    const allTotals = { ...linkedTotals };
    for (const [currency, amount] of Object.entries(unlinked.totals)) addTotal(allTotals, currency, amount);

    const details =
        expenses.map(expense => ({
            date: expense.expenseDate,
            expenseCode: expense.expenseCode,
            description: expense.description,
            project: expense.project?.name || "",
            category: expense.category,
            donor: expense.donation?.donor?.name || "",
            donation: expense.donation ? `${expense.donation.donationCode} ${expense.donation.title}` : "Not linked to a donation",
            amount: expense.budgetAmount,
            currency: expense.budgetCurrency
        }));

    return {

        title: "Spending by Donor",

        summary: {
            approvedExpenses: expenses.length,
            donorsWithSpending: donorRows.length,
            totalSpent: formatTotals(allTotals),
            linkedToDonations: formatTotals(linkedTotals),
            notLinkedToADonation: formatTotals(unlinked.totals),
            expensesNotLinked: unlinked.count
        },

        statistics: {
            byDonor: donorRows,
            byDonation: donationRows
        },

        charts: {},

        details

    };

};


module.exports = {
    generate
};
