// =====================================================
// BUDGET & SPENDING REPORT
// =====================================================
//
// For the fiscal year of the period (calendar year), the
// approved budgets against approved expenses: per project
// budget, per category, per donor, per month, the lines
// over budget, and how much of each program's envelope
// is given to its projects. Replaces Budget vs Actual and
// Spending by Donor.
//
//   Budget    the lines' amounts for the fiscal year
//   Spent     approved expenses dated in the period
//   Pending   draft, submitted or returned expenses
//
// Amounts are in each budget's own currency and never
// added across currencies. Needs budget.read.
//
// Filters: program, project
//
// =====================================================

const Budget = require("../../../models/Budget");
const Expense = require("../../../models/Expense");

const {
    scope, formatTotals, objectId, toId, round2, toNumber, percent, groupRows,
    summaryItem, column, section, buildReport
} = require("../core");

const { inPeriod, monthKey, monthName } = require("../period");


const PENDING = ["Draft", "Submitted", "Returned"];

const addTo = (totals, currency, amount) => {
    const key = currency || "ETB";
    totals[key] = round2((totals[key] || 0) + toNumber(amount));
    return totals;
};

const yearAmount = (line, year) =>
    toNumber((line.amounts || []).find(item => Number(item.fiscalYear) === Number(year))?.amount);


const generate = async (query, context, period) => {

    const { organizationId } = context;

    // the fiscal year the budgets are read for
    const year = period.year || (period.start ? new Date(period.start.getTime() + 3 * 3600 * 1000).getUTCFullYear() : new Date().getFullYear());

    const filter = { status: "Approved", startYear: { $lte: year }, endYear: { $gte: year } };
    if (objectId(query.program)) filter.program = objectId(query.program);
    if (objectId(query.project)) filter.project = objectId(query.project);

    const budgets =
        await Budget.find(scope(organizationId, filter))
            .populate("program", "programCode name")
            .populate("project", "projectCode name")
            .sort({ budgetCode: 1 })
            .lean();

    const projectBudgets = budgets.filter(budget => budget.level === "project");
    const programBudgets = budgets.filter(budget => budget.level === "program");

    const expenseDate = inPeriod(period);
    const expenses =
        projectBudgets.length
            ? await Expense.find(scope(organizationId, {
                budget: { $in: projectBudgets.map(budget => budget._id) },
                status: { $in: ["Approved", ...PENDING] },
                ...(expenseDate ? { expenseDate } : {})
            }))
                .populate({ path: "donation", select: "donationCode title donor", populate: { path: "donor", select: "name" } })
                .lean()
            : [];

    const approved = expenses.filter(expense => expense.status === "Approved");
    const pending = expenses.filter(expense => PENDING.includes(expense.status));
    const amountOf = (expense) => toNumber(expense.budgetAmount ?? expense.amount);

    // ---------- per project budget ----------
    const budgetRows = projectBudgets.map(budget => {
        const id = toId(budget._id);
        const plan = (budget.lines || []).reduce((sum, line) => sum + yearAmount(line, year), 0);
        const spent = approved.filter(expense => toId(expense.budget) === id).reduce((sum, expense) => sum + amountOf(expense), 0);
        const waiting = pending.filter(expense => toId(expense.budget) === id).reduce((sum, expense) => sum + amountOf(expense), 0);
        return {
            id,
            code: budget.budgetCode,
            name: budget.name,
            program: budget.program?.name || "",
            project: budget.project?.name || "",
            currency: budget.currency || "ETB",
            budget: round2(plan),
            spent: round2(spent),
            pending: round2(waiting),
            remaining: round2(plan - spent),
            used: percent(spent, plan),
            flag: spent > plan + 0.01 ? "Over budget" : plan > 0 && spent / plan > 0.9 ? "Nearly used" : ""
        };
    });

    // ---------- per line (category, over budget) ----------
    const lines = [];
    for (const budget of projectBudgets) {
        for (const line of budget.lines || []) {
            const spent = approved.filter(expense => toId(expense.budget) === toId(budget._id) && toId(expense.budgetLine) === toId(line._id))
                .reduce((sum, expense) => sum + amountOf(expense), 0);
            lines.push({ budget, line, plan: yearAmount(line, year), spent, currency: budget.currency || "ETB" });
        }
    }

    const categoryRows = (() => {
        const map = new Map();
        for (const entry of lines) {
            const key = `${entry.line.category || "Other"}|${entry.currency}`;
            const row = map.get(key) || { label: entry.line.category || "Other", currency: entry.currency, budget: 0, spent: 0 };
            row.budget += entry.plan;
            row.spent += entry.spent;
            map.set(key, row);
        }
        return [...map.values()].map(row => ({ ...row, budget: round2(row.budget), spent: round2(row.spent), remaining: round2(row.budget - row.spent), used: percent(row.spent, row.budget) }))
            .sort((a, b) => b.budget - a.budget);
    })();

    const overRows = lines.filter(entry => entry.spent > entry.plan + 0.01).map(entry => ({
        id: toId(entry.budget._id),
        budget: entry.budget.budgetCode,
        project: entry.budget.project?.name || "",
        line: entry.line.description || entry.line.category,
        category: entry.line.category,
        currency: entry.currency,
        plan: round2(entry.plan),
        spent: round2(entry.spent),
        over: round2(entry.spent - entry.plan)
    }));

    // ---------- by donor (and spending no donor sees) ----------
    const donorRows = (() => {
        const map = new Map();
        for (const expense of approved) {
            const budget = projectBudgets.find(item => toId(item._id) === toId(expense.budget));
            const currency = budget?.currency || "ETB";
            const donor = expense.donation ? expense.donation.donor?.name || "Unknown donor" : "Not linked to a donation";
            const donation = expense.donation ? `${expense.donation.donationCode || ""} ${expense.donation.title || ""}`.trim() : "—";
            const key = `${donor}|${donation}|${currency}`;
            const row = map.get(key) || { id: toId(expense.donation?._id), label: donor, donation, currency, expenses: 0, spent: 0 };
            row.expenses += 1;
            row.spent += amountOf(expense);
            map.set(key, row);
        }
        return [...map.values()].map(row => ({ ...row, spent: round2(row.spent) })).sort((a, b) => b.spent - a.spent);
    })();

    const monthRows = (() => {
        const map = new Map();
        for (const expense of approved) {
            const budget = projectBudgets.find(item => toId(item._id) === toId(expense.budget));
            const currency = budget?.currency || "ETB";
            const key = `${monthKey(expense.expenseDate)}|${currency}`;
            const row = map.get(key) || { key: monthKey(expense.expenseDate), currency, expenses: 0, spent: 0 };
            row.expenses += 1;
            row.spent += amountOf(expense);
            map.set(key, row);
        }
        return [...map.values()].sort((a, b) => a.key.localeCompare(b.key)).map(row => ({ label: monthName(row.key), currency: row.currency, expenses: row.expenses, spent: round2(row.spent) }));
    })();

    const envelopeRows = programBudgets.map(budget => {
        const envelope = (budget.yearlyAmounts || []).find(item => Number(item.fiscalYear) === year)?.amount ??
            (budget.lines || []).reduce((sum, line) => sum + yearAmount(line, year), 0);
        const given = budgetRows.filter(row => projectBudgets.find(item => toId(item._id) === row.id && toId(item.program?._id) === toId(budget.program?._id)))
            .reduce((sum, row) => sum + row.budget, 0);
        return {
            program: budget.program?.name || budget.name,
            currency: budget.currency || "ETB",
            envelope: round2(envelope),
            projects: round2(given),
            free: round2(toNumber(envelope) - given)
        };
    });

    const totalsOf = (rows, key) => rows.reduce((totals, row) => addTo(totals, row.currency, row[key]), {});
    const untraced = approved.filter(expense => !expense.donation)
        .reduce((totals, expense) => addTo(totals, projectBudgets.find(item => toId(item._id) === toId(expense.budget))?.currency, amountOf(expense)), {});

    return buildReport({
        key: "budgets",
        title: "Budget & spending",
        description: `Approved budgets for FY ${year} against approved expenses dated in the period. Amounts are in each budget's currency.`,
        period,
        summary: [
            summaryItem("Project budgets", budgetRows.length),
            summaryItem(`Budget for FY ${year}`, formatTotals(totalsOf(budgetRows, "budget")), "text"),
            summaryItem("Spent", formatTotals(totalsOf(budgetRows, "spent")), "text"),
            summaryItem("Waiting for approval", formatTotals(totalsOf(budgetRows, "pending")), "text"),
            summaryItem("Remaining", formatTotals(totalsOf(budgetRows, "remaining")), "text"),
            summaryItem("Lines over budget", overRows.length),
            summaryItem("Spending not linked to a donation", formatTotals(untraced), "text")
        ],
        sections: [
            section("category", "By category", [
                column("label", "Category"),
                column("budget", "Budget", "money"),
                column("spent", "Spent", "money"),
                column("remaining", "Remaining", "money"),
                column("used", "Used", "percent"),
                column("currency", "Currency")
            ], categoryRows, { chart: { type: "bar", x: "label", series: ["budget", "spent"] } }),
            section("donor", "Spending by donor", [
                column("label", "Donor"),
                column("donation", "Donation"),
                column("expenses", "Expenses", "number"),
                column("spent", "Spent", "money"),
                column("currency", "Currency")
            ], donorRows, { link: { kind: "donation", idKey: "id" }, note: "Spending not linked to a donation appears in no donor's report." }),
            section("month", "Spending by month", [
                column("label", "Month"),
                column("expenses", "Expenses", "number"),
                column("spent", "Spent", "money"),
                column("currency", "Currency")
            ], monthRows, { chart: { type: "bar", x: "label", series: ["spent"] } }),
            overRows.length
                ? section("over", "Lines over budget", [
                    column("budget", "Budget"),
                    column("project", "Project"),
                    column("line", "Line"),
                    column("plan", "Budget", "money"),
                    column("spent", "Spent", "money"),
                    column("over", "Over by", "money"),
                    column("currency", "Currency")
                ], overRows, { link: { kind: "budget", idKey: "id" } })
                : null,
            envelopeRows.length
                ? section("envelopes", `Program envelopes, FY ${year}`, [
                    column("program", "Program"),
                    column("envelope", "Envelope", "money"),
                    column("projects", "Given to projects", "money"),
                    column("free", "Not yet given", "money"),
                    column("currency", "Currency")
                ], envelopeRows)
                : null
        ],
        details: {
            title: "Project budgets",
            link: { kind: "budget", idKey: "id" },
            columns: [
                column("code", "Budget"),
                column("project", "Project"),
                column("program", "Program"),
                column("currency", "Currency"),
                column("budget", `Budget FY ${year}`, "money"),
                column("spent", "Spent", "money"),
                column("pending", "Waiting", "money"),
                column("remaining", "Remaining", "money"),
                column("used", "Used", "percent"),
                column("flag", "Note")
            ],
            rows: budgetRows
        }
    });

};


module.exports = {
    key: "budgets",
    title: "Budget & spending",
    description: "Approved budgets against spending: by budget, category, donor and month, lines over budget.",
    filters: ["program", "project"],
    permission: "budget.read",
    generate
};
