const Donation = require("../../models/donation");

const {
    buildDateFilter
} = require("./reportFilters");

const {
    formatTotals
} = require("../budgetFigures");


// =====================================================
// FINANCIAL REPORT (donations received per month)
// =====================================================
// Received donations only (pledged = not yet received,
// cancelled = never). Amounts in different currencies are
// never added together: one row per month and currency,
// totals per currency. Charts use ETB (the base currency).

const generate = async (
    filters,
    context
) => {

    const { organizationId } = context;

    const monthly =
        await Donation.aggregate([
            {
                $match: {
                    organization: organizationId,
                    isDeleted: false,
                    status: "Received",
                    ...buildDateFilter(filters, "donationDate")
                }
            },
            {
                $group: {
                    _id: {
                        year: { $year: "$donationDate" },
                        month: { $month: "$donationDate" },
                        currency: { $ifNull: ["$currency", "ETB"] }
                    },
                    totalAmount: { $sum: "$amount" },
                    totalDonations: { $sum: 1 }
                }
            },
            { $sort: { "_id.year": 1, "_id.month": 1, "_id.currency": 1 } }
        ]);

    const details =
        monthly.map(item => ({
            year: item._id.year,
            month: item._id.month,
            currency: item._id.currency,
            totalDonations: item.totalDonations,
            amount: formatTotals({ [item._id.currency]: item.totalAmount })
        }));

    const totals = {};
    for (const item of monthly) {
        totals[item._id.currency] = (totals[item._id.currency] || 0) + item.totalAmount;
    }

    const etbMonths = monthly.filter(item => item._id.currency === "ETB");

    return {

        title: "Financial Report",

        summary: {
            totalMonths: new Set(monthly.map(item => `${item._id.year}-${item._id.month}`)).size,
            totalDonations: monthly.reduce((sum, item) => sum + item.totalDonations, 0),
            totalReceived: formatTotals(totals)
        },

        statistics: {},

        charts: {
            monthlyFunding: etbMonths.map(item => ({
                label: `${item._id.month}/${item._id.year} (ETB)`,
                amount: item.totalAmount
            })),
            monthlyDonations: details.map(item => ({
                label: `${item.month}/${item.year} ${item.currency}`,
                donations: item.totalDonations
            }))
        },

        details

    };

};


module.exports = {
    generate
};
