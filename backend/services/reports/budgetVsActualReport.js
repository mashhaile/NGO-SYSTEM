const Budget = require("../../models/Budget");

const {
    BUDGET_STATUS,
    BUDGET_LEVEL
} = require("../../models/Budget");

const {
    totalsByLine
} = require("../expenseService");

const {
    roundMoney,
    percent,
    toObjectId,
    organizationObjectId,
    assertBudgetAccess,
    reportFiscalYear,
    yearElapsedPercent,
    burnStatus
} = require("./financeReportHelpers");


// =====================================================
// BUDGET VS ACTUAL
// =====================================================
//
// For one fiscal year (calendar year: filters.year, the
// start date's year, or the current year), every APPROVED
// project budget covering that year:
//
//   Budget    = the line's amount for the year
//   Spent     = approved expenses
//   Pending   = draft / submitted / returned expenses
//   Remaining = Budget - Spent
//
// Burn rate compares % spent with % of the year passed.
// Totals are kept per currency (budgets may differ).
//
// =====================================================

const generate = async (filters = {}, context) => {

    assertBudgetAccess(context);

    const fiscalYear = reportFiscalYear(filters);
    const elapsed = yearElapsedPercent(fiscalYear);

    const match = {
        organization: organizationObjectId(context),
        level: BUDGET_LEVEL.PROJECT,
        status: BUDGET_STATUS.APPROVED,
        isDeleted: false,
        startYear: { $lte: fiscalYear },
        endYear: { $gte: fiscalYear }
    };

    if (toObjectId(filters.program)) match.program = toObjectId(filters.program);
    if (toObjectId(filters.project)) match.project = toObjectId(filters.project);

    const budgets =
        await Budget.find(match)
            .populate("program", "programCode name")
            .populate("project", "projectCode name")
            .sort({ budgetCode: 1 })
            .lean();

    const totals =
        await totalsByLine(context.organizationId, budgets.map(budget => budget._id));

    const lineRows = [];
    const projectRows = [];

    for (const budget of budgets) {

        const project = { budget: 0, spent: 0, pending: 0 };

        for (const line of budget.lines || []) {

            const amount = roundMoney(line.amounts.find(item => item.fiscalYear === fiscalYear)?.amount || 0);
            const actual = totals[String(line._id)]?.[fiscalYear] || { spent: 0, pending: 0 };

            if (!amount && !actual.spent && !actual.pending) continue;

            const remaining = roundMoney(amount - actual.spent);

            lineRows.push({
                fiscalYear: `FY ${fiscalYear}`,
                budgetCode: budget.budgetCode,
                program: budget.program?.name || "",
                project: budget.project?.name || "",
                category: line.category,
                line: line.description || "",
                currency: budget.currency,
                budget: amount,
                spent: actual.spent,
                pending: actual.pending,
                remaining,
                percentUsed: percent(actual.spent, amount),
                status: actual.spent > amount + 0.005 ? "Over budget" : "Within budget"
            });

            project.budget += amount;
            project.spent += actual.spent;
            project.pending += actual.pending;

        }

        const percentSpent = percent(project.spent, project.budget);

        projectRows.push({
            budgetCode: budget.budgetCode,
            project: budget.project?.name || "",
            program: budget.program?.name || "",
            currency: budget.currency,
            budget: roundMoney(project.budget),
            spent: roundMoney(project.spent),
            pending: roundMoney(project.pending),
            remaining: roundMoney(project.budget - project.spent),
            percentSpent,
            percentOfYearPassed: elapsed,
            burnRate: burnStatus(percentSpent, elapsed)
        });

    }


    // Totals per currency

    const byCurrency = {};

    for (const row of projectRows) {
        const entry = byCurrency[row.currency] || (byCurrency[row.currency] = { currency: row.currency, budgets: 0, budget: 0, spent: 0, pending: 0 });
        entry.budgets += 1;
        entry.budget = roundMoney(entry.budget + row.budget);
        entry.spent = roundMoney(entry.spent + row.spent);
        entry.pending = roundMoney(entry.pending + row.pending);
    }

    const currencyRows =
        Object.values(byCurrency).map(entry => ({
            ...entry,
            remaining: roundMoney(entry.budget - entry.spent),
            percentSpent: percent(entry.spent, entry.budget)
        }));

    const overBudget = lineRows.filter(row => row.status === "Over budget");

    // One currency: headline totals. Several: see the table.
    const single = currencyRows.length === 1 ? currencyRows[0] : null;

    return {

        title: `Budget vs Actual — FY ${fiscalYear}`,

        summary: {
            fiscalYear: `FY ${fiscalYear}`,
            projectBudgets: budgets.length,
            ...(single
                ? {
                    currency: single.currency,
                    totalBudget: single.budget,
                    totalSpent: single.spent,
                    totalPending: single.pending,
                    totalRemaining: single.remaining,
                    percentSpent: single.percentSpent
                }
                : { currencies: currencyRows.map(row => row.currency).join(", ") || "-" }),
            percentOfYearPassed: elapsed,
            linesOverBudget: overBudget.length
        },

        statistics: {
            byProject: projectRows,
            overBudgetLines: overBudget,
            ...(currencyRows.length > 1 ? { totalsByCurrency: currencyRows } : {})
        },

        // One value per bar (what the chart component shows)
        charts: {
            spentByProject:
                projectRows.map(row => ({ label: row.project || row.budgetCode, spent: row.spent })),
            budgetByProject:
                projectRows.map(row => ({ label: row.project || row.budgetCode, budget: row.budget }))
        },

        details: lineRows

    };

};


module.exports = {
    generate
};
