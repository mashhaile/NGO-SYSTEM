const mongoose = require("mongoose");

const Budget = require("../models/Budget");
const Expense = require("../models/Expense");

const { BUDGET_STATUS, BUDGET_LEVEL } = Budget;
const { EXPENSE_STATUS } = Expense;


// =====================================================
// BUDGET FIGURES FOR PROGRAMS / PROJECTS
// =====================================================
// The Budgets module is the only source of budget numbers.
// Programs, projects, lists and reports read their budget
// from here instead of a number typed on the program or
// project form.
//
// Each program / project has at most one active budget.
// A figure is returned for it whatever its status; only an
// Approved budget counts as "approved" (approvedAmount).
//
//   { budgetId, budgetCode, status, currency, startYear,
//     endYear, totalAmount, approvedAmount, spent, remaining }
//
// spent = approved expenses. For a program budget it is the
// spent of the project budgets in that program.

const roundMoney = (value) => Math.round(Number(value || 0) * 100) / 100;

const toObjectIds = (ids) =>
    [...new Set(ids.filter(id => mongoose.isValidObjectId(id)).map(String))]
        .map(id => new mongoose.Types.ObjectId(id));


// Approved expenses per budget
const spentByBudget = async (organizationId, budgetIds) => {

    if (!budgetIds.length) return {};

    const rows =
        await Expense.aggregate([
            {
                $match: {
                    organization: new mongoose.Types.ObjectId(String(organizationId)),
                    budget: { $in: budgetIds },
                    isDeleted: false,
                    status: EXPENSE_STATUS.APPROVED
                }
            },
            { $group: { _id: "$budget", total: { $sum: "$budgetAmount" } } }
        ]);

    return Object.fromEntries(rows.map(row => [String(row._id), roundMoney(row.total)]));

};


const figureOf = (budget, spent) => {

    const approvedAmount =
        budget.status === BUDGET_STATUS.APPROVED ? roundMoney(budget.totalAmount) : 0;

    return {
        budgetId: budget._id,
        budgetCode: budget.budgetCode,
        status: budget.status,
        currency: budget.currency,
        startYear: budget.startYear,
        endYear: budget.endYear,
        totalAmount: roundMoney(budget.totalAmount),
        approvedAmount,
        spent: roundMoney(spent),
        remaining: roundMoney(approvedAmount - spent)
    };

};


// { programs: { [programId]: figure }, projects: { [projectId]: figure } }
const getBudgetFigures = async (organizationId, { programIds = [], projectIds = [] } = {}) => {

    const programObjectIds = toObjectIds(programIds);
    const projectObjectIds = toObjectIds(projectIds);

    if (!programObjectIds.length && !projectObjectIds.length) {
        return { programs: {}, projects: {} };
    }

    const organization = new mongoose.Types.ObjectId(String(organizationId));

    // Program budgets, plus every project budget of those programs
    // (a program's spent is what its projects spent)
    const budgets =
        await Budget.find({
            organization,
            isDeleted: false,
            $or: [
                ...(programObjectIds.length ? [{ program: { $in: programObjectIds } }] : []),
                ...(projectObjectIds.length ? [{ level: BUDGET_LEVEL.PROJECT, project: { $in: projectObjectIds } }] : [])
            ]
        })
            .select("budgetCode level program project status currency startYear endYear totalAmount")
            .lean();

    const spent = await spentByBudget(organizationId, budgets.map(budget => budget._id));

    const programs = {};
    const projects = {};

    const projectBudgets = budgets.filter(budget => budget.level === BUDGET_LEVEL.PROJECT);

    for (const budget of projectBudgets) {
        projects[String(budget.project)] = figureOf(budget, spent[String(budget._id)] || 0);
    }

    for (const budget of budgets.filter(item => item.level === BUDGET_LEVEL.PROGRAM)) {
        const programSpent =
            projectBudgets
                .filter(item => String(item.program) === String(budget.program))
                .reduce((total, item) => total + (spent[String(item._id)] || 0), 0);
        programs[String(budget.program)] = figureOf(budget, programSpent);
    }

    // Only what was asked for
    const pick = (map, ids) =>
        Object.fromEntries(ids.map(String).filter(id => map[id]).map(id => [id, map[id]]));

    return {
        programs: pick(programs, programObjectIds),
        projects: pick(projects, projectObjectIds)
    };

};


// Approved amounts added up per currency: { ETB: 6500000, USD: 20000 }
const approvedTotalsByCurrency = (figures) => {

    const totals = {};

    for (const figure of figures) {
        if (!figure || !figure.approvedAmount) continue;
        totals[figure.currency] = roundMoney((totals[figure.currency] || 0) + figure.approvedAmount);
    }

    return totals;

};


// "ETB 6,500,000.00" or "ETB 6,500,000.00 + USD 20,000.00" ("-" when none)
const formatTotals = (totals) => {

    const entries = Object.entries(totals);

    if (!entries.length) return "-";

    return entries
        .map(([currency, amount]) =>
            `${currency} ${Number(amount).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`)
        .join(" + ");

};


module.exports = {
    getBudgetFigures,
    approvedTotalsByCurrency,
    formatTotals
};
