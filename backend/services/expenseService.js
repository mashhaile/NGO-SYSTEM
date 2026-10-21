const mongoose = require("mongoose");

const Expense = require("../models/Expense");

const {
    EXPENSE_STATUS
} = require("../models/Expense");

const Budget = require("../models/Budget");

const {
    BUDGET_STATUS,
    BUDGET_LEVEL
} = require("../models/Budget");

const Donation = require("../models/donation");

const Activity = require("../models/Activity");

const ApiError = require("../utils/apiError");

const escapeRegex = require("../utils/escapeRegex");

const generateSequence = require("../utils/generateSequence");

const {
    runInTransaction
} = require("../utils/transaction");

const {
    fiscalYearOf,
    fiscalYearLabel
} = require("../utils/fiscalYear");


// =====================================================
// RULES
// =====================================================
//
// - Charged to one line of an APPROVED project budget;
//   the expense date's fiscal year must be in the budget.
// - Spent = Approved expenses only.
// - Submitting past the line's budget is allowed but
//   flagged; APPROVING past it needs allowOverBudget plus a
//   comment from the approver.
// - Approve / void run in a transaction that also bumps
//   budget.chargeVersion, so concurrent approvals on the
//   same budget cannot both pass the remaining check.
// - Approved expenses are never edited or deleted; a
//   mistake is voided with a reason.
//
// =====================================================

const EDITABLE = [EXPENSE_STATUS.DRAFT, EXPENSE_STATUS.RETURNED];

const PENDING = [EXPENSE_STATUS.DRAFT, EXPENSE_STATUS.SUBMITTED, EXPENSE_STATUS.RETURNED];

const USER_FIELDS = "name email";

const DETAIL_POPULATE = [
    { path: "budget", select: "budgetCode name currency startYear endYear status" },
    { path: "program", select: "programCode name" },
    { path: "project", select: "projectCode name" },
    { path: "donation", select: "donationCode title amount currency" },
    { path: "activity", select: "activityCode name" },
    { path: "createdBy", select: USER_FIELDS },
    { path: "submittedBy", select: USER_FIELDS },
    { path: "approvedBy", select: USER_FIELDS },
    { path: "voidedBy", select: USER_FIELDS },
    { path: "history.by", select: USER_FIELDS }
];


// =====================================================
// HELPERS
// =====================================================

const roundMoney = (value) => {
    const number = Number(value);
    return Number.isFinite(number) ? Math.round(number * 100) / 100 : 0;
};

const money = (amount, currency) =>
    `${currency} ${Number(amount).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

const notFound = () => new ApiError("Expense not found.", 404);

const assertId = (id) => {
    if (!mongoose.isValidObjectId(id)) throw notFound();
};

const historyEntry = (action, status, userId, comment = "") => ({
    action, status, comment, by: userId, at: new Date()
});

const emptyToNull = (value) =>
    value === "" || value === undefined ? null : value;


// The budget + line an expense is charged to

const resolveCharge = async (organizationId, budgetId, lineId, expenseDate, session = null) => {

    if (!mongoose.isValidObjectId(budgetId) || !mongoose.isValidObjectId(lineId)) {
        throw new ApiError("Select the budget and the budget line.", 400);
    }

    const budget =
        await Budget.findOne({ _id: budgetId, organization: organizationId, isDeleted: false })
            .session(session);

    if (!budget || budget.level !== BUDGET_LEVEL.PROJECT) {
        throw new ApiError("Project budget not found.", 404);
    }

    if (budget.status !== BUDGET_STATUS.APPROVED) {
        throw new ApiError(
            `Expenses can only be charged to an approved budget (${budget.budgetCode} is ${budget.status.toLowerCase()}).`,
            400
        );
    }

    const line = budget.lines.id(lineId);

    if (!line) {
        throw new ApiError("Budget line not found in this budget.", 404);
    }

    const date = new Date(expenseDate);

    if (Number.isNaN(date.getTime())) {
        throw new ApiError("Enter a valid expense date.", 400);
    }

    const fiscalYear = fiscalYearOf(date);

    if (fiscalYear < budget.startYear || fiscalYear > budget.endYear) {
        throw new ApiError(
            `${fiscalYearLabel(fiscalYear)} is outside this budget (${fiscalYearLabel(budget.startYear)}–${fiscalYearLabel(budget.endYear)}).`,
            400
        );
    }

    const lineBudget =
        roundMoney(line.amounts.find(item => item.fiscalYear === fiscalYear)?.amount || 0);

    return { budget, line, fiscalYear, lineBudget, date };

};


const convert = (amount, currency, exchangeRate, budgetCurrency) => {

    const value = roundMoney(amount);

    if (!(value > 0)) {
        throw new ApiError("The amount must be greater than zero.", 400);
    }

    const code = String(currency || budgetCurrency).toUpperCase();

    if (code === budgetCurrency) {
        return { amount: value, currency: code, exchangeRate: 1, budgetAmount: value };
    }

    const rate = Number(exchangeRate);

    if (!(rate > 0)) {
        throw new ApiError(
            `Enter the exchange rate from ${code} to ${budgetCurrency} (the budget's currency).`,
            400
        );
    }

    return { amount: value, currency: code, exchangeRate: rate, budgetAmount: roundMoney(value * rate) };

};


// Approved and pending amounts on one line for one year

const lineTotals = async (organizationId, budgetId, lineId, fiscalYear, excludeId = null, session = null) => {

    const match = {
        organization: new mongoose.Types.ObjectId(String(organizationId)),
        budget: new mongoose.Types.ObjectId(String(budgetId)),
        budgetLine: new mongoose.Types.ObjectId(String(lineId)),
        fiscalYear,
        isDeleted: false
    };

    if (excludeId) {
        match._id = { $ne: new mongoose.Types.ObjectId(String(excludeId)) };
    }

    const rows =
        await Expense.aggregate([
            { $match: match },
            { $group: { _id: "$status", total: { $sum: "$budgetAmount" } } }
        ]).session(session);

    const byStatus = Object.fromEntries(rows.map(row => [row._id, row.total]));

    return {
        spent: roundMoney(byStatus[EXPENSE_STATUS.APPROVED] || 0),
        pending: roundMoney(PENDING.reduce((sum, status) => sum + (byStatus[status] || 0), 0))
    };

};


const optionalLinks = async (organizationId, data) => {

    const links = {};

    if (data.donation !== undefined) {
        const id = emptyToNull(data.donation);
        if (id) {
            const donation = await Donation.exists({ _id: id, organization: organizationId, isDeleted: { $ne: true } });
            if (!donation) throw new ApiError("Donation not found.", 404);
        }
        links.donation = id;
    }

    if (data.activity !== undefined) {
        const id = emptyToNull(data.activity);
        if (id) {
            const activity = await Activity.exists({ _id: id, organization: organizationId, isDeleted: { $ne: true } });
            if (!activity) throw new ApiError("Activity not found.", 404);
        }
        links.activity = id;
    }

    return links;

};


const findExpense = async (id, organizationId, session = null) => {

    assertId(id);

    const expense =
        await Expense.findOne({ _id: id, organization: organizationId, isDeleted: false })
            .session(session);

    if (!expense) throw notFound();

    return expense;

};


const TEXT_FIELDS = ["description", "payee", "referenceNumber", "paymentMethod"];


// =====================================================
// CREATE
// =====================================================

const createExpense = async (data, organizationId, userId) => {

    const charge =
        await resolveCharge(organizationId, data.budget, data.budgetLine, data.expenseDate);

    const amounts =
        convert(data.amount, data.currency, data.exchangeRate, charge.budget.currency);

    const expenseCode =
        await generateSequence("Expense", "EXP", organizationId);

    const expense =
        await Expense.create({
            organization: organizationId,
            expenseCode,
            budget: charge.budget._id,
            budgetLine: charge.line._id,
            category: charge.line.category,
            program: charge.budget.program,
            project: charge.budget.project,
            expenseDate: charge.date,
            fiscalYear: charge.fiscalYear,
            ...Object.fromEntries(TEXT_FIELDS.filter(f => data[f] !== undefined).map(f => [f, data[f]])),
            ...amounts,
            budgetCurrency: charge.budget.currency,
            ...(await optionalLinks(organizationId, data)),
            status: EXPENSE_STATUS.DRAFT,
            history: [historyEntry("Created", EXPENSE_STATUS.DRAFT, userId)],
            createdBy: userId,
            updatedBy: userId
        });

    return getExpenseById(expense._id, organizationId);

};


// =====================================================
// LIST
// =====================================================

const getExpenses = async (organizationId, query = {}) => {

    const page = Math.max(1, Number(query.page) || 1);
    const limit = Math.min(100, Math.max(1, Number(query.limit) || 10));

    const filter = { organization: organizationId, isDeleted: false };

    if (query.status) filter.status = query.status;
    if (query.category) filter.category = query.category;
    if (query.fiscalYear) filter.fiscalYear = Number(query.fiscalYear);
    if (mongoose.isValidObjectId(query.budget)) filter.budget = query.budget;
    if (mongoose.isValidObjectId(query.budgetLine)) filter.budgetLine = query.budgetLine;
    if (mongoose.isValidObjectId(query.project)) filter.project = query.project;

    if (query.from || query.to) {
        filter.expenseDate = {};
        if (query.from) filter.expenseDate.$gte = new Date(query.from);
        if (query.to) filter.expenseDate.$lte = new Date(query.to);
    }

    if (query.search) {
        const pattern = { $regex: escapeRegex(query.search), $options: "i" };
        filter.$or = [
            { expenseCode: pattern },
            { description: pattern },
            { payee: pattern },
            { referenceNumber: pattern }
        ];
    }

    const [data, total] =
        await Promise.all([
            Expense.find(filter)
                .select("expenseCode expenseDate fiscalYear description payee category amount currency budgetAmount budgetCurrency status budget project approvedOverBudget")
                .populate("budget", "budgetCode name")
                .populate("project", "projectCode name")
                .sort({ expenseDate: -1, createdAt: -1 })
                .skip((page - 1) * limit)
                .limit(limit)
                .lean(),
            Expense.countDocuments(filter)
        ]);

    return {
        data,
        pagination: { total, page, limit, pages: Math.ceil(total / limit) }
    };

};


// =====================================================
// DETAILS (with the line's position)
// =====================================================

const getExpenseById = async (id, organizationId) => {

    assertId(id);

    const expense =
        await Expense.findOne({ _id: id, organization: organizationId, isDeleted: false })
            .populate(DETAIL_POPULATE)
            .lean();

    if (!expense) throw notFound();

    const budget =
        await Budget.findOne({ _id: expense.budget?._id, organization: organizationId }).lean();

    const line = budget?.lines?.find(item => String(item._id) === String(expense.budgetLine));

    const lineBudget =
        roundMoney(line?.amounts?.find(item => item.fiscalYear === expense.fiscalYear)?.amount || 0);

    const totals =
        await lineTotals(organizationId, expense.budget._id, expense.budgetLine, expense.fiscalYear, expense._id);

    const counted = expense.status !== EXPENSE_STATUS.VOIDED;

    return {
        ...expense,
        line: {
            _id: expense.budgetLine,
            category: line?.category || expense.category,
            description: line?.description || "",
            fiscalYear: expense.fiscalYear,
            budget: lineBudget,
            spentByOthers: totals.spent,
            pendingByOthers: totals.pending,
            remainingBefore: roundMoney(lineBudget - totals.spent),
            remainingAfter: roundMoney(lineBudget - totals.spent - (counted ? expense.budgetAmount : 0)),
            overBudget: counted && expense.budgetAmount > roundMoney(lineBudget - totals.spent) + 0.005
        }
    };

};


// =====================================================
// UPDATE / DELETE (Draft / Returned only)
// =====================================================

const assertEditable = (expense, verb) => {
    if (!EDITABLE.includes(expense.status)) {
        throw new ApiError(`A ${expense.status.toLowerCase()} expense cannot be ${verb}.`, 409);
    }
};


const updateExpense = async (id, data, organizationId, userId) => {

    const expense = await findExpense(id, organizationId);

    assertEditable(expense, "edited");

    const charge =
        await resolveCharge(
            organizationId,
            data.budget ?? expense.budget,
            data.budgetLine ?? expense.budgetLine,
            data.expenseDate ?? expense.expenseDate
        );

    const amounts =
        convert(
            data.amount ?? expense.amount,
            data.currency ?? expense.currency,
            data.exchangeRate ?? expense.exchangeRate,
            charge.budget.currency
        );

    Object.assign(expense, {
        budget: charge.budget._id,
        budgetLine: charge.line._id,
        category: charge.line.category,
        program: charge.budget.program,
        project: charge.budget.project,
        expenseDate: charge.date,
        fiscalYear: charge.fiscalYear,
        ...Object.fromEntries(TEXT_FIELDS.filter(f => data[f] !== undefined).map(f => [f, data[f]])),
        ...amounts,
        budgetCurrency: charge.budget.currency,
        ...(await optionalLinks(organizationId, data)),
        updatedBy: userId
    });

    expense.history.push(historyEntry("Updated", expense.status, userId));

    await expense.save();

    return getExpenseById(expense._id, organizationId);

};


const deleteExpense = async (id, organizationId, userId) => {

    const expense = await findExpense(id, organizationId);

    assertEditable(expense, "deleted");

    expense.isDeleted = true;
    expense.deletedAt = new Date();
    expense.deletedBy = userId;

    await expense.save();

};


// =====================================================
// WORKFLOW
// =====================================================

const submitExpense = async (id, organizationId, userId) => {

    const expense = await findExpense(id, organizationId);

    assertEditable(expense, "submitted");

    // Budget must still be approved and the date still inside it
    await resolveCharge(organizationId, expense.budget, expense.budgetLine, expense.expenseDate);

    const updated =
        await Expense.findOneAndUpdate(
            { _id: id, organization: organizationId, isDeleted: false, status: { $in: EDITABLE } },
            {
                $set: { status: EXPENSE_STATUS.SUBMITTED, submittedBy: userId, submittedAt: new Date(), reviewComment: "", updatedBy: userId },
                $push: { history: historyEntry("Submitted", EXPENSE_STATUS.SUBMITTED, userId) }
            },
            { returnDocument: "after" }
        );

    if (!updated) {
        throw new ApiError("This expense was changed by someone else. Reload and try again.", 409);
    }

    return getExpenseById(id, organizationId);

};


const approveExpense = async (id, organizationId, userId, { comment = "", allowOverBudget = false } = {}) => {

    await runInTransaction(async (session) => {

        const expense = await findExpense(id, organizationId, session);

        if (expense.status !== EXPENSE_STATUS.SUBMITTED) {
            throw new ApiError(`This expense is ${expense.status.toLowerCase()} and cannot be approved.`, 409);
        }

        const charge =
            await resolveCharge(organizationId, expense.budget, expense.budgetLine, expense.expenseDate, session);

        // Serialize approvals on this budget (see RULES)
        await Budget.updateOne({ _id: charge.budget._id }, { $inc: { chargeVersion: 1 } }, { session });

        const { spent } =
            await lineTotals(organizationId, charge.budget._id, charge.line._id, charge.fiscalYear, expense._id, session);

        const remaining = roundMoney(charge.lineBudget - spent);
        const overBudget = expense.budgetAmount > remaining + 0.005;

        if (overBudget && !allowOverBudget) {
            throw new ApiError(
                `${charge.line.category} (${fiscalYearLabel(charge.fiscalYear)}) has ${money(Math.max(0, remaining), charge.budget.currency)} left; this expense is ${money(expense.budgetAmount, charge.budget.currency)}. Confirm approving over budget, with a reason.`,
                400,
                [{ field: "allowOverBudget", code: "OVER_BUDGET", remaining, amount: expense.budgetAmount }]
            );
        }

        if (overBudget && String(comment || "").trim().length < 3) {
            throw new ApiError("Give a reason for approving over budget.", 400);
        }

        expense.status = EXPENSE_STATUS.APPROVED;
        expense.approvedBy = userId;
        expense.approvedAt = new Date();
        expense.approvedOverBudget = overBudget;
        expense.updatedBy = userId;
        expense.history.push(
            historyEntry(overBudget ? "Approved over budget" : "Approved", EXPENSE_STATUS.APPROVED, userId, comment || "")
        );

        await expense.save({ session });

    });

    return getExpenseById(id, organizationId);

};


const returnExpense = async (id, organizationId, userId, comment) => {

    const updated =
        await Expense.findOneAndUpdate(
            { _id: id, organization: organizationId, isDeleted: false, status: EXPENSE_STATUS.SUBMITTED },
            {
                $set: { status: EXPENSE_STATUS.RETURNED, reviewComment: comment, updatedBy: userId },
                $push: { history: historyEntry("Returned", EXPENSE_STATUS.RETURNED, userId, comment) }
            },
            { returnDocument: "after" }
        );

    if (!updated) {
        const current = await findExpense(id, organizationId);
        throw new ApiError(`This expense is ${current.status.toLowerCase()} and cannot be returned.`, 409);
    }

    return getExpenseById(id, organizationId);

};


const voidExpense = async (id, organizationId, userId, reason) => {

    await runInTransaction(async (session) => {

        const expense = await findExpense(id, organizationId, session);

        if (expense.status !== EXPENSE_STATUS.APPROVED) {
            throw new ApiError("Only approved expenses can be voided. Drafts can simply be deleted.", 409);
        }

        await Budget.updateOne({ _id: expense.budget }, { $inc: { chargeVersion: 1 } }, { session });

        expense.status = EXPENSE_STATUS.VOIDED;
        expense.voidedBy = userId;
        expense.voidedAt = new Date();
        expense.voidReason = reason;
        expense.updatedBy = userId;
        expense.history.push(historyEntry("Voided", EXPENSE_STATUS.VOIDED, userId, reason));

        await expense.save({ session });

    });

    return getExpenseById(id, organizationId);

};


// =====================================================
// TOTALS FOR BUDGET SUMMARIES
// =====================================================
//
// { [lineId]: { [fiscalYear]: { spent, pending } } }
// for the given budgets (used by budgetService).
//
// =====================================================

const totalsByLine = async (organizationId, budgetIds) => {

    if (!budgetIds.length) return {};

    const rows =
        await Expense.aggregate([
            {
                $match: {
                    organization: new mongoose.Types.ObjectId(String(organizationId)),
                    budget: { $in: budgetIds.map(budgetId => new mongoose.Types.ObjectId(String(budgetId))) },
                    isDeleted: false,
                    status: { $in: [EXPENSE_STATUS.APPROVED, ...PENDING] }
                }
            },
            {
                $group: {
                    _id: { line: "$budgetLine", year: "$fiscalYear", status: "$status" },
                    total: { $sum: "$budgetAmount" }
                }
            }
        ]);

    const totals = {};

    for (const row of rows) {
        const line = String(row._id.line);
        const year = row._id.year;
        totals[line] = totals[line] || {};
        totals[line][year] = totals[line][year] || { spent: 0, pending: 0 };
        if (row._id.status === EXPENSE_STATUS.APPROVED) {
            totals[line][year].spent = roundMoney(totals[line][year].spent + row.total);
        }
        else {
            totals[line][year].pending = roundMoney(totals[line][year].pending + row.total);
        }
    }

    return totals;

};


module.exports = {
    createExpense,
    getExpenses,
    getExpenseById,
    updateExpense,
    deleteExpense,
    submitExpense,
    approveExpense,
    returnExpense,
    voidExpense,
    totalsByLine
};
