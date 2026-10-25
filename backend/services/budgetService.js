const mongoose = require("mongoose");

const Budget = require("../models/Budget");

const {
    BUDGET_STATUS,
    BUDGET_LEVEL
} = require("../models/Budget");

const Program = require("../models/program");

const Project = require("../models/Project");

const ApiError = require("../utils/apiError");


// notifications and audit for approval steps
const budgetEvents = () => require("./budgetEvents");
const escapeRegex = require("../utils/escapeRegex");

const generateSequence = require("../utils/generateSequence");

const {
    fiscalYearRange,
    fiscalYearLabel
} = require("../utils/fiscalYear");

const {
    totalsByLine
} = require("./expenseService");


// =====================================================
// RULES
// =====================================================
//
// - Program budget: an amount per fiscal year.
// - Project budget: lines x fiscal years; it draws on its
//   program's budget (when the program has one):
//     * same currency as the program budget
//     * its years inside the program budget's years
//     * per year, all project budgets of the program
//       together <= the program budget for that year
//   checked on submit and on approve (drafts may be over
//   while being worked on; the summary shows it).
// - Draft / Returned can be edited or deleted;
//   Submitted / Approved are locked.
//
// =====================================================

const EDITABLE_STATUSES = [
    BUDGET_STATUS.DRAFT,
    BUDGET_STATUS.RETURNED
];

const MAX_YEARS = 10;

const USER_FIELDS = "name email";

const DETAIL_POPULATE = [
    { path: "program", select: "programCode name" },
    { path: "project", select: "projectCode name" },
    { path: "createdBy", select: USER_FIELDS },
    { path: "submittedBy", select: USER_FIELDS },
    { path: "approvedBy", select: USER_FIELDS },
    { path: "history.by", select: USER_FIELDS },
    { path: "revision.requestedBy", select: USER_FIELDS },
    { path: "revision.submittedBy", select: USER_FIELDS },
    { path: "versions.approvedBy", select: USER_FIELDS }
];


// =====================================================
// HELPERS
// =====================================================

const roundMoney = (value) => {
    const number = Number(value);
    return Number.isFinite(number)
        ? Math.round(number * 100) / 100
        : 0;
};


const notFound = () =>
    new ApiError("Budget not found.", 404);


const assertBudgetId = (id) => {
    if (!mongoose.isValidObjectId(id)) {
        throw notFound();
    }
};


const historyEntry = (action, status, userId, comment = "") => ({
    action,
    status,
    comment,
    by: userId,
    at: new Date()
});


const validateYears = (startYear, endYear) => {

    const start = Number(startYear);
    const end = Number(endYear);

    if (!Number.isInteger(start) || !Number.isInteger(end)) {
        throw new ApiError("Start and end fiscal years are required.", 400);
    }

    if (end < start) {
        throw new ApiError("The end year cannot be before the start year.", 400);
    }

    if (end - start + 1 > MAX_YEARS) {
        throw new ApiError(`A budget can cover at most ${MAX_YEARS} years.`, 400);
    }

    return fiscalYearRange(start, end);

};


// One entry per year of the budget period, in order.
// Years outside the period are rejected (not silently
// dropped), so a shortened period is a visible decision.

const normalizeYearAmounts = (amounts = [], years, label) => {

    const byYear = new Map();

    for (const item of amounts || []) {

        const year = Number(item.fiscalYear);
        const amount = roundMoney(item.amount);

        if (!years.includes(year)) {
            if (amount > 0) {
                throw new ApiError(
                    `${label}: ${fiscalYearLabel(year)} is outside the budget period.`,
                    400
                );
            }
            continue;
        }

        if (amount < 0) {
            throw new ApiError(`${label}: amounts cannot be negative.`, 400);
        }

        byYear.set(year, roundMoney((byYear.get(year) || 0) + amount));

    }

    return years.map(year => ({
        fiscalYear: year,
        amount: byYear.get(year) || 0
    }));

};


const sumAmounts = (amounts) =>
    roundMoney(amounts.reduce((total, item) => total + item.amount, 0));


// Computes totals; never trusts totals from the client.

const normalizeContent = (level, data, years) => {

    if (level === BUDGET_LEVEL.PROGRAM) {

        const yearlyAmounts =
            normalizeYearAmounts(data.yearlyAmounts, years, "Program budget");

        return {
            yearlyAmounts,
            lines: [],
            totalAmount: sumAmounts(yearlyAmounts)
        };

    }

    const lines =
        (data.lines || []).map((line, index) => {

            const amounts =
                normalizeYearAmounts(line.amounts, years, `Line ${index + 1}`);

            return {
                ...(line._id ? { _id: line._id } : {}),
                category: line.category,
                description: String(line.description || "").trim(),
                amounts,
                total: sumAmounts(amounts)
            };

        });

    return {
        yearlyAmounts: [],
        lines,
        totalAmount: roundMoney(lines.reduce((total, line) => total + line.total, 0))
    };

};


// Amount per fiscal year of any budget (program or project)

const yearTotals = (budget) => {

    const totals = new Map();

    const add = (item) =>
        totals.set(item.fiscalYear, roundMoney((totals.get(item.fiscalYear) || 0) + item.amount));

    if (budget.level === BUDGET_LEVEL.PROGRAM) {
        (budget.yearlyAmounts || []).forEach(add);
    }
    else {
        (budget.lines || []).forEach(line => (line.amounts || []).forEach(add));
    }

    return fiscalYearRange(budget.startYear, budget.endYear).map(year => ({
        fiscalYear: year,
        amount: totals.get(year) || 0
    }));

};


// Program / project must belong to the organization; a
// project budget takes its program from the project.

const resolveTarget = async (organizationId, level, programId, projectId) => {

    if (level === BUDGET_LEVEL.PROJECT) {

        if (!mongoose.isValidObjectId(projectId)) {
            throw new ApiError("Select the project for this budget.", 400);
        }

        const project =
            await Project.findOne({ _id: projectId, organization: organizationId, isDeleted: { $ne: true } })
                .select("_id program name")
                .lean();

        if (!project) {
            throw new ApiError("Project not found.", 404);
        }

        return { program: project.program, project: project._id };

    }

    if (!mongoose.isValidObjectId(programId)) {
        throw new ApiError("Select the program for this budget.", 400);
    }

    const program =
        await Program.findOne({ _id: programId, organization: organizationId, isDeleted: { $ne: true } })
            .select("_id")
            .lean();

    if (!program) {
        throw new ApiError("Program not found.", 404);
    }

    return { program: program._id, project: null };

};


const findBudget = async (id, organizationId) => {

    assertBudgetId(id);

    const budget =
        await Budget.findOne({ _id: id, organization: organizationId, isDeleted: false });

    if (!budget) {
        throw notFound();
    }

    return budget;

};


const projectBudgetsOf = (organizationId, programId, exceptId = null) =>
    Budget.find({
        organization: organizationId,
        program: programId,
        level: BUDGET_LEVEL.PROJECT,
        isDeleted: false,
        ...(exceptId ? { _id: { $ne: exceptId } } : {})
    })
        .populate("project", "projectCode name")
        .lean();


const programBudgetOf = (organizationId, programId) =>
    Budget.findOne({
        organization: organizationId,
        program: programId,
        level: BUDGET_LEVEL.PROGRAM,
        isDeleted: false
    }).lean();


// Allocated per year by a set of project budgets

// What 1 unit of a project budget's currency is worth in the
// program budget's currency (null: no rate given)
const rateToProgram = (projectBudget, programCurrency) =>
    !programCurrency || projectBudget.currency === programCurrency
        ? 1
        : Number(projectBudget.programExchangeRate?.rate) > 0
            ? Number(projectBudget.programExchangeRate.rate)
            : null;

// a rate as people quote it: "1 USD = 188 ETB" (rate is what
// 1 unit of the budget's currency is worth in the program's)
const quotedRate = (budgetCurrency, programCurrency, rate) => {
    const inverted = budgetCurrency === "ETB" && programCurrency !== "ETB";
    const value = Number((inverted ? 1 / rate : rate).toPrecision(8));
    return inverted
        ? `1 ${programCurrency} = ${value.toLocaleString("en-US")} ${budgetCurrency}`
        : `1 ${budgetCurrency} = ${value.toLocaleString("en-US")} ${programCurrency}`;
};

// asked the way rates are quoted: 1 unit of the foreign
// currency in ETB (the form converts it to rateToProgram)
const missingRate = (projectBudget, programCurrency) => {
    const base = projectBudget.currency === "ETB" && programCurrency !== "ETB" ? programCurrency : projectBudget.currency;
    const quote = base === projectBudget.currency ? programCurrency : projectBudget.currency;
    return new ApiError(
        `Project budget ${projectBudget.budgetCode || ""} is in ${projectBudget.currency} and the program budget in ${programCurrency}: give the exchange rate (1 ${base} = ? ${quote}) and its date.`.replace("  ", " "),
        400
    );
};

// Per fiscal year, what project budgets use of the program
// budget, in the program budget's currency
const allocatedByYear = (projectBudgets, programCurrency = null, { strict = false } = {}) => {

    const allocated = new Map();

    for (const budget of projectBudgets) {
        const rate = rateToProgram(budget, programCurrency);
        if (rate === null) {
            if (strict) throw missingRate(budget, programCurrency);
            continue;
        }
        for (const item of yearTotals(budget)) {
            allocated.set(item.fiscalYear, roundMoney((allocated.get(item.fiscalYear) || 0) + item.amount * rate));
        }
    }

    return allocated;

};


const money = (amount, currency) =>
    `${currency} ${Number(amount).toLocaleString("en-US", { maximumFractionDigits: 2 })}`;


// Throws when the budget breaks the program envelope.

const assertWithinProgram = async (budget) => {

    if (budget.level === BUDGET_LEVEL.PROGRAM) {

        // The envelope must still cover what projects already took
        const projects = await projectBudgetsOf(budget.organization, budget.program);
        const allocated = allocatedByYear(projects, budget.currency, { strict: true });

        for (const item of yearTotals(budget)) {
            const taken = allocated.get(item.fiscalYear) || 0;
            if (taken > item.amount) {
                throw new ApiError(
                    `${fiscalYearLabel(item.fiscalYear)}: project budgets already use ${money(taken, budget.currency)}, more than this program budget (${money(item.amount, budget.currency)}).`,
                    400
                );
            }
        }



        return;

    }

    const programBudget =
        await programBudgetOf(budget.organization, budget.program);

    // No program budget: nothing to draw on, nothing to check
    if (!programBudget) {
        return;
    }

    // in the program budget's currency
    const rate = rateToProgram(budget, programBudget.currency);

    if (rate === null) {
        throw missingRate(budget, programBudget.currency);
    }

    if (budget.currency !== programBudget.currency && !budget.programExchangeRate?.date) {
        throw new ApiError(`Give the date of the exchange rate (1 ${budget.currency} = ${rate} ${programBudget.currency}).`, 400);
    }

    const programYears = new Map(yearTotals(programBudget).map(item => [item.fiscalYear, item.amount]));
    const others = allocatedByYear(await projectBudgetsOf(budget.organization, budget.program, budget._id), programBudget.currency, { strict: true });

    for (const item of yearTotals(budget)) {

        if (!programYears.has(item.fiscalYear)) {
            if (item.amount > 0) {
                throw new ApiError(
                    `${fiscalYearLabel(item.fiscalYear)} is outside the program budget (${fiscalYearLabel(programBudget.startYear)}–${fiscalYearLabel(programBudget.endYear)}).`,
                    400
                );
            }
            continue;
        }

        const available =
            roundMoney(programYears.get(item.fiscalYear) - (others.get(item.fiscalYear) || 0));

        const needed = roundMoney(item.amount * rate);

        if (needed > available) {
            throw new ApiError(
                `${fiscalYearLabel(item.fiscalYear)}: this budget needs ${money(item.amount, budget.currency)}${rate !== 1 ? ` (${money(needed, programBudget.currency)} at ${quotedRate(budget.currency, programBudget.currency, rate)})` : ""}, but only ${money(Math.max(0, available), programBudget.currency)} of the program budget is unallocated.`,
                400
            );
        }

    }

};


// Budget / Committed / Spent / Remaining per year (and per
// line):
//   Spent     = approved expenses
//   Pending   = draft / submitted / returned expenses (shown,
//               not deducted)
//   Committed = purchase orders (procurement, later): 0
//   Remaining = Budget - Committed - Spent

const withActuals = (items, actualsFor) =>
    items.map(item => {
        const { spent = 0, pending = 0 } = actualsFor(item.fiscalYear) || {};
        return {
            ...item,
            committed: 0,
            spent,
            pending,
            remaining: roundMoney(item.amount - spent)
        };
    });


// Sum of { spent, pending } over every line for a year

const yearActuals = (totals, lineIds) => (year) =>
    lineIds.reduce(
        (sum, lineId) => {
            const entry = totals[String(lineId)]?.[year];
            return entry
                ? { spent: roundMoney(sum.spent + entry.spent), pending: roundMoney(sum.pending + entry.pending) }
                : sum;
        },
        { spent: 0, pending: 0 }
    );


const buildSummary = async (budget) => {

    const programId = budget.program._id || budget.program;

    const projects =
        budget.level === BUDGET_LEVEL.PROGRAM
            ? await projectBudgetsOf(budget.organization, programId)
            : [];

    // Expenses are charged to project budget lines; a program
    // budget's spending is the sum over its project budgets.
    const sourceBudgets = budget.level === BUDGET_LEVEL.PROGRAM ? projects : [budget];

    const totals =
        await totalsByLine(budget.organization, sourceBudgets.map(item => item._id));

    const lineIds =
        sourceBudgets.flatMap(item => (item.lines || []).map(line => line._id));

    const years = withActuals(yearTotals(budget), yearActuals(totals, lineIds));

    const sum = (key) => roundMoney(years.reduce((total, item) => total + item[key], 0));

    const summary = {
        years,
        totalAmount: budget.totalAmount,
        totalCommitted: 0,
        totalSpent: sum("spent"),
        totalPending: sum("pending"),
        totalRemaining: roundMoney(budget.totalAmount - sum("spent"))
    };

    if (budget.level === BUDGET_LEVEL.PROGRAM) {

        const allocated = allocatedByYear(projects, budget.currency);

        summary.allocation = {
            years: years.map(item => ({
                fiscalYear: item.fiscalYear,
                amount: item.amount,
                allocated: allocated.get(item.fiscalYear) || 0,
                unallocated: roundMoney(item.amount - (allocated.get(item.fiscalYear) || 0))
            })),
            projects: projects.map(project => ({
                _id: project._id,
                budgetCode: project.budgetCode,
                project: project.project,
                status: project.status,
                currency: project.currency,
                totalAmount: project.totalAmount,
                // converted into the program's currency (null: rate missing)
                exchangeRate: rateToProgram(project, budget.currency),
                exchangeRateDate: project.programExchangeRate?.date || null,
                years: yearTotals(project)
            }))
        };

        summary.allocation.totalAllocated =
            roundMoney(summary.allocation.years.reduce((total, item) => total + item.allocated, 0));

        summary.allocation.totalUnallocated =
            roundMoney(budget.totalAmount - summary.allocation.totalAllocated);

        return summary;

    }

    summary.lines =
        (budget.lines || []).map(line => {

            const amounts =
                withActuals(line.amounts || [], year => totals[String(line._id)]?.[year]);

            const spent = roundMoney(amounts.reduce((total, item) => total + item.spent, 0));
            const pending = roundMoney(amounts.reduce((total, item) => total + item.pending, 0));

            return {
                _id: line._id,
                category: line.category,
                description: line.description,
                total: line.total,
                committed: 0,
                spent,
                pending,
                remaining: roundMoney(line.total - spent),
                amounts
            };

        });

    // Where this project budget sits in its program budget
    const programBudget =
        await programBudgetOf(budget.organization, budget.program._id || budget.program);

    if (programBudget) {

        const others = allocatedByYear(
            await projectBudgetsOf(budget.organization, programBudget.program, budget._id),
            programBudget.currency
        );

        const rate = rateToProgram(budget, programBudget.currency);

        summary.programBudget = {
            _id: programBudget._id,
            budgetCode: programBudget.budgetCode,
            status: programBudget.status,
            currency: programBudget.currency,
            exchangeRate: rate,
            exchangeRateDate: budget.programExchangeRate?.date || null,
            years: yearTotals(programBudget).map(item => ({
                fiscalYear: item.fiscalYear,
                amount: item.amount,
                usedByOtherProjects: others.get(item.fiscalYear) || 0,
                // in this budget's own currency, at its rate
                availableForThisProject:
                    rate ? roundMoney((item.amount - (others.get(item.fiscalYear) || 0)) / rate) : null
            }))
        };

    }

    return summary;

};


// =====================================================
// CREATE
// =====================================================

const assertNoActiveBudget = async (organizationId, level, target, exceptId = null) => {

    const existing =
        await Budget.findOne({
            organization: organizationId,
            level,
            isDeleted: false,
            ...(level === BUDGET_LEVEL.PROJECT ? { project: target.project } : { program: target.program }),
            ...(exceptId ? { _id: { $ne: exceptId } } : {})
        })
            .select("budgetCode")
            .lean();

    if (existing) {
        throw new ApiError(
            `This ${level} already has a budget (${existing.budgetCode}). Open and edit that one instead.`,
            409
        );
    }

};


const createBudget = async (data, organizationId, userId) => {

    const level = data.level;
    const years = validateYears(data.startYear, data.endYear);
    const target = await resolveTarget(organizationId, level, data.program, data.project);
    // a project in phases: each phase has its own budget
    if (level === BUDGET_LEVEL.PROJECT) {
        await require("./projectPhases").assertNotMainProject(target.project, organizationId, "the budget");
    }
    await assertNoActiveBudget(organizationId, level, target);

    const budgetCode =
        await generateSequence("Budget", "BUD", organizationId);

    const budget =
        await Budget.create({
            organization: organizationId,
            budgetCode,
            name: data.name,
            description: data.description || "",
            level,
            ...target,
            currency: data.currency || "ETB",
            programExchangeRate: data.programExchangeRate || undefined,
            startYear: years[0],
            endYear: years[years.length - 1],
            ...normalizeContent(level, data, years),
            status: BUDGET_STATUS.DRAFT,
            history: [historyEntry("Created", BUDGET_STATUS.DRAFT, userId)],
            createdBy: userId,
            updatedBy: userId
        });

    return getBudgetById(budget._id, organizationId);

};


// =====================================================
// WHAT ALREADY HAS A BUDGET
// =====================================================
//
// One budget per program and per project (or phase): the
// new budget form offers only those without one.
//
// =====================================================

const getBudgetedTargets = async (organizationId) => {
    const base = { organization: organizationId, isDeleted: false };
    const [programs, projects] = await Promise.all([
        Budget.distinct("program", { ...base, level: BUDGET_LEVEL.PROGRAM }),
        Budget.distinct("project", { ...base, level: BUDGET_LEVEL.PROJECT })
    ]);
    return {
        programs: programs.filter(Boolean).map(String),
        projects: projects.filter(Boolean).map(String)
    };
};


// =====================================================
// LIST
// =====================================================

const getBudgets = async (organizationId, query = {}) => {

    const page = Math.max(1, Number(query.page) || 1);
    const limit = Math.min(100, Math.max(1, Number(query.limit) || 10));

    const filter = {
        organization: organizationId,
        isDeleted: false
    };

    if (query.level) filter.level = query.level;
    if (query.status) filter.status = query.status;

    // budgets and revisions waiting for an approver
    if (String(query.waiting) === "true" || String(query.waiting) === "1") {
        filter.$and = [...(filter.$and || []), { $or: [{ status: BUDGET_STATUS.SUBMITTED }, { "revision.status": "Submitted" }] }];
    }
    if (mongoose.isValidObjectId(query.program)) filter.program = query.program;
    if (mongoose.isValidObjectId(query.project)) filter.project = query.project;

    if (query.fiscalYear) {
        const year = Number(query.fiscalYear);
        filter.startYear = { $lte: year };
        filter.endYear = { $gte: year };
    }

    if (query.search) {
        const pattern = { $regex: escapeRegex(query.search), $options: "i" };
        filter.$or = [{ budgetCode: pattern }, { name: pattern }];
    }

    const [data, total] =
        await Promise.all([
            Budget.find(filter)
                .select("budgetCode name level program project currency startYear endYear totalAmount status version createdAt revision.status revision.totalAmount revision.submittedAt")
                .populate("program", "programCode name")
                .populate("project", "projectCode name")
                .sort({ createdAt: -1 })
                .skip((page - 1) * limit)
                .limit(limit)
                .lean(),
            Budget.countDocuments(filter)
        ]);

    return {
        data,
        pagination: {
            total,
            page,
            limit,
            pages: Math.ceil(total / limit)
        }
    };

};


// =====================================================
// DETAILS (with summary)
// =====================================================

const getBudgetById = async (id, organizationId) => {

    assertBudgetId(id);

    const budget =
        await Budget.findOne({ _id: id, organization: organizationId, isDeleted: false })
            .populate(DETAIL_POPULATE)
            .lean();

    if (!budget) {
        throw notFound();
    }

    const waiting =
        budget.status === BUDGET_STATUS.SUBMITTED ||
        budget.revision?.status === "Submitted";

    return {
        ...budget,
        summary: await buildSummary(budget),
        // who can approve it, while it waits
        approvers: waiting ? await budgetEvents().getApprovers(organizationId) : []
    };

};


// =====================================================
// UPDATE (Draft / Returned only)
// =====================================================

const updateBudget = async (id, data, organizationId, userId) => {

    const budget = await findBudget(id, organizationId);

    if (!EDITABLE_STATUSES.includes(budget.status)) {
        throw new ApiError(
            `A ${budget.status.toLowerCase()} budget cannot be edited.`,
            409
        );
    }

    const years =
        validateYears(
            data.startYear ?? budget.startYear,
            data.endYear ?? budget.endYear
        );

    if (data.name !== undefined) budget.name = data.name;
    if (data.description !== undefined) budget.description = data.description || "";
    if (data.currency !== undefined) budget.currency = data.currency || "ETB";
    if (data.programExchangeRate !== undefined) budget.programExchangeRate = data.programExchangeRate || undefined;

    budget.startYear = years[0];
    budget.endYear = years[years.length - 1];

    // Re-normalize content against the (possibly new) period
    const content =
        normalizeContent(
            budget.level,
            {
                yearlyAmounts: data.yearlyAmounts ?? budget.yearlyAmounts,
                lines: data.lines ?? budget.lines.map(line => line.toObject())
            },
            years
        );

    budget.yearlyAmounts = content.yearlyAmounts;
    budget.lines = content.lines;
    budget.totalAmount = content.totalAmount;

    budget.updatedBy = userId;
    budget.history.push(historyEntry("Updated", budget.status, userId));

    await budget.save();

    return getBudgetById(budget._id, organizationId);

};


// =====================================================
// DELETE (Draft / Returned only, soft delete)
// =====================================================

const deleteBudget = async (id, organizationId, userId) => {

    const budget = await findBudget(id, organizationId);

    if (!EDITABLE_STATUSES.includes(budget.status)) {
        throw new ApiError(
            `A ${budget.status.toLowerCase()} budget cannot be deleted.`,
            409
        );
    }

    budget.isDeleted = true;
    budget.deletedAt = new Date();
    budget.deletedBy = userId;

    await budget.save();

};


// =====================================================
// WORKFLOW
// =====================================================
//
// One conditional update on the current status, so two
// people acting at once cannot both succeed.
//
// =====================================================

const transition = async ({ id, organizationId, userId, from, to, action, verb, comment = "", set = {} }) => {

    assertBudgetId(id);

    const updated =
        await Budget.findOneAndUpdate(
            { _id: id, organization: organizationId, isDeleted: false, status: { $in: from } },
            {
                $set: { status: to, updatedBy: userId, ...set },
                $push: { history: historyEntry(action, to, userId, comment) }
            },
            { returnDocument: "after" }
        );

    if (!updated) {
        const current = await findBudget(id, organizationId);
        throw new ApiError(
            `This budget is ${current.status.toLowerCase()} and cannot be ${verb}.`,
            409
        );
    }

    return getBudgetById(updated._id, organizationId);

};


const assertReadyForReview = async (budget) => {

    if (budget.level === BUDGET_LEVEL.PROJECT && !budget.lines.length) {
        throw new ApiError("Add at least one budget line before submitting.", 400);
    }

    if (!(budget.totalAmount > 0)) {
        throw new ApiError("The budget total is zero. Enter the amounts before submitting.", 400);
    }

    await assertWithinProgram(budget);

};


const submitBudget = async (id, organizationId, userId) => {

    const budget = await findBudget(id, organizationId);

    await assertReadyForReview(budget);

    const result = await transition({
        id,
        organizationId,
        userId,
        from: EDITABLE_STATUSES,
        to: BUDGET_STATUS.SUBMITTED,
        action: "Submitted",
        verb: "submitted",
        set: { submittedBy: userId, submittedAt: new Date(), reviewComment: "" }
    });

    await budgetEvents().submitted({ budget: result, organizationId, userId });

    return result;

};


const approveBudget = async (id, organizationId, userId, comment = "") => {

    const budget = await findBudget(id, organizationId);

    // Re-check: other budgets may have changed since submit
    await assertReadyForReview(budget);

    // A project budget draws on its program budget, so that
    // ceiling must itself be approved first.
    if (budget.level === BUDGET_LEVEL.PROJECT) {
        const programBudget = await programBudgetOf(organizationId, budget.program);
        if (programBudget && programBudget.status !== BUDGET_STATUS.APPROVED) {
            throw new ApiError(
                `Approve the program budget ${programBudget.budgetCode} first (it is ${programBudget.status.toLowerCase()}).`,
                400
            );
        }
    }

    return transition({
        id,
        organizationId,
        userId,
        comment: comment || "",
        from: [BUDGET_STATUS.SUBMITTED],
        to: BUDGET_STATUS.APPROVED,
        action: "Approved",
        verb: "approved",
        set: { approvedBy: userId, approvedAt: new Date() }
    }).then(async (result) => {
        await budgetEvents().decided({ budget: result, organizationId, userId, approved: true, comment, submittedBy: budget.submittedBy });
        return result;
    });

};


const returnBudget = async (id, organizationId, userId, comment) =>
    transitionAndTell({
        id,
        organizationId,
        userId,
        comment,
        from: [BUDGET_STATUS.SUBMITTED],
        to: BUDGET_STATUS.RETURNED,
        action: "Returned",
        verb: "returned",
        set: { reviewComment: comment }
    });


// Return, then tell the person who submitted it
const transitionAndTell = async (options) => {
    const before = await findBudget(options.id, options.organizationId);
    const result = await transition(options);
    await budgetEvents().decided({ budget: result, organizationId: options.organizationId, userId: options.userId, approved: false, comment: options.comment, submittedBy: before.submittedBy });
    return result;
};


module.exports = {
    createBudget,
    getBudgetedTargets,
    getBudgets,
    getBudgetById,
    updateBudget,
    deleteBudget,
    submitBudget,
    approveBudget,
    returnBudget,

    // Shared with budgetRevisionService
    internals: {
        validateYears,
        normalizeContent,
        assertWithinProgram,
        findBudget,
        historyEntry,
        roundMoney,
        money
    }
};
