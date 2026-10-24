const Budget = require("../models/Budget");

const {
    BUDGET_STATUS,
    BUDGET_LEVEL,
    REVISION_STATUS
} = require("../models/Budget");

const ApiError = require("../utils/apiError");

const {
    runInTransaction
} = require("../utils/transaction");

const {
    fiscalYearLabel
} = require("../utils/fiscalYear");

const {
    totalsByLine
} = require("./expenseService");

const budgetService = require("./budgetService");


const budgetEvents = require("./budgetEvents");
const {
    validateYears,
    normalizeContent,
    assertWithinProgram,
    findBudget,
    historyEntry,
    money
} = budgetService.internals;


// =====================================================
// BUDGET REVISIONS
// =====================================================
//
// Only an APPROVED budget is revised. The revision is kept
// on the same record (budget.revision) so expenses stay
// linked to their lines; the approved figures stay in force
// until the revision is approved.
//
//   start -> Draft -> submit -> Submitted -> approve
//                       ^            |-> return (comment) -> Returned
//                       |________________________________|
//   Draft / Returned can be cancelled.
//
// On approve, the current figures are saved in `versions`,
// the revision becomes the budget, version + 1.
//
// Rules (checked on submit and again on approve):
//   - a reason is required
//   - a line with expenses (approved or pending) cannot be
//     removed
//   - no line-year can go below what is already spent
//   - project budgets: still within the program budget
//   - program budgets: still cover what projects use
//
// =====================================================

const EDITABLE = [REVISION_STATUS.DRAFT, REVISION_STATUS.RETURNED];


const assertApproved = (budget) => {
    if (budget.status !== BUDGET_STATUS.APPROVED) {
        throw new ApiError("Only an approved budget can be revised. Edit drafts directly.", 409);
    }
};

const assertHasRevision = (budget, statuses, verb) => {
    if (!budget.revision) {
        throw new ApiError("This budget has no revision in progress.", 409);
    }
    if (statuses && !statuses.includes(budget.revision.status)) {
        throw new ApiError(
            `The revision is ${budget.revision.status.toLowerCase()} and cannot be ${verb}.`,
            409
        );
    }
};


// Proposed figures, normalized like a normal budget edit

const buildContent = (budget, data, base) => {

    const years =
        validateYears(
            data.startYear ?? base.startYear,
            data.endYear ?? base.endYear
        );

    const content =
        normalizeContent(
            budget.level,
            {
                yearlyAmounts: data.yearlyAmounts ?? base.yearlyAmounts,
                lines: data.lines ?? (base.lines || []).map(line => (line.toObject ? line.toObject() : line))
            },
            years
        );

    return {
        startYear: years[0],
        endYear: years[years.length - 1],
        ...content
    };

};


// The checks that protect spending and the program ceiling

const assertRevisionAllowed = async (budget, content) => {

    if (budget.level === BUDGET_LEVEL.PROJECT) {

        const totals = await totalsByLine(budget.organization, [budget._id]);
        const proposed = new Map(content.lines.map(line => [String(line._id || ""), line]));

        for (const line of budget.lines) {

            const actual = totals[String(line._id)] || {};
            const usedYears = Object.entries(actual).filter(([, entry]) => entry.spent > 0 || entry.pending > 0);

            if (!usedYears.length) continue;

            const next = proposed.get(String(line._id));

            if (!next) {
                throw new ApiError(
                    `${line.category}${line.description ? ` (${line.description})` : ""} has expenses and cannot be removed.`,
                    400
                );
            }

            for (const [year, entry] of usedYears) {
                const amount = next.amounts.find(item => item.fiscalYear === Number(year))?.amount || 0;
                if (amount + 0.005 < entry.spent) {
                    throw new ApiError(
                        `${line.category} ${fiscalYearLabel(Number(year))}: ${money(entry.spent, budget.currency)} is already spent; the revised amount (${money(amount, budget.currency)}) cannot be lower.`,
                        400
                    );
                }
            }

        }

    }

    // Same ceiling checks as a normal budget, on the proposed figures
    await assertWithinProgram({
        _id: budget._id,
        organization: budget.organization,
        program: budget.program,
        level: budget.level,
        currency: budget.currency,
        budgetCode: budget.budgetCode,
        // the budget's exchange rate to its program budget
        programExchangeRate: budget.programExchangeRate,
        ...content
    });

};


// =====================================================
// START / EDIT / CANCEL
// =====================================================

const startRevision = async (id, organizationId, userId) => {

    const budget = await findBudget(id, organizationId);

    assertApproved(budget);

    if (budget.revision) {
        throw new ApiError("A revision is already in progress for this budget.", 409);
    }

    budget.revision = {
        status: REVISION_STATUS.DRAFT,
        ...buildContent(budget, {}, budget),
        requestedBy: userId,
        requestedAt: new Date()
    };

    budget.history.push(historyEntry(`Revision v${budget.version + 1} started`, budget.status, userId));

    await budget.save();

    return budgetService.getBudgetById(id, organizationId);

};


const updateRevision = async (id, data, organizationId, userId) => {

    const budget = await findBudget(id, organizationId);

    assertHasRevision(budget, EDITABLE, "edited");

    const content = buildContent(budget, data, budget.revision);

    Object.assign(budget.revision, content);

    if (data.reason !== undefined) {
        budget.revision.reason = data.reason;
    }

    // A revision is saved to be submitted, and submitting
    // needs the reason: ask for it now, not at the last step.
    // (Starting a revision, which only copies the figures,
    // needs none.)
    if (String(budget.revision.reason || "").trim().length < 3) {
        throw new ApiError("Give the reason for this revision (what changed and why) before saving it.", 400);
    }

    budget.updatedBy = userId;

    await budget.save();

    return budgetService.getBudgetById(id, organizationId);

};


const cancelRevision = async (id, organizationId, userId) => {

    const budget = await findBudget(id, organizationId);

    assertHasRevision(budget, EDITABLE, "cancelled");

    budget.history.push(historyEntry(`Revision v${budget.version + 1} cancelled`, budget.status, userId));

    await budgetEvents.audit({ budget, organizationId, userId, action: "BUDGET_REVISION_CANCELLED" });

    budget.revision = null;

    await budget.save();

    return budgetService.getBudgetById(id, organizationId);

};


// =====================================================
// SUBMIT / RETURN / APPROVE
// =====================================================

const submitRevision = async (id, organizationId, userId) => {

    const budget = await findBudget(id, organizationId);

    assertHasRevision(budget, EDITABLE, "submitted");

    if (String(budget.revision.reason || "").trim().length < 3) {
        throw new ApiError("Give the reason for this revision before submitting.", 400);
    }

    if (!(budget.revision.totalAmount > 0)) {
        throw new ApiError("The revised total is zero.", 400);
    }

    await assertRevisionAllowed(budget, budget.revision.toObject());

    budget.revision.status = REVISION_STATUS.SUBMITTED;
    budget.revision.submittedBy = userId;
    budget.revision.submittedAt = new Date();
    budget.revision.reviewComment = "";

    budget.history.push(historyEntry(`Revision v${budget.version + 1} submitted`, budget.status, userId, budget.revision.reason));

    await budget.save();

    await budgetEvents.submitted({ budget, organizationId, userId, revision: true });

    return budgetService.getBudgetById(id, organizationId);

};


const returnRevision = async (id, organizationId, userId, comment) => {

    const budget = await findBudget(id, organizationId);

    assertHasRevision(budget, [REVISION_STATUS.SUBMITTED], "returned");

    budget.revision.status = REVISION_STATUS.RETURNED;
    budget.revision.reviewComment = comment;

    budget.history.push(historyEntry(`Revision v${budget.version + 1} returned`, budget.status, userId, comment));

    await budget.save();

    await budgetEvents.decided({ budget, organizationId, userId, approved: false, revision: true, comment, submittedBy: budget.revision.submittedBy });

    return budgetService.getBudgetById(id, organizationId);

};


const approveRevision = async (id, organizationId, userId, comment = "") => {

    let decidedBudget = null;
    let submittedBy = null;

    await runInTransaction(async (session) => {

        // Serialize with expense approvals on this budget
        // (they bump the same counter), then re-check: spending
        // may have changed since the revision was submitted.
        const bumped =
            await Budget.updateOne(
                { _id: id, organization: organizationId, isDeleted: false },
                { $inc: { chargeVersion: 1 } },
                { session }
            );

        if (!bumped.matchedCount) {
            throw new ApiError("Budget not found.", 404);
        }

        const budget =
            await Budget.findOne({ _id: id, organization: organizationId, isDeleted: false }).session(session);

        assertApproved(budget);
        assertHasRevision(budget, [REVISION_STATUS.SUBMITTED], "approved");

        const proposed = budget.revision.toObject();

        submittedBy = proposed.submittedBy;

        await assertRevisionAllowed(budget, proposed);

        const now = new Date();

        // Keep the figures being replaced
        budget.versions.push({
            version: budget.version,
            startYear: budget.startYear,
            endYear: budget.endYear,
            yearlyAmounts: budget.yearlyAmounts.map(item => item.toObject()),
            lines: budget.lines.map(line => line.toObject()),
            totalAmount: budget.totalAmount,
            approvedBy: budget.approvedBy,
            approvedAt: budget.approvedAt,
            replacedAt: now,
            replacedBecause: proposed.reason
        });

        // The revision becomes the budget (line _ids kept)
        budget.startYear = proposed.startYear;
        budget.endYear = proposed.endYear;
        budget.yearlyAmounts = proposed.yearlyAmounts;
        budget.lines = proposed.lines;
        budget.totalAmount = proposed.totalAmount;

        budget.version += 1;
        budget.approvedBy = userId;
        budget.approvedAt = now;
        budget.updatedBy = userId;
        budget.revision = null;

        budget.history.push(
            historyEntry(`Revision approved (now version ${budget.version})`, budget.status, userId, comment || proposed.reason)
        );

        await budget.save({ session });

        decidedBudget = budget;

    });

    await budgetEvents.decided({ budget: decidedBudget, organizationId, userId, approved: true, revision: true, comment, submittedBy });

    return budgetService.getBudgetById(id, organizationId);

};


module.exports = {
    startRevision,
    updateRevision,
    cancelRevision,
    submitRevision,
    returnRevision,
    approveRevision
};