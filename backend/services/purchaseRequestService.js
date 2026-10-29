const mongoose = require("mongoose");

const PurchaseRequest = require("../models/PurchaseRequest");

const {
    PURCHASE_REQUEST_STATUS,
    COMMITTING_STATUSES
} = require("../models/PurchaseRequest");

const Budget = require("../models/Budget");

const {
    BUDGET_STATUS,
    BUDGET_LEVEL
} = require("../models/Budget");

const Expense = require("../models/Expense");

const PurchaseOrder = require("../models/PurchaseOrder");

const { PO_COMMITTING_STATUSES } = require("../models/PurchaseOrder");

const { EXPENSE_STATUS } = require("../models/Expense");

const Supplier = require("../models/Supplier");

const { SUPPLIER_STATUS } = require("../models/Supplier");

const Activity = require("../models/Activity");

const ApiError = require("../utils/apiError");

const escapeRegex = require("../utils/escapeRegex");

const generateSequence = require("../utils/generateSequence");

const notifications = require("./notificationService");

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
// - Charged to one line of an APPROVED project budget; the
//   request date's fiscal year must be in the budget.
// - At least one item; the estimate is the sum of
//   quantity x unit price.
// - Approved requests reserve their estimate on the line
//   ("Committed"). A request can only be submitted or
//   approved for what the line has left:
//       Budget - Spent (approved expenses) - Committed
// - Approval runs in a transaction that bumps
//   budget.chargeVersion (as expense approval does), so two
//   approvals on the same budget cannot both take the last
//   of a line.
// - Approved requests are never edited or deleted; one that
//   is no longer needed is cancelled with a reason, which
//   releases its money.
// - Commitments count only while the organization has the
//   procurement module on.
//
// =====================================================

const EDITABLE = [PURCHASE_REQUEST_STATUS.DRAFT, PURCHASE_REQUEST_STATUS.RETURNED];

const USER_FIELDS = "name email";

const DETAIL_POPULATE = [
    { path: "budget", select: "budgetCode name currency startYear endYear status" },
    { path: "program", select: "programCode name" },
    { path: "project", select: "projectCode name" },
    { path: "activity", select: "activityCode name" },
    { path: "suggestedSupplier", select: "supplierCode name status phone" },
    { path: "createdBy", select: USER_FIELDS },
    { path: "submittedBy", select: USER_FIELDS },
    { path: "approvedBy", select: USER_FIELDS },
    { path: "rejectedBy", select: USER_FIELDS },
    { path: "cancelledBy", select: USER_FIELDS },
    { path: "history.by", select: USER_FIELDS },
    { path: "sourcing.quotes.supplier", select: "supplierCode name status" },
    { path: "sourcing.quotes.enteredBy", select: USER_FIELDS },
    { path: "sourcing.panel.user", select: USER_FIELDS },
    { path: "sourcing.startedBy", select: USER_FIELDS },
    { path: "sourcing.submittedBy", select: USER_FIELDS },
    { path: "sourcing.approvedBy", select: USER_FIELDS },
    { path: "purchaseOrder", select: "poCode status total currency budgetAmount paidAmount paidTotal orderDate supplier" }
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

const notFound = () => new ApiError("Purchase request not found.", 404);

const assertId = (id) => {
    if (!mongoose.isValidObjectId(id)) throw notFound();
};

const historyEntry = (action, status, userId, comment = "") => ({
    action, status, comment, by: userId, at: new Date()
});

const emptyToNull = (value) =>
    value === "" || value === undefined ? null : value;

const objectId = (id) => new mongoose.Types.ObjectId(String(id));

// "PR-000012 Office furniture for Adama office"
const requestLabel = (request) =>
    `${request.requestCode || ""} ${request.title || ""}`.trim();

// the person who submitted it (or wrote it) hears the decision
const tellRequester = (request, organizationId, userId, title, message) =>
    notifications.notifyUser({
        organizationId,
        to: request.submittedBy?._id || request.submittedBy || request.createdBy?._id || request.createdBy,
        byUserId: userId,
        title,
        message,
        link: `/purchase-requests/${request._id}`
    });

const procurementOn = async (organizationId) =>
    (await require("./moduleService").enabledFor(organizationId)).has("procurement");


// The budget + line a request is charged to

const resolveCharge = async (organizationId, budgetId, lineId, requestDate, session = null) => {

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
            `Purchase requests can only be charged to an approved budget (${budget.budgetCode} is ${budget.status.toLowerCase()}).`,
            400
        );
    }

    const line = budget.lines.id(lineId);

    if (!line) {
        throw new ApiError("Budget line not found in this budget.", 404);
    }

    const date = new Date(requestDate);

    if (Number.isNaN(date.getTime())) {
        throw new ApiError("Enter a valid request date.", 400);
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


// Items: [{ description, specification, unit, quantity, unitPrice }]
// -> with totals, and the estimate

const itemsOf = (items) => {

    if (!Array.isArray(items) || !items.length) {
        throw new ApiError("Add at least one item.", 400);
    }

    const clean =
        items.map((item, index) => {
            const description = String(item?.description || "").trim();
            const quantity = Number(item?.quantity);
            const unitPrice = Number(item?.unitPrice);
            const row = `Item ${index + 1}`;
            if (description.length < 2) throw new ApiError(`${row}: describe the item.`, 400);
            if (!(quantity > 0)) throw new ApiError(`${row} (${description}): the quantity must be more than zero.`, 400);
            if (!(unitPrice > 0)) throw new ApiError(`${row} (${description}): enter the estimated unit price.`, 400);
            return {
                description,
                specification: String(item.specification || "").trim(),
                unit: String(item.unit || "").trim() || "pcs",
                quantity,
                unitPrice: roundMoney(unitPrice),
                total: roundMoney(quantity * unitPrice)
            };
        });

    return {
        items: clean,
        estimatedTotal: roundMoney(clean.reduce((sum, item) => sum + item.total, 0))
    };

};


const convert = (estimatedTotal, currency, exchangeRate, budgetCurrency) => {

    const code = String(currency || budgetCurrency).toUpperCase();

    if (code === budgetCurrency) {
        return { currency: code, exchangeRate: 1, budgetAmount: estimatedTotal };
    }

    const rate = Number(exchangeRate);

    if (!(rate > 0)) {
        throw new ApiError(
            `Enter the exchange rate from ${code} to ${budgetCurrency} (the budget's currency).`,
            400
        );
    }

    return { currency: code, exchangeRate: rate, budgetAmount: roundMoney(estimatedTotal * rate) };

};


// =====================================================
// COMMITTED (approved requests not yet spent)
// =====================================================

// Committed = approved requests not yet ordered (their
// estimate) + open purchase orders (what is not yet paid).

// Committed on one line for one year, leaving out one request
// and its order (excludeId: the request)
const lineCommitted = async (organizationId, budgetId, lineId, fiscalYear, { excludeId = null, session = null } = {}) => {

    if (!(await procurementOn(organizationId))) return 0;

    const match = {
        organization: objectId(organizationId),
        budget: objectId(budgetId),
        budgetLine: objectId(lineId),
        fiscalYear
    };

    const [requests, orders] =
        await Promise.all([
            PurchaseRequest.aggregate([
                { $match: { ...match, isDeleted: false, status: { $in: COMMITTING_STATUSES }, ...(excludeId ? { _id: { $ne: objectId(excludeId) } } : {}) } },
                { $group: { _id: null, total: { $sum: "$budgetAmount" } } }
            ]).session(session),
            PurchaseOrder.aggregate([
                { $match: { ...match, status: { $in: PO_COMMITTING_STATUSES }, ...(excludeId ? { purchaseRequest: { $ne: objectId(excludeId) } } : {}) } },
                { $group: { _id: null, total: { $sum: { $max: [0, { $subtract: ["$budgetAmount", { $ifNull: ["$paidAmount", 0] }] }] } } } }
            ]).session(session)
        ]);

    return roundMoney((requests[0]?.total || 0) + (orders[0]?.total || 0));

};


// { [lineId]: { [fiscalYear]: committed } } for the given budgets
const committedByLine = async (organizationId, budgetIds) => {

    if (!budgetIds.length || !(await procurementOn(organizationId))) return {};

    const match = {
        organization: objectId(organizationId),
        budget: { $in: budgetIds.map(objectId) }
    };

    const group = { $group: { _id: { line: "$budgetLine", year: "$fiscalYear" }, total: { $sum: "$budgetAmount" } } };

    const [requests, orders] =
        await Promise.all([
            PurchaseRequest.aggregate([{ $match: { ...match, isDeleted: false, status: { $in: COMMITTING_STATUSES } } }, group]),
            PurchaseOrder.aggregate([{ $match: { ...match, status: { $in: PO_COMMITTING_STATUSES } } }, { $group: { _id: { line: "$budgetLine", year: "$fiscalYear" }, total: { $sum: { $max: [0, { $subtract: ["$budgetAmount", { $ifNull: ["$paidAmount", 0] }] }] } } } }])
        ]);

    const totals = {};

    for (const row of [...requests, ...orders]) {
        const line = String(row._id.line);
        totals[line] = totals[line] || {};
        totals[line][row._id.year] = roundMoney((totals[line][row._id.year] || 0) + row.total);
    }

    return totals;

};


// Approved expenses on one line for one year
const lineSpent = async (organizationId, budgetId, lineId, fiscalYear, session = null) => {

    const [row] =
        await Expense.aggregate([
            {
                $match: {
                    organization: objectId(organizationId),
                    budget: objectId(budgetId),
                    budgetLine: objectId(lineId),
                    fiscalYear,
                    isDeleted: false,
                    status: EXPENSE_STATUS.APPROVED
                }
            },
            { $group: { _id: null, total: { $sum: "$budgetAmount" } } }
        ]).session(session);

    return roundMoney(row?.total || 0);

};


// What the line has for this request: { budget, spent, committed, available }
const linePosition = async (organizationId, charge, excludeId = null, session = null) => {

    const [spent, committed] =
        await Promise.all([
            lineSpent(organizationId, charge.budget._id, charge.line._id, charge.fiscalYear, session),
            lineCommitted(organizationId, charge.budget._id, charge.line._id, charge.fiscalYear, { excludeId, session })
        ]);

    return {
        budget: charge.lineBudget,
        spent,
        committed,
        available: roundMoney(charge.lineBudget - spent - committed)
    };

};


const assertFits = (request, charge, position) => {

    if (request.budgetAmount <= position.available + 0.005) return;

    const currency = charge.budget.currency;

    throw new ApiError(
        `${charge.line.category} (${fiscalYearLabel(charge.fiscalYear)}) has ${money(Math.max(0, position.available), currency)} left ` +
        `(budget ${money(position.budget, currency)} − spent ${money(position.spent, currency)} − committed ${money(position.committed, currency)}); ` +
        `this request is ${money(request.budgetAmount, currency)}. Reduce the request, or have the budget revised first.`,
        400,
        [{ field: "budgetAmount", code: "OVER_BUDGET", available: position.available, amount: request.budgetAmount }]
    );

};


// Optional links: the activity (of the budget's project) and the supplier (Active)

const optionalLinks = async (organizationId, data, project, current = {}) => {

    const links = {};

    if (data.activity !== undefined) {
        const id = emptyToNull(data.activity);
        if (id) {
            if (!mongoose.isValidObjectId(id)) throw new ApiError("Activity not found.", 404);
            const activity = await Activity.findOne({ _id: id, organization: organizationId, isDeleted: { $ne: true } }).select("project").lean();
            if (!activity) throw new ApiError("Activity not found.", 404);
            if (String(activity.project) !== String(project)) throw new ApiError("The activity must belong to the budget's project.", 400);
        }
        links.activity = id;
    }

    if (data.suggestedSupplier !== undefined) {
        const id = emptyToNull(data.suggestedSupplier);
        if (id && String(id) !== String(current.suggestedSupplier || "")) {
            if (!mongoose.isValidObjectId(id)) throw new ApiError("Supplier not found.", 404);
            const supplier = await Supplier.findOne({ _id: id, organization: organizationId, isDeleted: false }).select("name status").lean();
            if (!supplier) throw new ApiError("Supplier not found.", 404);
            if (supplier.status !== SUPPLIER_STATUS.ACTIVE) {
                throw new ApiError(`${supplier.name} is ${supplier.status.toLowerCase()} and cannot be suggested.`, 400);
            }
        }
        links.suggestedSupplier = id;
    }

    return links;

};


const findRequest = async (id, organizationId, session = null) => {

    assertId(id);

    const request =
        await PurchaseRequest.findOne({ _id: id, organization: organizationId, isDeleted: false })
            .session(session);

    if (!request) throw notFound();

    return request;

};


const TEXT_FIELDS = ["title", "justification", "deliveryLocation"];

const textOf = (data) =>
    Object.fromEntries(TEXT_FIELDS.filter(field => data[field] !== undefined).map(field => [field, data[field]]));

const neededByOf = (data) =>
    data.neededBy === undefined ? {} : { neededBy: emptyToNull(data.neededBy) };


// =====================================================
// CREATE
// =====================================================

const createPurchaseRequest = async (data, organizationId, userId) => {

    const charge =
        await resolveCharge(organizationId, data.budget, data.budgetLine, data.requestDate);

    const { items, estimatedTotal } = itemsOf(data.items);

    const amounts = convert(estimatedTotal, data.currency, data.exchangeRate, charge.budget.currency);

    const links = await optionalLinks(organizationId, data, charge.budget.project);

    const requestCode =
        await generateSequence("PurchaseRequest", "PR", organizationId);

    const request =
        await PurchaseRequest.create({
            organization: organizationId,
            requestCode,
            budget: charge.budget._id,
            budgetLine: charge.line._id,
            category: charge.line.category,
            program: charge.budget.program,
            project: charge.budget.project,
            requestDate: charge.date,
            fiscalYear: charge.fiscalYear,
            ...neededByOf(data),
            ...textOf(data),
            items,
            estimatedTotal,
            ...amounts,
            budgetCurrency: charge.budget.currency,
            ...links,
            status: PURCHASE_REQUEST_STATUS.DRAFT,
            history: [historyEntry("Created", PURCHASE_REQUEST_STATUS.DRAFT, userId)],
            createdBy: userId,
            updatedBy: userId
        });

    return getPurchaseRequestById(request._id, organizationId);

};


// =====================================================
// LIST
// =====================================================

const getPurchaseRequests = async (organizationId, query = {}) => {

    const page = Math.max(1, Number(query.page) || 1);
    const limit = Math.min(100, Math.max(1, Number(query.limit) || 10));

    const filter = { organization: organizationId, isDeleted: false };

    if (query.status) filter.status = query.status;
    if (query.category) filter.category = query.category;
    if (query.fiscalYear) filter.fiscalYear = Number(query.fiscalYear);
    if (mongoose.isValidObjectId(query.budget)) filter.budget = query.budget;
    if (mongoose.isValidObjectId(query.project)) filter.project = query.project;
    if (mongoose.isValidObjectId(query.supplier)) filter.suggestedSupplier = query.supplier;

    if (query.from || query.to) {
        filter.requestDate = {};
        if (query.from) filter.requestDate.$gte = new Date(query.from);
        if (query.to) filter.requestDate.$lte = new Date(query.to);
    }

    if (query.search) {
        const pattern = { $regex: escapeRegex(query.search), $options: "i" };
        filter.$or = [
            { requestCode: pattern },
            { title: pattern },
            { "items.description": pattern }
        ];
    }

    const [data, total] =
        await Promise.all([
            PurchaseRequest.find(filter)
                .select("requestCode title requestDate neededBy fiscalYear category estimatedTotal currency budgetAmount budgetCurrency status budget project suggestedSupplier createdBy items sourcing.status sourcing.methodName purchaseOrder")
                .populate("budget", "budgetCode name")
                .populate("project", "projectCode name")
                .populate("suggestedSupplier", "supplierCode name")
                .populate("createdBy", USER_FIELDS)
                .sort({ requestDate: -1, createdAt: -1 })
                .skip((page - 1) * limit)
                .limit(limit)
                .lean(),
            PurchaseRequest.countDocuments(filter)
        ]);

    return {
        data: data.map(({ items, ...row }) => ({ ...row, itemCount: (items || []).length })),
        pagination: { total, page, limit, pages: Math.ceil(total / limit) }
    };

};


// =====================================================
// DETAILS (with the line's position)
// =====================================================

const getPurchaseRequestById = async (id, organizationId) => {

    assertId(id);

    const request =
        await PurchaseRequest.findOne({ _id: id, organization: organizationId, isDeleted: false })
            .populate(DETAIL_POPULATE)
            .lean();

    if (!request) throw notFound();

    const budget =
        await Budget.findOne({ _id: request.budget?._id, organization: organizationId }).lean();

    const line = budget?.lines?.find(item => String(item._id) === String(request.budgetLine));

    const lineBudget =
        roundMoney(line?.amounts?.find(item => item.fiscalYear === request.fiscalYear)?.amount || 0);

    const [spent, committedByOthers] =
        await Promise.all([
            lineSpent(organizationId, request.budget._id, request.budgetLine, request.fiscalYear),
            lineCommitted(organizationId, request.budget._id, request.budgetLine, request.fiscalYear, { excludeId: request._id })
        ]);

    const available = roundMoney(lineBudget - spent - committedByOthers);

    // what it takes (or would take) from the line: the order's
    // total once ordered, otherwise the estimate
    const counts = ![PURCHASE_REQUEST_STATUS.REJECTED, PURCHASE_REQUEST_STATUS.CANCELLED].includes(request.status);
    // ordered: what its order has not yet paid (paid is in spent)
    const ordered = [PURCHASE_REQUEST_STATUS.ORDERED, PURCHASE_REQUEST_STATUS.CLOSED].includes(request.status) && request.purchaseOrder;
    const takes =
        ordered
            ? (request.purchaseOrder.status === "Closed" ? 0 : Math.max(0, roundMoney(request.purchaseOrder.budgetAmount - (request.purchaseOrder.paidAmount || 0))))
            : request.budgetAmount;

    // before the quotations start: whether emergency procurement applies
    const settingsService = require("./procurementSettingsService");
    const emergency =
        request.status === PURCHASE_REQUEST_STATUS.APPROVED && !request.sourcing
            ? await settingsService.emergencyFor(await settingsService.getSettings(organizationId), organizationId, request.project?._id || request.project)
            : null;

    return {
        ...request,
        emergencyRule: emergency ? { minQuotes: emergency.minQuotes, afterPurchase: emergency.afterPurchase } : null,
        line: {
            _id: request.budgetLine,
            category: line?.category || request.category,
            description: line?.description || "",
            fiscalYear: request.fiscalYear,
            budget: lineBudget,
            spent,
            committedByOthers,
            available,
            takes: counts ? takes : 0,
            remainingAfter: roundMoney(available - (counts ? takes : 0)),
            overBudget: counts && !ordered && request.budgetAmount > available + 0.005
        }
    };

};


// =====================================================
// UPDATE / DELETE (Draft / Returned only)
// =====================================================

const assertEditable = (request, verb) => {
    if (!EDITABLE.includes(request.status)) {
        throw new ApiError(`A ${request.status.toLowerCase()} purchase request cannot be ${verb}.`, 409);
    }
};


const updatePurchaseRequest = async (id, data, organizationId, userId) => {

    const request = await findRequest(id, organizationId);

    assertEditable(request, "edited");

    const charge =
        await resolveCharge(
            organizationId,
            data.budget ?? request.budget,
            data.budgetLine ?? request.budgetLine,
            data.requestDate ?? request.requestDate
        );

    const { items, estimatedTotal } =
        itemsOf(data.items ?? request.items.map(item => item.toObject()));

    const amounts =
        convert(
            estimatedTotal,
            data.currency ?? request.currency,
            data.exchangeRate ?? request.exchangeRate,
            charge.budget.currency
        );

    // another budget: an activity of the old project no longer fits
    const projectChanged = String(charge.budget.project) !== String(request.project);
    const linkData = projectChanged && data.activity === undefined ? { ...data, activity: null } : data;

    Object.assign(request, {
        budget: charge.budget._id,
        budgetLine: charge.line._id,
        category: charge.line.category,
        program: charge.budget.program,
        project: charge.budget.project,
        requestDate: charge.date,
        fiscalYear: charge.fiscalYear,
        ...neededByOf(data),
        ...textOf(data),
        items,
        estimatedTotal,
        ...amounts,
        budgetCurrency: charge.budget.currency,
        ...(await optionalLinks(organizationId, linkData, charge.budget.project, request)),
        updatedBy: userId
    });

    request.history.push(historyEntry("Updated", request.status, userId));

    await request.save();

    return getPurchaseRequestById(request._id, organizationId);

};


const deletePurchaseRequest = async (id, organizationId, userId) => {

    const request = await findRequest(id, organizationId);

    assertEditable(request, "deleted");

    request.isDeleted = true;
    request.deletedAt = new Date();
    request.deletedBy = userId;

    await request.save();

};


// =====================================================
// WORKFLOW
// =====================================================

const submitPurchaseRequest = async (id, organizationId, userId) => {

    const request = await findRequest(id, organizationId);

    assertEditable(request, "submitted");

    // the budget must still be approved, the date inside it,
    // and the line able to carry it
    const charge = await resolveCharge(organizationId, request.budget, request.budgetLine, request.requestDate);
    assertFits(request, charge, await linePosition(organizationId, charge, request._id));

    const updated =
        await PurchaseRequest.findOneAndUpdate(
            { _id: id, organization: organizationId, isDeleted: false, status: { $in: EDITABLE } },
            {
                $set: { status: PURCHASE_REQUEST_STATUS.SUBMITTED, submittedBy: userId, submittedAt: new Date(), reviewComment: "", updatedBy: userId },
                $push: { history: historyEntry("Submitted", PURCHASE_REQUEST_STATUS.SUBMITTED, userId) }
            },
            { returnDocument: "after" }
        );

    if (!updated) {
        throw new ApiError("This purchase request was changed by someone else. Reload and try again.", 409);
    }

    const submitted = await getPurchaseRequestById(id, organizationId);

    // the people who can approve purchase requests
    await notifications.notifyPermission({
        organizationId,
        permission: "purchase_request.approve",
        byUserId: userId,
        title: "Purchase request waiting for approval",
        message: `${requestLabel(submitted)} (${money(submitted.estimatedTotal, submitted.currency)}) was submitted for approval.`,
        link: `/purchase-requests/${submitted._id}`
    });

    return submitted;

};


const approvePurchaseRequest = async (id, organizationId, userId, { comment = "" } = {}) => {

    await runInTransaction(async (session) => {

        const request = await findRequest(id, organizationId, session);

        if (request.status !== PURCHASE_REQUEST_STATUS.SUBMITTED) {
            throw new ApiError(`This purchase request is ${request.status.toLowerCase()} and cannot be approved.`, 409);
        }

        const charge =
            await resolveCharge(organizationId, request.budget, request.budgetLine, request.requestDate, session);

        // Serialize approvals on this budget (see RULES)
        await Budget.updateOne({ _id: charge.budget._id }, { $inc: { chargeVersion: 1 } }, { session });

        assertFits(request, charge, await linePosition(organizationId, charge, request._id, session));

        request.status = PURCHASE_REQUEST_STATUS.APPROVED;
        request.approvedBy = userId;
        request.approvedAt = new Date();
        request.reviewComment = comment || "";
        request.updatedBy = userId;
        request.history.push(historyEntry("Approved", PURCHASE_REQUEST_STATUS.APPROVED, userId, comment || ""));

        await request.save({ session });

    });

    const approved = await getPurchaseRequestById(id, organizationId);

    await tellRequester(
        approved, organizationId, userId,
        "Purchase request approved",
        `${requestLabel(approved)} was approved. ${money(approved.budgetAmount, approved.budgetCurrency)} is now committed on the budget line.`
    );

    return approved;

};


// Submitted -> Returned (to correct) or Rejected (final)
const decide = async (id, organizationId, userId, comment, status, action) => {

    const updated =
        await PurchaseRequest.findOneAndUpdate(
            { _id: id, organization: organizationId, isDeleted: false, status: PURCHASE_REQUEST_STATUS.SUBMITTED },
            {
                $set: {
                    status,
                    reviewComment: comment,
                    updatedBy: userId,
                    ...(status === PURCHASE_REQUEST_STATUS.REJECTED ? { rejectedBy: userId, rejectedAt: new Date() } : {})
                },
                $push: { history: historyEntry(action, status, userId, comment) }
            },
            { returnDocument: "after" }
        );

    if (!updated) {
        const current = await findRequest(id, organizationId);
        throw new ApiError(`This purchase request is ${current.status.toLowerCase()} and cannot be ${status.toLowerCase()}.`, 409);
    }

    return getPurchaseRequestById(id, organizationId);

};


const returnPurchaseRequest = async (id, organizationId, userId, comment) => {

    const returned = await decide(id, organizationId, userId, comment, PURCHASE_REQUEST_STATUS.RETURNED, "Returned");

    await tellRequester(
        returned, organizationId, userId,
        "Purchase request returned for changes",
        `${requestLabel(returned)} was returned${comment ? `: ${comment}` : "."}`
    );

    return returned;

};


const rejectPurchaseRequest = async (id, organizationId, userId, comment) => {

    const rejected = await decide(id, organizationId, userId, comment, PURCHASE_REQUEST_STATUS.REJECTED, "Rejected");

    await tellRequester(
        rejected, organizationId, userId,
        "Purchase request rejected",
        `${requestLabel(rejected)} was rejected${comment ? `: ${comment}` : "."}`
    );

    return rejected;

};


// Approved -> Cancelled: the money is released
const cancelPurchaseRequest = async (id, organizationId, userId, reason) => {

    await runInTransaction(async (session) => {

        const request = await findRequest(id, organizationId, session);

        if (request.status !== PURCHASE_REQUEST_STATUS.APPROVED) {
            throw new ApiError(
                request.status === PURCHASE_REQUEST_STATUS.CANCELLED
                    ? "This purchase request is already cancelled."
                    : request.status === PURCHASE_REQUEST_STATUS.ORDERED
                        ? "This purchase request has a purchase order. Cancel the purchase order first."
                        : "Only approved purchase requests are cancelled. A draft or returned one can simply be deleted.",
                409
            );
        }

        await Budget.updateOne({ _id: request.budget }, { $inc: { chargeVersion: 1 } }, { session });

        request.status = PURCHASE_REQUEST_STATUS.CANCELLED;
        request.cancelledBy = userId;
        request.cancelledAt = new Date();
        request.cancelReason = reason;
        request.updatedBy = userId;
        request.history.push(historyEntry("Cancelled", PURCHASE_REQUEST_STATUS.CANCELLED, userId, reason));

        await request.save({ session });

    });

    const cancelled = await getPurchaseRequestById(id, organizationId);

    await tellRequester(
        cancelled, organizationId, userId,
        "Purchase request cancelled",
        `${requestLabel(cancelled)} was cancelled and its money released on the budget line${reason ? `: ${reason}` : "."}`
    );

    return cancelled;

};


module.exports = {
    createPurchaseRequest,
    getPurchaseRequests,
    getPurchaseRequestById,
    updatePurchaseRequest,
    deletePurchaseRequest,
    submitPurchaseRequest,
    approvePurchaseRequest,
    returnPurchaseRequest,
    rejectPurchaseRequest,
    cancelPurchaseRequest,
    lineCommitted,
    committedByLine,
    // for the bid analysis and purchase orders
    internals: {
        resolveCharge,
        linePosition,
        findRequest,
        tellRequester,
        requestLabel,
        money,
        roundMoney,
        historyEntry
    }
};
