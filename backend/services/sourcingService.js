const mongoose = require("mongoose");

const PurchaseRequest = require("../models/PurchaseRequest");

const {
    PURCHASE_REQUEST_STATUS,
    SOURCING_STATUS
} = require("../models/PurchaseRequest");

const Budget = require("../models/Budget");

const Supplier = require("../models/Supplier");

const { SUPPLIER_STATUS } = require("../models/Supplier");

const ProcurementCommittee = require("../models/ProcurementCommittee");

const { COMMITTEE_STATUS } = require("../models/ProcurementCommittee");

const ApiError = require("../utils/apiError");

const notifications = require("./notificationService");

const settingsService = require("./procurementSettingsService");

const purchaseRequestService = require("./purchaseRequestService");

const {
    resolveCharge,
    linePosition,
    findRequest,
    requestLabel,
    money,
    roundMoney,
    historyEntry
} = purchaseRequestService.internals;

const {
    runInTransaction
} = require("../utils/transaction");


// =====================================================
// QUOTATIONS AND BID ANALYSIS (on an approved request)
// =====================================================
//
//   start      the method comes from the request's value in
//              ETB and the organization's limits (a stricter
//              one may be chosen)
//   quotes     one per supplier, a price for every item, in
//              the request's currency
//   select     the winning quote; a reason when it is not
//              the lowest; a reason when there are fewer
//              quotes than the method asks for; the committee
//              when the method needs one
//   submit  -> Submitted
//      no committee: someone with quotation.approve approves
//                    or returns it
//      committee:    its members (copied at submission)
//                    approve or object; approved when enough
//                    approve, returned when too many object
//   Approved -> a purchase order can be issued
//
// The winning quote must fit what the budget line has left
// (this request's own estimate is given back for it):
// checked on submit and again on approval.
//
// =====================================================

const EDITABLE = [SOURCING_STATUS.DRAFT, SOURCING_STATUS.RETURNED];

const idOf = (value) => String(value?._id || value || "");

const done = (id, organizationId) => purchaseRequestService.getPurchaseRequestById(id, organizationId);


const assertApprovedRequest = (request) => {
    if (request.status !== PURCHASE_REQUEST_STATUS.APPROVED) {
        throw new ApiError(
            request.status === PURCHASE_REQUEST_STATUS.ORDERED
                ? "This request already has a purchase order."
                : `Quotations are collected for approved requests only (this one is ${request.status.toLowerCase()}).`,
            409
        );
    }
};

const assertEditable = (request) => {
    assertApprovedRequest(request);
    if (!request.sourcing) throw new ApiError("Start the quotations first.", 409);
    if (!EDITABLE.includes(request.sourcing.status)) {
        throw new ApiError(`The bid analysis is ${request.sourcing.status.toLowerCase()} and cannot be changed.`, 409);
    }
};


// the request's value in ETB (what the limits are in)
const etbValueOf = (request, etbRate) => {

    if (request.currency === settingsService.CURRENCY) return request.estimatedTotal;
    if (request.budgetCurrency === settingsService.CURRENCY) return request.budgetAmount;

    const rate = Number(etbRate);

    if (!(rate > 0)) {
        throw new ApiError(`Enter the rate from ${request.currency} to ETB (1 ${request.currency} = ? ETB), to know which method the amount needs.`, 400, [{ field: "etbRate", code: "ETB_RATE_NEEDED" }]);
    }

    return roundMoney(request.estimatedTotal * rate);

};


// ---------------------------------------------------------------- start

const startSourcing = async (id, organizationId, userId, data = {}) => {

    const request = await findRequest(id, organizationId);

    assertApprovedRequest(request);

    if (request.sourcing && request.sourcing.status !== SOURCING_STATUS.DRAFT) {
        throw new ApiError("The quotations are already under way.", 409);
    }
    if (request.sourcing?.quotes?.length) {
        throw new ApiError("Quotations are already entered. Remove them to start again with another method.", 409);
    }

    // "standard": the normal method by amount for an emergency project
    if (data.method && data.method !== "standard" && !settingsService.KEYS.includes(data.method)) throw new ApiError("Unknown procurement method.", 400);

    const settings = await settingsService.getSettings(organizationId);

    // a project of an emergency type: emergency procurement, whatever the amount
    const emergency =
        data.method === "standard" || (data.method && data.method !== "emergency")
            ? null
            : await settingsService.emergencyFor(settings, organizationId, request.project);

    if (data.method === "emergency" && !emergency) {
        throw new ApiError("Emergency procurement is for projects of an emergency type (Procurement Setup).", 400);
    }

    const etbValue = emergency ? (() => { try { return etbValueOf(request, data.etbRate); } catch { return 0; } })() : etbValueOf(request, data.etbRate);
    const method =
        emergency
            ? { key: "emergency", name: emergency.name, minQuotes: emergency.minQuotes, committee: false }
            : settingsService.methodFor(settings, etbValue, data.method === "standard" ? null : data.method || null);

    request.sourcing = {
        method: method.key,
        methodName: method.name,
        minQuotes: method.minQuotes,
        needsCommittee: method.committee,
        afterPurchase: Boolean(emergency?.afterPurchase),
        etbValue,
        quotes: [],
        status: SOURCING_STATUS.DRAFT,
        startedBy: userId,
        startedAt: new Date()
    };
    request.updatedBy = userId;
    request.history.push(historyEntry("Quotations started", request.status, userId, `${method.name}: at least ${method.minQuotes} quotation${method.minQuotes === 1 ? "" : "s"}${method.committee ? ", committee approval" : ""}`));

    await request.save();

    return done(id, organizationId);

};


// ---------------------------------------------------------------- quotes

const quoteFrom = async (request, data, organizationId, currentSupplier = null) => {

    const supplierId = idOf(data.supplier ?? currentSupplier);

    if (!mongoose.isValidObjectId(supplierId)) throw new ApiError("Choose the supplier.", 400);

    if (supplierId !== idOf(currentSupplier)) {
        const supplier = await Supplier.findOne({ _id: supplierId, organization: organizationId, isDeleted: false }).select("name status").lean();
        if (!supplier) throw new ApiError("Supplier not found.", 404);
        if (supplier.status !== SUPPLIER_STATUS.ACTIVE) throw new ApiError(`${supplier.name} is ${supplier.status.toLowerCase()} and cannot quote.`, 400);
        if (request.sourcing.quotes.some(quote => idOf(quote.supplier) === supplierId)) {
            throw new ApiError(`${supplier.name} has already quoted on this request. Edit that quotation instead.`, 409);
        }
    }

    // a price for every item of the request
    const prices = new Map((Array.isArray(data.items) ? data.items : []).map(item => [idOf(item.item), Number(item.unitPrice)]));

    const items =
        request.items.map((item, index) => {
            const unitPrice = prices.get(String(item._id));
            if (!(unitPrice > 0)) throw new ApiError(`Enter the supplier's unit price for item ${index + 1} (${item.description}).`, 400);
            return { item: item._id, unitPrice: roundMoney(unitPrice), total: roundMoney(unitPrice * item.quantity) };
        });

    const day = (value) => (value ? new Date(value) : null);

    const quoteDate = day(data.quoteDate);
    const validUntil = day(data.validUntil);

    if (quoteDate && quoteDate.getTime() > Date.now() + 24 * 60 * 60 * 1000) throw new ApiError("The quotation date is in the future.", 400);
    if (quoteDate && validUntil && validUntil < quoteDate) throw new ApiError("The quotation cannot be valid until a date before it was given.", 400);

    const deliveryDays = data.deliveryDays === "" || data.deliveryDays === null || data.deliveryDays === undefined ? null : Number(data.deliveryDays);
    if (deliveryDays !== null && !(Number.isInteger(deliveryDays) && deliveryDays >= 0)) throw new ApiError("Delivery time is a whole number of days.", 400);

    return {
        supplier: supplierId,
        reference: String(data.reference || "").trim(),
        quoteDate,
        validUntil,
        deliveryDays,
        items,
        total: roundMoney(items.reduce((sum, item) => sum + item.total, 0)),
        notes: String(data.notes || "").trim()
    };

};


const addQuote = async (id, data, organizationId, userId) => {

    const request = await findRequest(id, organizationId);

    assertEditable(request);

    const quote = await quoteFrom(request, data, organizationId);

    request.sourcing.quotes.push({ ...quote, enteredBy: userId, enteredAt: new Date() });
    request.updatedBy = userId;

    await request.save();

    return done(id, organizationId);

};


const findQuote = (request, quoteId) => {
    const quote = request.sourcing?.quotes?.id(quoteId);
    if (!quote) throw new ApiError("Quotation not found.", 404);
    return quote;
};


const updateQuote = async (id, quoteId, data, organizationId, userId) => {

    const request = await findRequest(id, organizationId);

    assertEditable(request);

    const quote = findQuote(request, quoteId);
    const values = await quoteFrom(request, { ...quote.toObject(), ...data }, organizationId, quote.supplier);

    Object.assign(quote, values);
    request.updatedBy = userId;

    await request.save();

    return done(id, organizationId);

};


const removeQuote = async (id, quoteId, organizationId, userId) => {

    const request = await findRequest(id, organizationId);

    assertEditable(request);

    findQuote(request, quoteId).deleteOne();

    if (idOf(request.sourcing.selectedQuote) === String(quoteId)) request.sourcing.selectedQuote = null;

    request.updatedBy = userId;

    await request.save();

    return done(id, organizationId);

};


// ---------------------------------------------------------------- selection

// { selectedQuote, selectionReason, fewerQuotesReason, committee }
const updateBid = async (id, data, organizationId, userId) => {

    const request = await findRequest(id, organizationId);

    assertEditable(request);

    const sourcing = request.sourcing;

    if (data.selectedQuote !== undefined) {
        if (data.selectedQuote) findQuote(request, data.selectedQuote);
        sourcing.selectedQuote = data.selectedQuote || null;
    }

    if (data.selectionReason !== undefined) sourcing.selectionReason = String(data.selectionReason || "").trim();
    if (data.fewerQuotesReason !== undefined) sourcing.fewerQuotesReason = String(data.fewerQuotesReason || "").trim();
    if (data.emergencyReason !== undefined) sourcing.emergencyReason = String(data.emergencyReason || "").trim();

    if (data.committee !== undefined) {
        if (data.committee) {
            if (!sourcing.needsCommittee) throw new ApiError(`${sourcing.methodName} does not need a committee.`, 400);
            await activeCommittee(organizationId, data.committee);
        }
        sourcing.committee = data.committee || null;
    }

    request.updatedBy = userId;

    await request.save();

    return done(id, organizationId);

};


const activeCommittee = async (organizationId, committeeId) => {

    if (!mongoose.isValidObjectId(committeeId)) throw new ApiError("Choose the committee.", 400);

    const committee =
        await ProcurementCommittee.findOne({ _id: committeeId, organization: organizationId, isDeleted: false }).lean();

    if (!committee) throw new ApiError("Committee not found.", 404);
    if (committee.status !== COMMITTEE_STATUS.ACTIVE) throw new ApiError(`${committee.name} is inactive.`, 400);
    if (!committee.members?.length) throw new ApiError(`${committee.name} has no members.`, 400);

    return committee;

};


// What the selected quote takes from the budget line, and whether it fits
const checkSelection = async (organizationId, request, session = null) => {

    const sourcing = request.sourcing;
    const quotes = sourcing.quotes || [];

    if (!quotes.length) throw new ApiError("Enter at least one quotation.", 400);

    if (sourcing.method === "emergency" && String(sourcing.emergencyReason || "").length < 3) {
        throw new ApiError("Emergency procurement: say what the emergency is and why normal procurement cannot wait.", 400);
    }
    if (!sourcing.selectedQuote) throw new ApiError("Choose the winning quotation.", 400);

    const selected = quotes.find(quote => idOf(quote._id) === idOf(sourcing.selectedQuote));
    if (!selected) throw new ApiError("The chosen quotation is no longer there. Choose again.", 400);

    const lowest = Math.min(...quotes.map(quote => quote.total));

    if (selected.total > lowest + 0.005 && sourcing.selectionReason.length < 3) {
        throw new ApiError(`The chosen quotation is not the lowest (${money(lowest, request.currency)}). Give the reason for choosing it.`, 400);
    }

    if (quotes.length < sourcing.minQuotes && sourcing.fewerQuotesReason.length < 3) {
        throw new ApiError(`${sourcing.methodName} needs at least ${sourcing.minQuotes} quotations; there ${quotes.length === 1 ? "is" : "are"} ${quotes.length}. Give the reason for going ahead with fewer.`, 400);
    }

    // the budget line, without this request's own estimate
    const charge = await resolveCharge(organizationId, request.budget, request.budgetLine, request.requestDate, session);
    const position = await linePosition(organizationId, charge, request._id, session);
    const amount = roundMoney(selected.total * (request.exchangeRate || 1));

    if (amount > position.available + 0.005) {
        const currency = charge.budget.currency;
        throw new ApiError(
            `The chosen quotation is ${money(amount, currency)}; ${charge.line.category} (FY ${charge.fiscalYear}) has ${money(Math.max(0, position.available), currency)} for this request. Choose another quotation, or have the budget revised first.`,
            400,
            [{ field: "selectedQuote", code: "OVER_BUDGET", available: position.available, amount }]
        );
    }

    return { selected, amount, charge };

};


// ---------------------------------------------------------------- submit / decide

const submitBid = async (id, organizationId, userId) => {

    const request = await findRequest(id, organizationId);

    assertEditable(request);

    await checkSelection(organizationId, request);

    const sourcing = request.sourcing;

    if (sourcing.needsCommittee) {
        if (!sourcing.committee) throw new ApiError(`${sourcing.methodName} is approved by a committee. Choose the committee.`, 400);
        const committee = await activeCommittee(organizationId, sourcing.committee);
        sourcing.committeeName = committee.name;
        sourcing.approvalsNeeded = committee.approvalsNeeded;
        sourcing.panel = committee.members.map(member => ({ user: member.user, role: member.role, decision: null, comment: "", at: null }));
    }
    else {
        sourcing.committee = null;
        sourcing.committeeName = "";
        sourcing.approvalsNeeded = 0;
        sourcing.panel = [];
    }

    sourcing.status = SOURCING_STATUS.SUBMITTED;
    sourcing.submittedBy = userId;
    sourcing.submittedAt = new Date();
    sourcing.reviewComment = "";
    request.updatedBy = userId;
    request.history.push(historyEntry("Bid analysis submitted", request.status, userId, sourcing.needsCommittee ? `to ${sourcing.committeeName}` : ""));

    await request.save();

    const label = requestLabel(request);
    const link = `/purchase-requests/${request._id}`;

    if (sourcing.needsCommittee) {
        for (const member of sourcing.panel) {
            await notifications.notifyUser({
                organizationId,
                to: member.user,
                byUserId: userId,
                title: "Bid analysis waiting for your decision",
                message: `${label}: ${sourcing.committeeName} is asked to approve the bid analysis (${sourcing.quotes.length} quotation${sourcing.quotes.length === 1 ? "" : "s"}).`,
                link
            });
        }
    }
    else {
        await notifications.notifyPermission({
            organizationId,
            permission: "quotation.approve",
            byUserId: userId,
            title: sourcing.method === "emergency" ? "Emergency purchase waiting for approval" : "Bid analysis waiting for approval",
            message: sourcing.method === "emergency"
                ? `${label}: emergency procurement (${sourcing.emergencyReason})${sourcing.afterPurchase ? ". The order may be issued now; your approval follows." : " was submitted for approval."}`
                : `${label}: the bid analysis (${sourcing.quotes.length} quotation${sourcing.quotes.length === 1 ? "" : "s"}) was submitted for approval.`,
            link
        });
    }

    return done(id, organizationId);

};


// Approved: checked in a transaction with the budget's other approvals
const markApproved = async (organizationId, request, userId, comment, session) => {

    const { charge } = await checkSelection(organizationId, request, session);

    await Budget.updateOne({ _id: charge.budget._id }, { $inc: { chargeVersion: 1 } }, { session });

    request.sourcing.status = SOURCING_STATUS.APPROVED;
    request.sourcing.approvedBy = userId;
    request.sourcing.approvedAt = new Date();
    request.updatedBy = userId;
    request.history.push(historyEntry("Bid analysis approved", request.status, userId, comment || ""));

};


const afterApproval = async (organizationId, id, userId) => {

    const approved = await done(id, organizationId);
    const winner = approved.sourcing.quotes.find(quote => idOf(quote._id) === idOf(approved.sourcing.selectedQuote));
    const label = requestLabel(approved);
    const link = `/purchase-requests/${approved._id}`;

    await notifications.notifyUser({
        organizationId,
        to: approved.sourcing.submittedBy,
        byUserId: userId,
        title: "Bid analysis approved",
        message: `${label}: ${winner?.supplier?.name || "the chosen supplier"} (${money(winner?.total || 0, approved.currency)}) was approved.${approved.sourcing.orderedBeforeApproval ? " (The order was already issued.)" : " The purchase order can be issued."}`,
        link
    });

    if (!approved.sourcing.orderedBeforeApproval) await notifications.notifyPermission({
        organizationId,
        permission: "purchase_order.create",
        byUserId: userId,
        title: "Ready for a purchase order",
        message: `${label}: the bid analysis was approved; issue the purchase order to ${winner?.supplier?.name || "the supplier"}.`,
        link
    });

    return approved;

};


// No committee: someone with quotation.approve
const approveBid = async (id, organizationId, userId, { comment = "" } = {}) => {

    await runInTransaction(async (session) => {

        const request = await findRequest(id, organizationId, session);

        // an emergency order issued before approval is approved afterwards
        if (!request.sourcing?.orderedBeforeApproval) assertApprovedRequest(request);

        if (request.sourcing?.status !== SOURCING_STATUS.SUBMITTED) {
            throw new ApiError("Only a submitted bid analysis can be approved.", 409);
        }

        if (request.sourcing.needsCommittee) {
            throw new ApiError(`This bid analysis is decided by ${request.sourcing.committeeName}; its members approve it.`, 409);
        }

        await markApproved(organizationId, request, userId, comment, session);

        await request.save({ session });

    });

    return afterApproval(organizationId, id, userId);

};


// A committee member's decision: "Approve" or "Object" (with a comment)
const decideBid = async (id, organizationId, userId, { decision, comment = "" } = {}) => {

    if (!["Approve", "Object"].includes(decision)) throw new ApiError("Choose Approve or Object.", 400);
    if (decision === "Object" && String(comment || "").trim().length < 3) throw new ApiError("Say why you object.", 400);

    let outcome = null;

    await runInTransaction(async (session) => {

        const request = await findRequest(id, organizationId, session);

        assertApprovedRequest(request);

        const sourcing = request.sourcing;

        if (sourcing?.status !== SOURCING_STATUS.SUBMITTED || !sourcing.needsCommittee) {
            throw new ApiError("There is no committee decision waiting on this request.", 409);
        }

        const seat = sourcing.panel.find(member => idOf(member.user) === String(userId));

        if (!seat) throw new ApiError(`Only the members of ${sourcing.committeeName} decide on this bid analysis.`, 403);
        if (seat.decision) throw new ApiError(`You have already decided (${seat.decision}).`, 409);

        seat.decision = decision;
        seat.comment = String(comment || "").trim();
        seat.at = new Date();

        request.history.push(historyEntry(decision === "Approve" ? "Committee member approved" : "Committee member objected", request.status, userId, seat.comment));

        const approvals = sourcing.panel.filter(member => member.decision === "Approve").length;
        const objections = sourcing.panel.filter(member => member.decision === "Object").length;

        if (approvals >= sourcing.approvalsNeeded) {
            await markApproved(organizationId, request, userId, `${sourcing.committeeName}: ${approvals} of ${sourcing.panel.length} approved`, session);
            outcome = "approved";
        }
        else if (sourcing.panel.length - objections < sourcing.approvalsNeeded) {
            const objectionsText =
                sourcing.panel.filter(member => member.decision === "Object").map(member => member.comment).join(" | ");
            sourcing.status = SOURCING_STATUS.RETURNED;
            sourcing.reviewComment = `${sourcing.committeeName} objected: ${objectionsText}`;
            request.history.push(historyEntry("Bid analysis returned by the committee", request.status, userId, sourcing.reviewComment));
            outcome = "returned";
        }

        request.updatedBy = userId;

        await request.save({ session });

    });

    if (outcome === "approved") return afterApproval(organizationId, id, userId);

    const current = await done(id, organizationId);

    if (outcome === "returned") {
        await notifications.notifyUser({
            organizationId,
            to: current.sourcing.submittedBy,
            byUserId: userId,
            title: "Bid analysis returned by the committee",
            message: `${requestLabel(current)}: ${current.sourcing.reviewComment}`,
            link: `/purchase-requests/${current._id}`
        });
    }

    return current;

};


// Submitted -> Returned (quotation.approve), committee or not
const returnBid = async (id, organizationId, userId, comment) => {

    const request = await findRequest(id, organizationId);

    if (request.sourcing?.orderedBeforeApproval) {
        throw new ApiError("The order was already issued (emergency procurement). It cannot be returned; approve it with your comment, or cancel the order.", 409);
    }

    assertApprovedRequest(request);

    if (request.sourcing?.status !== SOURCING_STATUS.SUBMITTED) {
        throw new ApiError("Only a submitted bid analysis can be returned.", 409);
    }

    request.sourcing.status = SOURCING_STATUS.RETURNED;
    request.sourcing.reviewComment = comment;
    request.updatedBy = userId;
    request.history.push(historyEntry("Bid analysis returned", request.status, userId, comment));

    await request.save();

    const returned = await done(id, organizationId);

    await notifications.notifyUser({
        organizationId,
        to: returned.sourcing.submittedBy,
        byUserId: userId,
        title: "Bid analysis returned for changes",
        message: `${requestLabel(returned)}: ${comment}`,
        link: `/purchase-requests/${returned._id}`
    });

    return returned;

};


// the bid analyses waiting for this user's committee decision
const waitingForMe = async (organizationId, userId) =>
    PurchaseRequest.find({
        organization: organizationId,
        isDeleted: false,
        "sourcing.status": SOURCING_STATUS.SUBMITTED,
        "sourcing.panel": { $elemMatch: { user: userId, decision: null } }
    })
        .select("requestCode title estimatedTotal currency sourcing.committeeName sourcing.submittedAt")
        .sort({ "sourcing.submittedAt": 1 })
        .lean();


module.exports = {
    startSourcing,
    addQuote,
    updateQuote,
    removeQuote,
    updateBid,
    submitBid,
    approveBid,
    decideBid,
    returnBid,
    waitingForMe
};
