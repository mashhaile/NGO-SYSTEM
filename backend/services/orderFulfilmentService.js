const mongoose = require("mongoose");

const PurchaseOrder = require("../models/PurchaseOrder");

const { PURCHASE_ORDER_STATUS } = require("../models/PurchaseOrder");

const PurchaseRequest = require("../models/PurchaseRequest");

const { PURCHASE_REQUEST_STATUS } = require("../models/PurchaseRequest");

const GoodsReceipt = require("../models/GoodsReceipt");

const { GOODS_RECEIPT_STATUS } = require("../models/GoodsReceipt");

const Expense = require("../models/Expense");

const { EXPENSE_STATUS } = require("../models/Expense");

const ApiError = require("../utils/apiError");

const generateSequence = require("../utils/generateSequence");

const notifications = require("./notificationService");

const {
    runInTransaction
} = require("../utils/transaction");


// =====================================================
// RECEIVING AND PAYING A PURCHASE ORDER
// =====================================================
//
// Goods received notes (GRN)
//   - per order item: accepted and rejected quantities; all
//     notes together never accept more than was ordered
//   - the order becomes Partially Received / Received
//   - a note is cancelled (reason) only while the order has
//     no payments
//
// Payments
//   - an expense linked to the order (source "procurement"),
//     charged to the order's budget line, in the order's
//     currency; it goes through the normal expense approval
//   - only what was received and is not yet paid or waiting
//     for approval can be paid ("payable")
//   - approving it moves its amount from Committed to Spent
//     (order.paidAmount); voiding it moves it back
//   - everything received and paid: the order and its request
//     are Closed
//
// Closing short: a partially received order whose received
// goods are all paid can be closed with a reason; what was
// not delivered is released from Committed.
//
// =====================================================

const OPEN = [PURCHASE_ORDER_STATUS.ISSUED, PURCHASE_ORDER_STATUS.PARTIALLY_RECEIVED, PURCHASE_ORDER_STATUS.RECEIVED];

const PENDING_EXPENSE = [EXPENSE_STATUS.DRAFT, EXPENSE_STATUS.SUBMITTED, EXPENSE_STATUS.RETURNED];

const roundMoney = (value) => Math.round(Number(value || 0) * 100) / 100;

const roundQuantity = (value) => Math.round(Number(value || 0) * 1000) / 1000;

const money = (amount, currency) =>
    `${currency} ${Number(amount).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

const idOf = (value) => String(value?._id || value || "");

const history = (action, status, userId, comment = "") => ({ action, status, comment, by: userId, at: new Date() });

const notFound = () => new ApiError("Purchase order not found.", 404);


const findOrder = async (id, organizationId, session = null) => {
    if (!mongoose.isValidObjectId(id)) throw notFound();
    const order = await PurchaseOrder.findOne({ _id: id, organization: organizationId }).session(session);
    if (!order) throw notFound();
    return order;
};


// ---------------------------------------------------------------- figures

// { [orderItemId]: { accepted, rejected } } over the recorded notes
const receivedByItem = async (orderId, session = null) => {

    const notes =
        await GoodsReceipt.find({ purchaseOrder: orderId, status: GOODS_RECEIPT_STATUS.RECORDED })
            .select("lines")
            .session(session)
            .lean();

    const totals = {};

    for (const note of notes) {
        for (const line of note.lines) {
            const key = idOf(line.item);
            totals[key] = totals[key] || { accepted: 0, rejected: 0 };
            totals[key].accepted = roundQuantity(totals[key].accepted + line.accepted);
            totals[key].rejected = roundQuantity(totals[key].rejected + line.rejected);
        }
    }

    return totals;

};


// payments linked to the order: approved and waiting (order currency)
const paymentTotals = async (orderId, { excludeExpenseId = null, session = null } = {}) => {

    const rows =
        await Expense.aggregate([
            {
                $match: {
                    purchaseOrder: new mongoose.Types.ObjectId(String(orderId)),
                    isDeleted: false,
                    status: { $in: [EXPENSE_STATUS.APPROVED, ...PENDING_EXPENSE] },
                    ...(excludeExpenseId ? { _id: { $ne: new mongoose.Types.ObjectId(String(excludeExpenseId)) } } : {})
                }
            },
            { $group: { _id: "$status", total: { $sum: "$amount" } } }
        ]).session(session);

    const byStatus = Object.fromEntries(rows.map(row => [row._id, row.total]));

    return {
        approved: roundMoney(byStatus[EXPENSE_STATUS.APPROVED] || 0),
        pending: roundMoney(PENDING_EXPENSE.reduce((sum, status) => sum + (byStatus[status] || 0), 0))
    };

};


// what the order can still be paid for (order currency)
const figuresOf = async (order, { excludeExpenseId = null, session = null } = {}) => {

    const received = await receivedByItem(order._id, session);

    const receivedValue =
        roundMoney(order.items.reduce((sum, item) => sum + (received[idOf(item._id)]?.accepted || 0) * item.unitPrice, 0));

    const payments = await paymentTotals(order._id, { excludeExpenseId, session });

    return {
        received,
        receivedValue,
        paid: payments.approved,
        pendingPayments: payments.pending,
        payable: roundMoney(Math.max(0, receivedValue - payments.approved - payments.pending))
    };

};


// Issued / Partially Received / Received, from the notes
const statusFrom = (order, received) => {

    const any = order.items.some(item => (received[idOf(item._id)]?.accepted || 0) > 0);
    const all = order.items.every(item => (received[idOf(item._id)]?.accepted || 0) >= item.quantity - 0.0005);

    return all ? PURCHASE_ORDER_STATUS.RECEIVED : any ? PURCHASE_ORDER_STATUS.PARTIALLY_RECEIVED : PURCHASE_ORDER_STATUS.ISSUED;

};


const setRequestStatus = async (order, status, userId, action, session) => {

    const request = await PurchaseRequest.findById(order.purchaseRequest).session(session);

    if (!request || request.status === status) return;

    request.status = status;
    request.updatedBy = userId;
    request.history.push(history(action, status, userId, order.poCode));

    await request.save({ session });

};


const closeIfDone = async (order, userId, session) => {

    if (order.status !== PURCHASE_ORDER_STATUS.RECEIVED) return false;
    if (order.paidTotal < order.total - 0.005) return false;

    order.status = PURCHASE_ORDER_STATUS.CLOSED;
    order.closedBy = userId;
    order.closedAt = new Date();
    order.closeReason = "";
    order.history.push(history("Closed: received and paid", PURCHASE_ORDER_STATUS.CLOSED, userId));

    await setRequestStatus(order, PURCHASE_REQUEST_STATUS.CLOSED, userId, "Closed: received and paid", session);

    return true;

};


// ---------------------------------------------------------------- goods received

// data: { receivedDate, deliveryNote, notes, lines: [{ item, accepted, rejected, remark }] }
const recordReceipt = async (orderId, data, organizationId, userId) => {

    let noteId = null;

    await runInTransaction(async (session) => {

        const order = await findOrder(orderId, organizationId, session);

        if (![PURCHASE_ORDER_STATUS.ISSUED, PURCHASE_ORDER_STATUS.PARTIALLY_RECEIVED].includes(order.status)) {
            throw new ApiError(`Goods are received on an open order (this one is ${order.status.toLowerCase()}).`, 409);
        }

        const receivedDate = new Date(data.receivedDate || Date.now());
        if (Number.isNaN(receivedDate.getTime())) throw new ApiError("Enter the date the goods arrived.", 400);
        if (receivedDate.toISOString().slice(0, 10) < new Date(order.orderDate).toISOString().slice(0, 10)) {
            throw new ApiError("Goods cannot arrive before the order date.", 400);
        }

        const received = await receivedByItem(order._id, session);
        const given = new Map((Array.isArray(data.lines) ? data.lines : []).map(line => [idOf(line.item), line]));

        const lines = [];

        for (const [index, item] of order.items.entries()) {

            const line = given.get(idOf(item._id));
            if (!line) continue;

            const accepted = Number(line.accepted || 0);
            const rejected = Number(line.rejected || 0);

            if (!(accepted >= 0) || !(rejected >= 0)) throw new ApiError(`Item ${index + 1} (${item.description}): quantities cannot be negative.`, 400);
            if (!accepted && !rejected) continue;

            const left = roundQuantity(item.quantity - (received[idOf(item._id)]?.accepted || 0));

            if (accepted > left + 0.0005) {
                throw new ApiError(`Item ${index + 1} (${item.description}): ${left} ${item.unit} left to receive; ${accepted} cannot be accepted.`, 400);
            }

            if (rejected > 0 && String(line.remark || "").trim().length < 3) {
                throw new ApiError(`Item ${index + 1} (${item.description}): say why ${rejected} ${item.unit} were rejected.`, 400);
            }

            lines.push({
                item: item._id,
                description: item.description,
                unit: item.unit,
                accepted: roundQuantity(accepted),
                rejected: roundQuantity(rejected),
                remark: String(line.remark || "").trim()
            });

        }

        if (!lines.length) throw new ApiError("Enter what arrived: an accepted or rejected quantity for at least one item.", 400);

        const prices = new Map(order.items.map(item => [idOf(item._id), item.unitPrice]));

        const [note] =
            await GoodsReceipt.create([{
                organization: organizationId,
                grnCode: await generateSequence("GoodsReceipt", "GRN", organizationId),
                purchaseOrder: order._id,
                supplier: order.supplier,
                receivedDate,
                deliveryNote: String(data.deliveryNote || "").trim(),
                receivedBy: userId,
                notes: String(data.notes || "").trim(),
                lines,
                value: roundMoney(lines.reduce((sum, line) => sum + line.accepted * prices.get(idOf(line.item)), 0)),
                createdBy: userId
            }], { session });

        for (const line of lines) {
            const key = idOf(line.item);
            received[key] = received[key] || { accepted: 0, rejected: 0 };
            received[key].accepted = roundQuantity(received[key].accepted + line.accepted);
        }

        order.status = statusFrom(order, received);
        order.updatedBy = userId;
        order.history.push(history(`Goods received (${note.grnCode})`, order.status, userId));

        await order.save({ session });

        noteId = note._id;

    });

    const order = await PurchaseOrder.findById(orderId).select("poCode issuedBy").lean();
    const note = await GoodsReceipt.findById(noteId).select("grnCode").lean();

    await notifications.notifyPermission({
        organizationId,
        permission: "expense.create",
        byUserId: userId,
        type: "info",
        title: "Goods received",
        message: `${note.grnCode}: goods were received on ${order.poCode}. They can now be paid.`,
        link: `/purchase-orders/${orderId}`
    });

    return require("./purchaseOrderService").getPurchaseOrderById(orderId, organizationId);

};


const cancelReceipt = async (noteId, organizationId, userId, reason) => {

    if (!mongoose.isValidObjectId(noteId)) throw new ApiError("Goods received note not found.", 404);

    let orderId = null;

    await runInTransaction(async (session) => {

        const note = await GoodsReceipt.findOne({ _id: noteId, organization: organizationId }).session(session);

        if (!note) throw new ApiError("Goods received note not found.", 404);
        if (note.status !== GOODS_RECEIPT_STATUS.RECORDED) throw new ApiError("This goods received note is already cancelled.", 409);

        const order = await findOrder(note.purchaseOrder, organizationId, session);

        if (!OPEN.includes(order.status)) throw new ApiError(`The order is ${order.status.toLowerCase()}; its goods received notes stay as they are.`, 409);

        const payments = await paymentTotals(order._id, { session });

        if (payments.approved > 0 || payments.pending > 0) {
            throw new ApiError("This order has payments. A goods received note cannot be cancelled once the goods are being paid; correct it with the finance officer.", 409);
        }

        note.status = GOODS_RECEIPT_STATUS.CANCELLED;
        note.cancelledBy = userId;
        note.cancelledAt = new Date();
        note.cancelReason = reason;

        await note.save({ session });

        order.status = statusFrom(order, await receivedByItem(order._id, session));
        order.updatedBy = userId;
        order.history.push(history(`Goods received note cancelled (${note.grnCode})`, order.status, userId, reason));

        await order.save({ session });

        orderId = order._id;

    });

    return require("./purchaseOrderService").getPurchaseOrderById(orderId, organizationId);

};


// ---------------------------------------------------------------- payments

// data: { amount, expenseDate, paymentMethod, referenceNumber (invoice no.), exchangeRate, description, donation }
const createPayment = async (orderId, data, organizationId, userId) => {

    const order = await findOrder(orderId, organizationId);

    if (![PURCHASE_ORDER_STATUS.PARTIALLY_RECEIVED, PURCHASE_ORDER_STATUS.RECEIVED].includes(order.status)) {
        throw new ApiError(
            order.status === PURCHASE_ORDER_STATUS.ISSUED
                ? "Nothing has been received on this order yet. Record the goods received first."
                : `This order is ${order.status.toLowerCase()} and takes no more payments.`,
            409
        );
    }

    const figures = await figuresOf(order);
    const amount = roundMoney(data.amount ?? figures.payable);

    if (!(amount > 0)) throw new ApiError("Nothing is left to pay: everything received is paid or waiting for approval.", 400);

    if (amount > figures.payable + 0.005) {
        throw new ApiError(`At most ${money(figures.payable, order.currency)} can be paid: the goods received and not yet paid or waiting for approval.`, 400);
    }

    const request = await PurchaseRequest.findById(order.purchaseRequest).select("activity requestCode").lean();
    const supplier = await mongoose.model("Supplier").findById(order.supplier).select("name").lean();

    const expenseService = require("./expenseService");

    const expense =
        await expenseService.createExpense({
            budget: order.budget,
            budgetLine: order.budgetLine,
            expenseDate: data.expenseDate || new Date(),
            description: String(data.description || "").trim() || `${order.poCode}: payment to ${supplier?.name || "supplier"}`,
            payee: supplier?.name || "",
            referenceNumber: String(data.referenceNumber || "").trim(),
            paymentMethod: data.paymentMethod || "Bank Transfer",
            amount,
            currency: order.currency,
            exchangeRate: data.exchangeRate ?? order.exchangeRate,
            donation: data.donation || undefined,
            activity: request?.activity || undefined
        }, organizationId, userId);

    await Expense.updateOne({ _id: expense._id }, { $set: { source: "procurement", purchaseOrder: order._id } });

    await PurchaseOrder.updateOne(
        { _id: order._id },
        { $push: { history: history("Payment recorded", order.status, userId, `${expense.expenseCode} ${money(amount, order.currency)}`) } }
    );

    return expenseService.getExpenseById(expense._id, organizationId);

};


// Payment rules on an expense linked to an order (expense edits)
const checkPaymentEdit = async (expense, data) => {

    for (const field of ["budget", "budgetLine", "currency"]) {
        if (data[field] !== undefined && String(data[field] || "") !== String(expense[field] || "")) {
            throw new ApiError("A purchase order payment is charged to the order's budget line, in the order's currency. Those cannot be changed.", 400);
        }
    }

    if (data.amount === undefined) return;

    const order = await PurchaseOrder.findById(expense.purchaseOrder);
    if (!order) return;

    const figures = await figuresOf(order, { excludeExpenseId: expense._id });

    if (Number(data.amount) > figures.payable + 0.005) {
        throw new ApiError(`At most ${money(figures.payable, order.currency)} can be paid on ${order.poCode}: the goods received and not yet paid or waiting for approval.`, 400);
    }

};


// For approving an expense linked to an order: what the
// budget line has for it (the order's own unpaid commitment
// is the money set aside for this payment)
const approvalPosition = async (expense, { lineBudget, spent }, session) => {

    const order = await PurchaseOrder.findById(expense.purchaseOrder).session(session);

    if (!order) return null;

    const sameLine = idOf(order.budgetLine) === idOf(expense.budgetLine) && order.fiscalYear === expense.fiscalYear && OPEN.includes(order.status);

    const others =
        await require("./purchaseRequestService").lineCommitted(
            expense.organization, expense.budget, expense.budgetLine, expense.fiscalYear,
            { excludeId: sameLine ? order.purchaseRequest : null, session }
        );

    const ownAfter = sameLine ? Math.max(0, roundMoney(order.budgetAmount - order.paidAmount - expense.budgetAmount)) : 0;

    return { committed: roundMoney(others + ownAfter), remaining: roundMoney(lineBudget - spent - others - ownAfter) };

};


// An expense linked to an order was approved (+1) or voided (-1)
const paymentChanged = async (expense, sign, userId, session) => {

    const order = await PurchaseOrder.findById(expense.purchaseOrder).session(session);

    if (!order) return;

    order.paidTotal = roundMoney(order.paidTotal + sign * expense.amount);
    order.paidAmount = roundMoney(order.paidAmount + sign * expense.budgetAmount);
    order.updatedBy = userId;

    if (sign > 0) {
        order.history.push(history("Payment approved", order.status, userId, `${expense.expenseCode} ${money(expense.amount, expense.currency)}`));
        await closeIfDone(order, userId, session);
    }
    else {
        order.history.push(history("Payment voided", order.status, userId, expense.expenseCode));
        if (order.status === PURCHASE_ORDER_STATUS.CLOSED) {
            // open again: something is to be paid
            order.status = statusFrom(order, await receivedByItem(order._id, session));
            order.closedBy = null;
            order.closedAt = null;
            order.closeReason = "";
            order.history.push(history("Reopened", order.status, userId, "a payment was voided"));
            await setRequestStatus(order, PURCHASE_REQUEST_STATUS.ORDERED, userId, "Reopened: a payment was voided", session);
        }
    }

    await order.save({ session });

};


// ---------------------------------------------------------------- close short

const closeOrder = async (orderId, organizationId, userId, reason) => {

    await runInTransaction(async (session) => {

        const order = await findOrder(orderId, organizationId, session);

        if (order.status === PURCHASE_ORDER_STATUS.ISSUED) {
            throw new ApiError("Nothing has been received on this order. Cancel it instead.", 409);
        }
        if (!OPEN.includes(order.status)) {
            throw new ApiError(`This order is ${order.status.toLowerCase()}.`, 409);
        }

        const figures = await figuresOf(order, { session });

        if (figures.pendingPayments > 0) throw new ApiError("A payment on this order is waiting for approval. Approve or remove it first.", 409);
        if (figures.paid < figures.receivedValue - 0.005) {
            throw new ApiError(`${money(figures.receivedValue - figures.paid, order.currency)} of the goods received is not yet paid. Pay it first; then the rest of the order can be closed.`, 409);
        }

        order.status = PURCHASE_ORDER_STATUS.CLOSED;
        order.closedBy = userId;
        order.closedAt = new Date();
        order.closeReason = reason;
        order.updatedBy = userId;
        order.history.push(history("Closed short", PURCHASE_ORDER_STATUS.CLOSED, userId, reason));

        await order.save({ session });

        await setRequestStatus(order, PURCHASE_REQUEST_STATUS.CLOSED, userId, "Closed: order closed short", session);

    });

    return require("./purchaseOrderService").getPurchaseOrderById(orderId, organizationId);

};


// ---------------------------------------------------------------- read (for the order page)

const fulfilmentOf = async (order) => {

    const [notes, payments, figures] =
        await Promise.all([
            GoodsReceipt.find({ purchaseOrder: order._id })
                .populate("receivedBy", "name email")
                .populate("cancelledBy", "name email")
                .sort({ receivedDate: -1, createdAt: -1 })
                .lean(),
            Expense.find({ purchaseOrder: order._id, isDeleted: false })
                .select("expenseCode expenseDate amount currency budgetAmount status referenceNumber paymentMethod")
                .sort({ expenseDate: -1, createdAt: -1 })
                .lean(),
            figuresOf(order)
        ]);

    return {
        receipts: notes,
        payments,
        received: figures.received,
        receivedValue: figures.receivedValue,
        paid: figures.paid,
        pendingPayments: figures.pendingPayments,
        payable: figures.payable
    };

};


module.exports = {
    recordReceipt,
    cancelReceipt,
    createPayment,
    checkPaymentEdit,
    approvalPosition,
    paymentChanged,
    closeOrder,
    fulfilmentOf,
    receivedByItem
};
