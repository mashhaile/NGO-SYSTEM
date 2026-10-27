const mongoose = require("mongoose");

const PurchaseOrder = require("../models/PurchaseOrder");

const { PURCHASE_ORDER_STATUS } = require("../models/PurchaseOrder");

const PurchaseRequest = require("../models/PurchaseRequest");

const {
    PURCHASE_REQUEST_STATUS,
    SOURCING_STATUS
} = require("../models/PurchaseRequest");

const Budget = require("../models/Budget");

const Organization = require("../models/organization");

const ApiError = require("../utils/apiError");

const escapeRegex = require("../utils/escapeRegex");

const generateSequence = require("../utils/generateSequence");

const notifications = require("./notificationService");

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
// PURCHASE ORDERS
// =====================================================
//
// - Issued from a request whose bid analysis is approved,
//   to the winning supplier at the quoted prices. One
//   issued order per request; the request becomes Ordered.
// - The order's total (in the budget's currency) must fit
//   what the line has left, the request's own estimate
//   given back for it; checked in a transaction with the
//   budget's other approvals.
// - While Issued: the delivery date, place, payment terms
//   and notes can be corrected; prices and items cannot.
// - Cancelled (with a reason): the request goes back to
//   Approved with its quotations, to choose again or be
//   cancelled.
//
// =====================================================

const USER_FIELDS = "name email";

const notFound = () => new ApiError("Purchase order not found.", 404);

const idOf = (value) => String(value?._id || value || "");

const day = (value) => {
    if (value === undefined) return undefined;
    if (value === null || value === "") return null;
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) throw new ApiError("Enter a valid date.", 400);
    return date;
};


const findOrder = async (id, organizationId, session = null) => {

    if (!mongoose.isValidObjectId(id)) throw notFound();

    const order = await PurchaseOrder.findOne({ _id: id, organization: organizationId }).session(session);

    if (!order) throw notFound();

    return order;

};


// ---------------------------------------------------------------- issue

// data: { orderDate, deliveryDate, deliveryLocation, paymentTerms, notes }
const createPurchaseOrder = async (requestId, data, organizationId, userId) => {

    let orderId = null;

    await runInTransaction(async (session) => {

        const request = await findRequest(requestId, organizationId, session);

        if (request.status !== PURCHASE_REQUEST_STATUS.APPROVED) {
            throw new ApiError(
                request.status === PURCHASE_REQUEST_STATUS.ORDERED
                    ? "This request already has a purchase order."
                    : `A purchase order is issued for an approved request only (this one is ${request.status.toLowerCase()}).`,
                409
            );
        }

        if (request.sourcing?.status !== SOURCING_STATUS.APPROVED) {
            throw new ApiError("The bid analysis must be approved before the purchase order is issued.", 409);
        }

        const quote = request.sourcing.quotes.find(item => idOf(item._id) === idOf(request.sourcing.selectedQuote));

        if (!quote) throw new ApiError("The winning quotation is missing. Return the bid analysis and choose again.", 409);

        const charge = await resolveCharge(organizationId, request.budget, request.budgetLine, request.requestDate, session);

        await Budget.updateOne({ _id: charge.budget._id }, { $inc: { chargeVersion: 1 } }, { session });

        const position = await linePosition(organizationId, charge, request._id, session);

        const rate = request.exchangeRate || 1;
        const budgetAmount = roundMoney(quote.total * rate);

        if (budgetAmount > position.available + 0.005) {
            throw new ApiError(
                `This order is ${money(budgetAmount, charge.budget.currency)}; ${charge.line.category} has ${money(Math.max(0, position.available), charge.budget.currency)} for it. Have the budget revised first.`,
                400,
                [{ field: "budgetAmount", code: "OVER_BUDGET", available: position.available, amount: budgetAmount }]
            );
        }

        const prices = new Map(quote.items.map(item => [idOf(item.item), item]));

        const items =
            request.items.map(item => {
                const price = prices.get(String(item._id));
                return {
                    requestItem: item._id,
                    description: item.description,
                    specification: item.specification,
                    unit: item.unit,
                    quantity: item.quantity,
                    unitPrice: price?.unitPrice || 0,
                    total: price?.total || 0
                };
            });

        const deliveryDays = Number(quote.deliveryDays);
        const orderDate = day(data.orderDate) || new Date();

        const [order] =
            await PurchaseOrder.create([{
                organization: organizationId,
                poCode: await generateSequence("PurchaseOrder", "PO", organizationId),
                purchaseRequest: request._id,
                supplier: quote.supplier,
                quote: quote._id,
                quoteReference: quote.reference,
                budget: request.budget,
                budgetLine: request.budgetLine,
                category: request.category,
                program: request.program,
                project: request.project,
                fiscalYear: request.fiscalYear,
                orderDate,
                deliveryDate:
                    day(data.deliveryDate) !== undefined
                        ? day(data.deliveryDate)
                        : Number.isInteger(deliveryDays) && deliveryDays >= 0
                            ? new Date(orderDate.getTime() + deliveryDays * 24 * 60 * 60 * 1000)
                            : request.neededBy,
                deliveryLocation: data.deliveryLocation !== undefined ? String(data.deliveryLocation || "").trim() : request.deliveryLocation,
                paymentTerms: String(data.paymentTerms || "").trim(),
                notes: String(data.notes || "").trim(),
                items,
                currency: request.currency,
                exchangeRate: rate,
                total: quote.total,
                budgetCurrency: request.budgetCurrency,
                budgetAmount,
                status: PURCHASE_ORDER_STATUS.ISSUED,
                issuedBy: userId,
                history: [historyEntry("Issued", PURCHASE_ORDER_STATUS.ISSUED, userId)],
                createdBy: userId,
                updatedBy: userId
            }], { session });

        request.status = PURCHASE_REQUEST_STATUS.ORDERED;
        request.purchaseOrder = order._id;
        request.updatedBy = userId;
        request.history.push(historyEntry("Purchase order issued", PURCHASE_REQUEST_STATUS.ORDERED, userId, order.poCode));

        await request.save({ session });

        orderId = order._id;

    });

    const order = await getPurchaseOrderById(orderId, organizationId);

    await notifications.notifyUser({
        organizationId,
        to: order.purchaseRequest?.createdBy,
        byUserId: userId,
        type: "info",
        title: "Purchase order issued",
        message: `${order.poCode} to ${order.supplier?.name} (${money(order.total, order.currency)}) for ${requestLabel(order.purchaseRequest || {})}.`,
        link: `/purchase-orders/${order._id}`
    });

    return order;

};


// ---------------------------------------------------------------- edit / cancel

const updatePurchaseOrder = async (id, data, organizationId, userId) => {

    const order = await findOrder(id, organizationId);

    if (![PURCHASE_ORDER_STATUS.ISSUED, PURCHASE_ORDER_STATUS.PARTIALLY_RECEIVED].includes(order.status)) {
        throw new ApiError(`A ${order.status.toLowerCase()} purchase order cannot be changed.`, 409);
    }

    if (data.deliveryDate !== undefined) order.deliveryDate = day(data.deliveryDate);
    for (const field of ["deliveryLocation", "paymentTerms", "notes"]) {
        if (data[field] !== undefined) order[field] = String(data[field] || "").trim();
    }

    order.updatedBy = userId;
    order.history.push(historyEntry("Updated", order.status, userId));

    await order.save();

    return getPurchaseOrderById(order._id, organizationId);

};


const cancelPurchaseOrder = async (id, organizationId, userId, reason) => {

    await runInTransaction(async (session) => {

        const order = await findOrder(id, organizationId, session);

        if (order.status !== PURCHASE_ORDER_STATUS.ISSUED) {
            throw new ApiError(
                [PURCHASE_ORDER_STATUS.PARTIALLY_RECEIVED, PURCHASE_ORDER_STATUS.RECEIVED].includes(order.status)
                    ? "Goods have been received on this order, so it cannot be cancelled. Pay what was received and close it short instead."
                    : `This purchase order is ${order.status.toLowerCase()} and cannot be cancelled.`,
                409
            );
        }

        await Budget.updateOne({ _id: order.budget }, { $inc: { chargeVersion: 1 } }, { session });

        order.status = PURCHASE_ORDER_STATUS.CANCELLED;
        order.cancelledBy = userId;
        order.cancelledAt = new Date();
        order.cancelReason = reason;
        order.updatedBy = userId;
        order.history.push(historyEntry("Cancelled", PURCHASE_ORDER_STATUS.CANCELLED, userId, reason));

        await order.save({ session });

        // the request goes back to choosing a supplier
        const request = await PurchaseRequest.findOne({ _id: order.purchaseRequest, organization: organizationId }).session(session);

        if (request && request.status === PURCHASE_REQUEST_STATUS.ORDERED) {
            request.status = PURCHASE_REQUEST_STATUS.APPROVED;
            request.purchaseOrder = null;
            if (request.sourcing) {
                request.sourcing.status = SOURCING_STATUS.DRAFT;
                request.sourcing.selectedQuote = null;
                request.sourcing.selectionReason = "";
                request.sourcing.panel = [];
                request.sourcing.reviewComment = `${order.poCode} was cancelled: ${reason}. Choose another quotation, or cancel the request.`;
            }
            request.updatedBy = userId;
            request.history.push(historyEntry("Purchase order cancelled", PURCHASE_REQUEST_STATUS.APPROVED, userId, `${order.poCode}: ${reason}`));
            await request.save({ session });
        }

    });

    return getPurchaseOrderById(id, organizationId);

};


// ---------------------------------------------------------------- read

const getPurchaseOrders = async (organizationId, query = {}) => {

    const page = Math.max(1, Number(query.page) || 1);
    const limit = Math.min(100, Math.max(1, Number(query.limit) || 10));

    const filter = { organization: organizationId };

    if (query.status) filter.status = query.status;
    if (query.fiscalYear) filter.fiscalYear = Number(query.fiscalYear);
    if (mongoose.isValidObjectId(query.supplier)) filter.supplier = query.supplier;
    if (mongoose.isValidObjectId(query.budget)) filter.budget = query.budget;
    if (mongoose.isValidObjectId(query.project)) filter.project = query.project;

    if (query.search) {
        const pattern = { $regex: escapeRegex(query.search), $options: "i" };
        const [suppliers, requests] = await Promise.all([
            mongoose.model("Supplier").find({ organization: organizationId, name: pattern }).select("_id").lean(),
            PurchaseRequest.find({ organization: organizationId, $or: [{ title: pattern }, { requestCode: pattern }] }).select("_id").lean()
        ]);
        filter.$or = [
            { poCode: pattern },
            { quoteReference: pattern },
            { "items.description": pattern },
            { supplier: { $in: suppliers.map(item => item._id) } },
            { purchaseRequest: { $in: requests.map(item => item._id) } }
        ];
    }

    const [data, total] =
        await Promise.all([
            PurchaseOrder.find(filter)
                .select("poCode orderDate deliveryDate category total currency budgetAmount budgetCurrency paidTotal status supplier purchaseRequest project budget")
                .populate("supplier", "supplierCode name")
                .populate("purchaseRequest", "requestCode title")
                .populate("project", "projectCode name")
                .populate("budget", "budgetCode")
                .sort({ orderDate: -1, createdAt: -1 })
                .skip((page - 1) * limit)
                .limit(limit)
                .lean(),
            PurchaseOrder.countDocuments(filter)
        ]);

    return {
        data,
        pagination: { total, page, limit, pages: Math.ceil(total / limit) }
    };

};


const getPurchaseOrderById = async (id, organizationId) => {

    if (!mongoose.isValidObjectId(id)) throw notFound();

    const order =
        await PurchaseOrder.findOne({ _id: id, organization: organizationId })
            .populate("supplier", "supplierCode name tin vatRegistered contactPerson phone email address bankName bankAccountName bankAccountNumber")
            .populate("purchaseRequest", "requestCode title createdBy sourcing.methodName sourcing.committeeName sourcing.quotes")
            .populate("budget", "budgetCode name")
            .populate("program", "programCode name")
            .populate("project", "projectCode name")
            .populate("issuedBy", USER_FIELDS)
            .populate("cancelledBy", USER_FIELDS)
            .populate("closedBy", USER_FIELDS)
            .populate("history.by", USER_FIELDS)
            .lean();

    if (!order) throw notFound();

    // goods received notes, payments and what is left to pay
    order.fulfilment = await require("./orderFulfilmentService").fulfilmentOf(order);

    // how many quotations it won against
    const quoteCount = order.purchaseRequest?.sourcing?.quotes?.length || 0;

    if (order.purchaseRequest?.sourcing) {
        order.purchaseRequest.sourcing = {
            methodName: order.purchaseRequest.sourcing.methodName,
            committeeName: order.purchaseRequest.sourcing.committeeName,
            quoteCount
        };
    }

    return order;

};


// ---------------------------------------------------------------- PDF

const buildPurchaseOrderPdf = async (id, organizationId) => {

    const {
        createPdfDocument,
        drawTitle,
        drawSectionTitle,
        drawKeyValueGrid,
        drawTable,
        ensureSpace,
        addPageFooters,
        pdfDate
    } = require("./reports/pdf");

    const order = await getPurchaseOrderById(id, organizationId);

    const organization =
        await Organization.findById(organizationId).select("name email phone address").lean();

    const doc = createPdfDocument({ layout: "portrait" });

    const chunks = [];
    doc.on("data", chunk => chunks.push(chunk));
    const finished = new Promise((resolve, reject) => {
        doc.on("end", () => resolve(Buffer.concat(chunks)));
        doc.on("error", reject);
    });

    const supplier = order.supplier || {};
    const width = doc.page.width - doc.page.margins.left - doc.page.margins.right;

    drawTitle(doc, organization?.name || "Purchase Order", `PURCHASE ORDER · ${order.poCode}`);

    if (order.status === PURCHASE_ORDER_STATUS.CANCELLED) {
        doc.font("Helvetica-Bold").fontSize(12).fillColor("#b91c1c")
            .text(`CANCELLED ${pdfDate(order.cancelledAt)}: ${order.cancelReason}`, { align: "center" })
            .fillColor("#000000");
    }

    doc.moveDown(0.8);

    drawSectionTitle(doc, "ORDER");

    drawKeyValueGrid(
        doc,
        [
            { label: "PO number", value: order.poCode },
            { label: "Order date", value: pdfDate(order.orderDate) },
            { label: "Deliver by", value: order.deliveryDate ? pdfDate(order.deliveryDate) : "-" },
            { label: "Deliver to", value: order.deliveryLocation || "-" },
            { label: "Request", value: [order.purchaseRequest?.requestCode, order.purchaseRequest?.title].filter(Boolean).join(" - ") || "-" },
            { label: "Quotation ref.", value: order.quoteReference || "-" },
            { label: "Project", value: order.project?.name || "-" },
            { label: "Budget line", value: `${order.budget?.budgetCode || ""} · ${order.category}` },
            { label: "Payment terms", value: order.paymentTerms || "-" },
            { label: "Method", value: order.purchaseRequest?.sourcing?.methodName || "-" }
        ],
        { columns: 2, labelWidth: 90 }
    );

    doc.moveDown(0.8);

    drawSectionTitle(doc, "SUPPLIER");

    drawKeyValueGrid(
        doc,
        [
            { label: "Supplier", value: `${supplier.name || "-"} (${supplier.supplierCode || ""})` },
            { label: "TIN", value: `${supplier.tin || "-"}${supplier.vatRegistered ? " (VAT registered)" : ""}` },
            { label: "Contact", value: [supplier.contactPerson, supplier.phone, supplier.email].filter(Boolean).join(", ") || "-" },
            { label: "Address", value: supplier.address || "-" },
            { label: "Bank", value: [supplier.bankName, supplier.bankAccountName, supplier.bankAccountNumber].filter(Boolean).join(" · ") || "-" }
        ],
        { columns: 1, labelWidth: 90 }
    );

    doc.moveDown(0.8);

    drawSectionTitle(doc, "ITEMS");

    drawTable(
        doc,
        [
            { key: "no", label: "#", align: "right" },
            { key: "item", label: "Item" },
            { key: "unit", label: "Unit" },
            { key: "quantity", label: "Quantity", align: "right" },
            { key: "unitPrice", label: "Unit price", align: "right" },
            { key: "total", label: "Total", align: "right" }
        ],
        [
            ...order.items.map((item, index) => ({
                no: String(index + 1),
                item: item.specification ? `${item.description} (${item.specification})` : item.description,
                unit: item.unit,
                quantity: Number(item.quantity).toLocaleString("en-US"),
                unitPrice: money(item.unitPrice, order.currency),
                total: money(item.total, order.currency)
            })),
            { no: "", item: "TOTAL", unit: "", quantity: "", unitPrice: "", total: money(order.total, order.currency) }
        ]
    );

    if (order.notes) {
        doc.moveDown(0.6);
        doc.font("Helvetica").fontSize(9.5).text(`Notes: ${order.notes}`, doc.page.margins.left, doc.y, { width });
    }

    // signatures
    ensureSpace(doc, 110);
    doc.moveDown(2.5);

    const top = doc.y;
    const column = width / 3;
    ["Prepared by", "Approved by", "Supplier acceptance"].forEach((label, index) => {
        const x = doc.page.margins.left + index * column;
        doc.moveTo(x + 5, top + 40).lineTo(x + column - 15, top + 40).stroke("#999999");
        doc.font("Helvetica").fontSize(9).fillColor("#333333")
            .text(label, x + 5, top + 46, { width: column - 20 })
            .text("Name, signature, date", x + 5, top + 58, { width: column - 20 });
    });
    doc.fillColor("#000000");

    addPageFooters(doc, { leftText: `${order.poCode} · Purchase order` });

    doc.end();

    return {
        buffer: await finished,
        fileName: `${order.poCode}.pdf`
    };

};


module.exports = {
    createPurchaseOrder,
    updatePurchaseOrder,
    cancelPurchaseOrder,
    getPurchaseOrders,
    getPurchaseOrderById,
    buildPurchaseOrderPdf
};
