// =====================================================
// PROCUREMENT REPORT
// =====================================================
//
// What was asked for, ordered, received and paid in the
// period, and from whom:
//
//   Requests   purchase requests dated in the period
//   Orders     purchase orders dated in the period (not
//              cancelled), by method and by supplier
//   Received   goods received notes dated in the period
//   Paid       approved payments of orders dated in the period
//   Open       orders not yet closed (any date): what is
//              still to deliver and to pay, late deliveries
//   Exceptions orders whose bid analysis did not choose the
//              lowest quotation, or had fewer quotations than
//              the method asks for (with the reasons given)
//
// Amounts are in each order's currency and never added
// across currencies. Needs purchase_request.read; the
// procurement module must be on.
//
// Filters: program, project
//
// =====================================================

const PurchaseRequest = require("../../../models/PurchaseRequest");
const PurchaseOrder = require("../../../models/PurchaseOrder");
const GoodsReceipt = require("../../../models/GoodsReceipt");
const Expense = require("../../../models/Expense");

const {
    scope, formatTotals, objectId, toId, round2, toNumber, percent,
    summaryItem, column, section, buildReport, projectIn
} = require("../core");

const { inPeriod, monthKey, monthName } = require("../period");


const OPEN = ["Issued", "Partially Received", "Received"];

const addTo = (totals, currency, amount) => {
    const key = currency || "ETB";
    totals[key] = round2((totals[key] || 0) + toNumber(amount));
    return totals;
};

const day = (value) => (value ? new Date(value).toISOString().slice(0, 10) : "");

const daysBetween = (from, to) => Math.round((new Date(to) - new Date(from)) / (24 * 3600 * 1000));


const generate = async (query, context, period) => {

    const { organizationId } = context;

    const work = {};
    if (objectId(query.program)) work.program = objectId(query.program);
    if (objectId(query.project)) work.project = projectIn(query);

    const dated = (field) => {
        const condition = inPeriod(period);
        return condition ? { [field]: condition } : {};
    };

    const [requests, orders, openOrders] =
        await Promise.all([
            PurchaseRequest.find(scope(organizationId, { ...work, ...dated("requestDate") }))
                .select("requestCode title status estimatedTotal currency requestDate approvedAt purchaseOrder sourcing.method")
                .lean(),
            PurchaseOrder.find(scope(organizationId, { ...work, ...dated("orderDate"), status: { $ne: "Cancelled" } }))
                .populate("supplier", "supplierCode name")
                .populate("project", "projectCode name")
                .populate({ path: "purchaseRequest", select: "requestCode title requestDate approvedAt sourcing.method sourcing.methodName sourcing.minQuotes sourcing.quotes._id sourcing.quotes.total sourcing.selectedQuote sourcing.selectionReason sourcing.fewerQuotesReason sourcing.committeeName" })
                .sort({ orderDate: 1 })
                .lean(),
            PurchaseOrder.find(scope(organizationId, { ...work, status: { $in: OPEN } }))
                .populate("supplier", "supplierCode name")
                .sort({ deliveryDate: 1 })
                .lean()
        ]);

    const orderIds = [...new Set([...orders, ...openOrders].map(order => toId(order._id)))].map(objectId);

    const [notes, payments, allPayments, allNotes] =
        await Promise.all([
            GoodsReceipt.find({ organization: objectId(organizationId), status: "Recorded", ...dated("receivedDate"), ...(Object.keys(work).length ? { purchaseOrder: { $in: orderIds } } : {}) })
                .populate({ path: "purchaseOrder", select: "currency supplier", populate: { path: "supplier", select: "name" } })
                .lean(),
            Expense.find(scope(organizationId, { ...work, purchaseOrder: { $ne: null }, status: "Approved", ...dated("expenseDate") }))
                .populate({ path: "purchaseOrder", select: "supplier", populate: { path: "supplier", select: "name" } })
                .select("amount currency expenseDate purchaseOrder")
                .lean(),
            // for the open orders and the supplier table: everything paid / received on them
            Expense.find(scope(organizationId, { purchaseOrder: { $in: orderIds }, status: "Approved" })).select("amount purchaseOrder").lean(),
            GoodsReceipt.find({ purchaseOrder: { $in: orderIds }, status: "Recorded" }).select("value purchaseOrder").lean()
        ]);

    const sumBy = (rows, key) => {
        const map = new Map();
        for (const row of rows) map.set(toId(row.purchaseOrder?._id || row.purchaseOrder), round2((map.get(toId(row.purchaseOrder?._id || row.purchaseOrder)) || 0) + toNumber(row[key])));
        return map;
    };
    const paidOn = sumBy(allPayments, "amount");
    const receivedOn = sumBy(allNotes, "value");


    // ---------- requests by status ----------
    const requestRows = (() => {
        const map = new Map();
        for (const request of requests) {
            const key = `${request.status}|${request.currency}`;
            const row = map.get(key) || { label: request.status, currency: request.currency || "ETB", requests: 0, estimate: 0 };
            row.requests += 1;
            row.estimate = round2(row.estimate + request.estimatedTotal);
            map.set(key, row);
        }
        return [...map.values()].sort((a, b) => b.requests - a.requests);
    })();

    // ---------- orders by method ----------
    const methodRows = (() => {
        const map = new Map();
        for (const order of orders) {
            const sourcing = order.purchaseRequest?.sourcing || {};
            const key = `${sourcing.methodName || "-"}|${order.currency}`;
            const row = map.get(key) || { label: sourcing.methodName || "-", currency: order.currency, orders: 0, value: 0, quotes: 0, lowest: 0 };
            const quotes = sourcing.quotes || [];
            const chosen = quotes.find(quote => toId(quote._id) === toId(sourcing.selectedQuote));
            row.orders += 1;
            row.value = round2(row.value + order.total);
            row.quotes += quotes.length;
            if (chosen && chosen.total <= Math.min(...quotes.map(quote => quote.total)) + 0.005) row.lowest += 1;
            map.set(key, row);
        }
        return [...map.values()].map(row => ({
            ...row,
            averageQuotes: row.orders ? Math.round((row.quotes / row.orders) * 10) / 10 : 0,
            lowestShare: percent(row.lowest, row.orders)
        }));
    })();

    // ---------- spend per supplier ----------
    const supplierRows = (() => {
        const map = new Map();
        for (const order of orders) {
            const key = `${toId(order.supplier?._id)}|${order.currency}`;
            const row = map.get(key) || { id: toId(order.supplier?._id), label: order.supplier?.name || "-", code: order.supplier?.supplierCode || "", currency: order.currency, orders: 0, ordered: 0, received: 0, paid: 0 };
            row.orders += 1;
            row.ordered = round2(row.ordered + order.total);
            row.received = round2(row.received + (receivedOn.get(toId(order._id)) || 0));
            row.paid = round2(row.paid + (paidOn.get(toId(order._id)) || 0));
            map.set(key, row);
        }
        const totals = {};
        for (const row of map.values()) addTo(totals, row.currency, row.ordered);
        return [...map.values()]
            .map(row => ({ ...row, share: percent(row.ordered, totals[row.currency]) }))
            .sort((a, b) => b.ordered - a.ordered);
    })();

    // ---------- by month ----------
    const monthRows = (() => {
        const map = new Map();
        const touch = (date, currency) => {
            const key = `${monthKey(date)}|${currency || "ETB"}`;
            const row = map.get(key) || { key: monthKey(date), currency: currency || "ETB", requests: 0, orders: 0, ordered: 0, paid: 0 };
            map.set(key, row);
            return row;
        };
        for (const request of requests) touch(request.requestDate, request.currency).requests += 1;
        for (const order of orders) {
            const row = touch(order.orderDate, order.currency);
            row.orders += 1;
            row.ordered = round2(row.ordered + order.total);
        }
        for (const payment of payments) {
            const row = touch(payment.expenseDate, payment.currency);
            row.paid = round2(row.paid + payment.amount);
        }
        return [...map.values()].sort((a, b) => a.key.localeCompare(b.key)).map(row => ({ ...row, label: monthName(row.key) }));
    })();

    // ---------- open orders ----------
    const today = day(new Date());
    const openRows = openOrders.map(order => {
        const received = receivedOn.get(toId(order._id)) || 0;
        const paid = paidOn.get(toId(order._id)) || 0;
        const late = order.deliveryDate && day(order.deliveryDate) < today && order.status !== "Received";
        return {
            id: toId(order._id),
            code: order.poCode,
            supplier: order.supplier?.name || "",
            status: order.status,
            deliveryDate: order.deliveryDate,
            currency: order.currency,
            ordered: round2(order.total),
            received: round2(received),
            paid: round2(paid),
            toPay: round2(order.total - paid),
            flag: late ? `Late by ${daysBetween(order.deliveryDate, new Date())} days` : received > paid + 0.005 ? "Received, not paid" : ""
        };
    });

    // ---------- exceptions (for auditors) ----------
    const exceptionRows = [];
    for (const order of orders) {
        const sourcing = order.purchaseRequest?.sourcing;
        if (!sourcing) continue;
        const quotes = sourcing.quotes || [];
        const lowest = quotes.length ? Math.min(...quotes.map(quote => quote.total)) : 0;
        const chosen = quotes.find(quote => toId(quote._id) === toId(sourcing.selectedQuote));
        if (chosen && chosen.total > lowest + 0.005) {
            exceptionRows.push({ id: toId(order._id), code: order.poCode, supplier: order.supplier?.name || "", issue: "Not the lowest quotation", detail: `${round2(chosen.total)} vs lowest ${round2(lowest)}`, reason: sourcing.selectionReason || "-", currency: order.currency });
        }
        if (quotes.length < (sourcing.minQuotes || 1)) {
            exceptionRows.push({ id: toId(order._id), code: order.poCode, supplier: order.supplier?.name || "", issue: "Fewer quotations than required", detail: `${quotes.length} of ${sourcing.minQuotes} (${sourcing.methodName})`, reason: sourcing.fewerQuotesReason || "-", currency: order.currency });
        }
    }

    // ---------- request to order time ----------
    const leadTimes = orders
        .filter(order => order.purchaseRequest?.requestDate)
        .map(order => daysBetween(order.purchaseRequest.requestDate, order.orderDate));
    const averageLead = leadTimes.length ? Math.round(leadTimes.reduce((a, b) => a + b, 0) / leadTimes.length) : null;

    const orderTotals = orders.reduce((totals, order) => addTo(totals, order.currency, order.total), {});
    const receivedTotals = notes.reduce((totals, note) => addTo(totals, note.purchaseOrder?.currency, note.value), {});
    const paidTotals = payments.reduce((totals, payment) => addTo(totals, payment.currency, payment.amount), {});
    const stillToPay = openRows.reduce((totals, row) => addTo(totals, row.currency, row.toPay), {});

    return buildReport({
        key: "procurement",
        title: "Procurement",
        description: "Purchase requests, orders, goods received and payments in the period, per method and supplier, with open orders and exceptions. Amounts in each order's currency.",
        period,
        summary: [
            summaryItem("Purchase requests", requests.length),
            summaryItem("Purchase orders", orders.length),
            summaryItem("Ordered", formatTotals(orderTotals), "text"),
            summaryItem("Goods received (value)", formatTotals(receivedTotals), "text"),
            summaryItem("Paid", formatTotals(paidTotals), "text"),
            summaryItem("Open orders", openRows.length),
            summaryItem("Still to pay on open orders", formatTotals(stillToPay), "text"),
            summaryItem("Suppliers used", new Set(orders.map(order => toId(order.supplier?._id))).size),
            summaryItem("Average days from request to order", averageLead === null ? "-" : averageLead, averageLead === null ? "text" : "number"),
            summaryItem("Exceptions", exceptionRows.length)
        ],
        sections: [
            section("suppliers", "Spend per supplier", [
                column("label", "Supplier"),
                column("code", "Code"),
                column("orders", "Orders", "number"),
                column("ordered", "Ordered", "money"),
                column("received", "Received", "money"),
                column("paid", "Paid", "money"),
                column("share", "Share", "percent"),
                column("currency", "Currency")
            ], supplierRows, { link: { kind: "supplier", idKey: "id" }, chart: { type: "bar", x: "label", series: ["ordered", "paid"], yLabel: "Amount" } }),
            section("methods", "Orders by procurement method", [
                column("label", "Method"),
                column("orders", "Orders", "number"),
                column("value", "Value", "money"),
                column("averageQuotes", "Quotations per order", "number"),
                column("lowestShare", "Lowest chosen", "percent"),
                column("currency", "Currency")
            ], methodRows),
            section("requests", "Purchase requests by status", [
                column("label", "Status"),
                column("requests", "Requests", "number"),
                column("estimate", "Estimated", "money"),
                column("currency", "Currency")
            ], requestRows, { chart: { type: "pie", x: "label", series: ["requests"] } }),
            section("month", "By month", [
                column("label", "Month"),
                column("requests", "Requests", "number"),
                column("orders", "Orders", "number"),
                column("ordered", "Ordered", "money"),
                column("paid", "Paid", "money"),
                column("currency", "Currency")
            ], monthRows, { chart: { type: "bar", x: "label", series: ["ordered", "paid"] } }),
            section("open", "Open orders (any date)", [
                column("code", "Order"),
                column("supplier", "Supplier"),
                column("status", "Status"),
                column("deliveryDate", "Deliver by", "date"),
                column("ordered", "Ordered", "money"),
                column("received", "Received", "money"),
                column("paid", "Paid", "money"),
                column("toPay", "Still to pay", "money"),
                column("currency", "Currency"),
                column("flag", "Note")
            ], openRows, { link: { kind: "purchaseOrder", idKey: "id" } }),
            section("exceptions", "Exceptions", [
                column("code", "Order"),
                column("supplier", "Supplier"),
                column("issue", "Issue"),
                column("detail", "Detail"),
                column("reason", "Reason given")
            ], exceptionRows, { link: { kind: "purchaseOrder", idKey: "id" }, note: "Orders whose bid analysis did not choose the lowest quotation, or had fewer quotations than the method asks for." })
        ],
        details: {
            title: "Purchase orders in the period",
            link: { kind: "purchaseOrder", idKey: "id" },
            columns: [
                column("code", "Order"),
                column("date", "Date", "date"),
                column("supplier", "Supplier"),
                column("request", "Request"),
                column("project", "Project"),
                column("method", "Method"),
                column("status", "Status"),
                column("total", "Total", "money"),
                column("paid", "Paid", "money"),
                column("currency", "Currency")
            ],
            rows: orders.map(order => ({
                id: toId(order._id),
                code: order.poCode,
                date: order.orderDate,
                supplier: order.supplier?.name || "",
                request: [order.purchaseRequest?.requestCode, order.purchaseRequest?.title].filter(Boolean).join(" · "),
                project: order.project?.name || "",
                method: order.purchaseRequest?.sourcing?.methodName || "",
                status: order.status,
                total: round2(order.total),
                paid: round2(paidOn.get(toId(order._id)) || 0),
                currency: order.currency
            }))
        }
    });

};


module.exports = {
    key: "procurement",
    title: "Procurement",
    description: "Requests, orders, goods received and payments: spend per supplier, by method and month, open orders and exceptions.",
    filters: ["program", "project"],
    permission: "purchase_request.read",
    generate
};
