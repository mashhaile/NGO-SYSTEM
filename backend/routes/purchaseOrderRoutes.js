// =====================================================
// PURCHASE ORDERS  /api/v1/purchase-orders   (module "procurement")
// =====================================================
//
// GET    /              list (status, supplier, budget, project, fiscalYear, search)
// GET    /:id           one                              purchase_order.read
// GET    /:id/pdf       the order as a PDF               purchase_order.read
// PUT    /:id           delivery date / place, terms, notes (Issued)   purchase_order.update
// POST   /:id/cancel    Issued -> Cancelled (reason)     purchase_order.update
//
// Issued from a purchase request: POST /purchase-requests/:id/purchase-order
//
// =====================================================

const express = require("express");

const router = express.Router();

const authMiddleware = require("../middleware/authMiddleware");
const subscriptionMiddleware = require("../middleware/subscriptionMiddleware");
const authorize = require("../middleware/authorize");
const validate = require("../middleware/validate");
const PERMISSIONS = require("../constants/permissions");
const service = require("../services/purchaseOrderService");

const {
    cancelPurchaseRequestSchema
} = require("../validators/procurementValidator");

const base = [
    authMiddleware,
    subscriptionMiddleware
];

const org = (req) => req.user.organizationId;
const user = (req) => req.user.userId;

// errors go to the central error handler
const respond = (work, { status = 200, message } = {}) => async (req, res, next) => {
    try {
        const data = await work(req);
        res.status(status).json({ success: true, message, ...(data && data.pagination ? data : { data }) });
    }
    catch (error) {
        next(error);
    }
};


router.get("/", ...base, authorize(PERMISSIONS.PURCHASE_ORDER_READ),
    respond(req => service.getPurchaseOrders(org(req), req.query)));

router.get("/:id", ...base, authorize(PERMISSIONS.PURCHASE_ORDER_READ),
    respond(req => service.getPurchaseOrderById(req.params.id, org(req))));

router.get("/:id/pdf", ...base, authorize(PERMISSIONS.PURCHASE_ORDER_READ), async (req, res, next) => {
    try {
        const { buffer, fileName } = await service.buildPurchaseOrderPdf(req.params.id, org(req));
        res.setHeader("Content-Type", "application/pdf");
        res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
        res.send(buffer);
    }
    catch (error) {
        next(error);
    }
});

router.put("/:id", ...base, authorize(PERMISSIONS.PURCHASE_ORDER_UPDATE),
    respond(req => service.updatePurchaseOrder(req.params.id, req.body || {}, org(req), user(req)), { message: "Purchase order updated" }));

router.post("/:id/cancel", ...base, authorize(PERMISSIONS.PURCHASE_ORDER_UPDATE), validate(cancelPurchaseRequestSchema),
    respond(req => service.cancelPurchaseOrder(req.params.id, org(req), user(req), req.body.comment), { message: "Purchase order cancelled" }));


// ---------------------------------------------------------------- receiving and paying
//
// POST /:id/receipts                goods received note     goods_receipt.create
// POST /receipts/:noteId/cancel     cancel a note (reason; no payments yet)   goods_receipt.update
// POST /:id/payments                payment = an expense linked to the order (Draft)   expense.create
// POST /:id/close                   close short (reason; what was received is paid)   purchase_order.update

const fulfilment = require("../services/orderFulfilmentService");

router.post("/:id/receipts", ...base, authorize(PERMISSIONS.GOODS_RECEIPT_CREATE),
    respond(req => fulfilment.recordReceipt(req.params.id, req.body || {}, org(req), user(req)), { status: 201, message: "Goods received recorded" }));

router.post("/receipts/:noteId/cancel", ...base, authorize(PERMISSIONS.GOODS_RECEIPT_UPDATE), validate(cancelPurchaseRequestSchema),
    respond(req => fulfilment.cancelReceipt(req.params.noteId, org(req), user(req), req.body.comment), { message: "Goods received note cancelled" }));

router.post("/:id/payments", ...base, authorize(PERMISSIONS.PURCHASE_ORDER_READ), authorize(PERMISSIONS.EXPENSE_CREATE),
    respond(req => fulfilment.createPayment(req.params.id, req.body || {}, org(req), user(req)), { status: 201, message: "Payment recorded as an expense" }));

router.post("/:id/close", ...base, authorize(PERMISSIONS.PURCHASE_ORDER_UPDATE), validate(cancelPurchaseRequestSchema),
    respond(req => fulfilment.closeOrder(req.params.id, org(req), user(req), req.body.comment), { message: "Purchase order closed" }));


module.exports = router;
