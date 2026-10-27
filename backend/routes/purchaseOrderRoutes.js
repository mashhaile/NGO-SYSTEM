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


module.exports = router;
