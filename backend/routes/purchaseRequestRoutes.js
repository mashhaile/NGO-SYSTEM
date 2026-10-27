// =====================================================
// PURCHASE REQUESTS  /api/v1/purchase-requests   (module "procurement")
// =====================================================
//
// GET    /              list (budget, project, supplier, status, category, fiscalYear, from, to, search)
// POST   /              write (Draft)
// GET    /:id           details + the line's budget / spent / committed / available
// PUT    /:id           edit (Draft / Returned)
// DELETE /:id           delete (Draft / Returned)
// POST   /:id/submit    Draft / Returned -> Submitted   (must fit what the line has left)
// POST   /:id/approve   Submitted -> Approved           (purchase_request.approve; commits the money)
// POST   /:id/return    Submitted -> Returned           (purchase_request.approve; comment)
// POST   /:id/reject    Submitted -> Rejected           (purchase_request.approve; reason)
// POST   /:id/cancel    Approved -> Cancelled           (purchase_request.approve; reason; releases the money)
//
// =====================================================

const express = require("express");

const router = express.Router();

const authMiddleware = require("../middleware/authMiddleware");
const subscriptionMiddleware = require("../middleware/subscriptionMiddleware");
const authorize = require("../middleware/authorize");
const validate = require("../middleware/validate");
const PERMISSIONS = require("../constants/permissions");
const service = require("../services/purchaseRequestService");

const {
    createPurchaseRequestSchema,
    updatePurchaseRequestSchema,
    approvePurchaseRequestSchema,
    returnPurchaseRequestSchema,
    rejectPurchaseRequestSchema,
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

const { PURCHASE_REQUEST_READ: READ, PURCHASE_REQUEST_CREATE: CREATE, PURCHASE_REQUEST_UPDATE: UPDATE, PURCHASE_REQUEST_DELETE: DELETE, PURCHASE_REQUEST_APPROVE: APPROVE } = PERMISSIONS;


router.get("/", ...base, authorize(READ),
    respond(req => service.getPurchaseRequests(org(req), req.query)));

router.post("/", ...base, authorize(CREATE), validate(createPurchaseRequestSchema),
    respond(req => service.createPurchaseRequest(req.body, org(req), user(req)), { status: 201, message: "Purchase request saved" }));

router.get("/:id", ...base, authorize(READ),
    respond(req => service.getPurchaseRequestById(req.params.id, org(req))));

router.put("/:id", ...base, authorize(UPDATE), validate(updatePurchaseRequestSchema),
    respond(req => service.updatePurchaseRequest(req.params.id, req.body, org(req), user(req)), { message: "Purchase request updated" }));

router.delete("/:id", ...base, authorize(DELETE),
    respond(async req => { await service.deletePurchaseRequest(req.params.id, org(req), user(req)); return null; }, { message: "Purchase request deleted" }));

router.post("/:id/submit", ...base, authorize(UPDATE),
    respond(req => service.submitPurchaseRequest(req.params.id, org(req), user(req)), { message: "Purchase request submitted for approval" }));

router.post("/:id/approve", ...base, authorize(APPROVE), validate(approvePurchaseRequestSchema),
    respond(req => service.approvePurchaseRequest(req.params.id, org(req), user(req), req.body), { message: "Purchase request approved" }));

router.post("/:id/return", ...base, authorize(APPROVE), validate(returnPurchaseRequestSchema),
    respond(req => service.returnPurchaseRequest(req.params.id, org(req), user(req), req.body.comment), { message: "Purchase request returned for changes" }));

router.post("/:id/reject", ...base, authorize(APPROVE), validate(rejectPurchaseRequestSchema),
    respond(req => service.rejectPurchaseRequest(req.params.id, org(req), user(req), req.body.comment), { message: "Purchase request rejected" }));

router.post("/:id/cancel", ...base, authorize(APPROVE), validate(cancelPurchaseRequestSchema),
    respond(req => service.cancelPurchaseRequest(req.params.id, org(req), user(req), req.body.comment), { message: "Purchase request cancelled" }));


// ---------------------------------------------------------------- quotations and bid analysis
//
// POST   /:id/sourcing/start            { method?, etbRate? }       quotation.create
// POST   /:id/quotes                    a supplier's quotation      quotation.create
// PUT    /:id/quotes/:quoteId                                       quotation.update
// DELETE /:id/quotes/:quoteId                                       quotation.update
// PUT    /:id/sourcing                  { selectedQuote, selectionReason, fewerQuotesReason, committee }   quotation.update
// POST   /:id/sourcing/submit                                       quotation.update
// POST   /:id/sourcing/approve          { comment }   no committee  quotation.approve
// POST   /:id/sourcing/return           { comment }                 quotation.approve
// POST   /:id/sourcing/decision         { decision, comment }       a member of the committee
// POST   /:id/purchase-order            issue the purchase order    purchase_order.create

const sourcing = require("../services/sourcingService");
const purchaseOrders = require("../services/purchaseOrderService");

const body = (req) => req.body || {};

router.post("/:id/sourcing/start", ...base, authorize(PERMISSIONS.QUOTATION_CREATE),
    respond(req => sourcing.startSourcing(req.params.id, org(req), user(req), body(req)), { message: "Quotations started" }));

router.post("/:id/quotes", ...base, authorize(PERMISSIONS.QUOTATION_CREATE),
    respond(req => sourcing.addQuote(req.params.id, body(req), org(req), user(req)), { status: 201, message: "Quotation added" }));

router.put("/:id/quotes/:quoteId", ...base, authorize(PERMISSIONS.QUOTATION_UPDATE),
    respond(req => sourcing.updateQuote(req.params.id, req.params.quoteId, body(req), org(req), user(req)), { message: "Quotation updated" }));

router.delete("/:id/quotes/:quoteId", ...base, authorize(PERMISSIONS.QUOTATION_UPDATE),
    respond(req => sourcing.removeQuote(req.params.id, req.params.quoteId, org(req), user(req)), { message: "Quotation removed" }));

router.put("/:id/sourcing", ...base, authorize(PERMISSIONS.QUOTATION_UPDATE),
    respond(req => sourcing.updateBid(req.params.id, body(req), org(req), user(req)), { message: "Bid analysis saved" }));

router.post("/:id/sourcing/submit", ...base, authorize(PERMISSIONS.QUOTATION_UPDATE),
    respond(req => sourcing.submitBid(req.params.id, org(req), user(req)), { message: "Bid analysis submitted" }));

router.post("/:id/sourcing/approve", ...base, authorize(PERMISSIONS.QUOTATION_APPROVE),
    respond(req => sourcing.approveBid(req.params.id, org(req), user(req), body(req)), { message: "Bid analysis approved" }));

router.post("/:id/sourcing/return", ...base, authorize(PERMISSIONS.QUOTATION_APPROVE), validate(returnPurchaseRequestSchema),
    respond(req => sourcing.returnBid(req.params.id, org(req), user(req), req.body.comment), { message: "Bid analysis returned" }));

// committee members: membership is checked by the service
router.post("/:id/sourcing/decision", ...base, authorize(READ),
    respond(req => sourcing.decideBid(req.params.id, org(req), user(req), body(req)), { message: "Decision recorded" }));

router.post("/:id/purchase-order", ...base, authorize(PERMISSIONS.PURCHASE_ORDER_CREATE),
    respond(req => purchaseOrders.createPurchaseOrder(req.params.id, body(req), org(req), user(req)), { status: 201, message: "Purchase order issued" }));


module.exports = router;
