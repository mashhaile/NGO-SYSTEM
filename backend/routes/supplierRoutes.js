// =====================================================
// SUPPLIERS  /api/v1/suppliers   (module "procurement")
// =====================================================
//
// GET    /            list (?search, status, category, page, limit)
// GET    /options     the active suppliers, for pickers
// POST   /            add                    supplier.create
// GET    /:id         one, with its requests supplier.read
// PUT    /:id         edit                   supplier.update
// DELETE /:id         delete (unused only)   supplier.delete
//
// =====================================================

const express = require("express");

const router = express.Router();

const authMiddleware = require("../middleware/authMiddleware");
const subscriptionMiddleware = require("../middleware/subscriptionMiddleware");
const authorize = require("../middleware/authorize");
const validate = require("../middleware/validate");
const PERMISSIONS = require("../constants/permissions");
const service = require("../services/supplierService");

const {
    createSupplierSchema,
    updateSupplierSchema
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


router.get("/", ...base, authorize(PERMISSIONS.SUPPLIER_READ),
    respond(req => service.getSuppliers(org(req), req.query)));

router.get("/options", ...base, authorize(PERMISSIONS.SUPPLIER_READ),
    respond(req => service.getSupplierOptions(org(req))));

router.post("/", ...base, authorize(PERMISSIONS.SUPPLIER_CREATE), validate(createSupplierSchema),
    respond(req => service.createSupplier(req.body, org(req), user(req)), { status: 201, message: "Supplier added" }));

router.get("/:id", ...base, authorize(PERMISSIONS.SUPPLIER_READ),
    respond(req => service.getSupplierById(req.params.id, org(req))));

router.put("/:id", ...base, authorize(PERMISSIONS.SUPPLIER_UPDATE), validate(updateSupplierSchema),
    respond(req => service.updateSupplier(req.params.id, req.body, org(req), user(req)), { message: "Supplier updated" }));

router.delete("/:id", ...base, authorize(PERMISSIONS.SUPPLIER_DELETE),
    respond(async req => { await service.deleteSupplier(req.params.id, org(req), user(req)); return null; }, { message: "Supplier deleted" }));


module.exports = router;
