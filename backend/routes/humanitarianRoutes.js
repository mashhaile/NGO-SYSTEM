// =====================================================
// HUMANITARIAN RESPONSE  /api/v1/humanitarian   (module "humanitarian")
// =====================================================
//
// GET /settings   the duplicate check (period, days, same project)   service.read
// PUT /settings   change it, or { reset: true }                      organization.update
//
// =====================================================

const express = require("express");

const router = express.Router();

const authMiddleware = require("../middleware/authMiddleware");
const subscriptionMiddleware = require("../middleware/subscriptionMiddleware");
const authorize = require("../middleware/authorize");
const PERMISSIONS = require("../constants/permissions");
const ApiError = require("../utils/apiError");
const service = require("../services/humanitarianService");

const org = (req) => req.user.organizationId;
const user = (req) => req.user.userId;

// the module has no permissions of its own: check it is on
const moduleOn = async (req, res, next) => {
    try {
        if (!(await service.moduleOn(org(req)))) {
            throw new ApiError("The Humanitarian response module is not switched on for your organization.", 403);
        }
        next();
    }
    catch (error) {
        next(error);
    }
};

const base = [
    authMiddleware,
    subscriptionMiddleware,
    moduleOn
];

const respond = (work, message) => async (req, res, next) => {
    try {
        res.json({ success: true, message, data: await work(req) });
    }
    catch (error) {
        next(error);
    }
};


router.get("/settings", ...base, authorize(PERMISSIONS.SERVICE_READ),
    respond(req => service.getSettings(org(req))));

router.put("/settings", ...base, authorize(PERMISSIONS.ORGANIZATION_UPDATE),
    respond(req => service.updateSettings(org(req), req.body || {}, user(req)), "Humanitarian settings saved"));


module.exports = router;
