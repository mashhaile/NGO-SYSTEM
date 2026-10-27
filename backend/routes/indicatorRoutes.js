// =====================================================
// M&E INDICATORS  /api/v1/indicators
// =====================================================
//
// GET    /                       list (?program, project, level, status, search)
// GET    /measures               what automatic indicators can count
// GET    /settings               the organization's limits (on track / at risk from)
// PUT    /settings               change them, or { reset: true }   organization.update
// POST   /                       create                     indicator.create
// GET    /:id                    one, with its progress     indicator.read
// PUT    /:id                    update                     indicator.update
// DELETE /:id                    delete                     indicator.delete
// PUT    /:id/values/:period     enter the actual value     indicator.report
// DELETE /:id/values/:period     remove an entered value    indicator.report
//
// =====================================================

const express = require("express");

const router = express.Router();

const authMiddleware = require("../middleware/authMiddleware");
const subscriptionMiddleware = require("../middleware/subscriptionMiddleware");
const authorize = require("../middleware/authorize");
const PERMISSIONS = require("../constants/permissions");
const service = require("../services/indicatorService");
const { getErrorStatus } = require("../utils/errorStatus");

const base = [
    authMiddleware,
    subscriptionMiddleware
];

const org = (req) => req.user.organizationId;
const user = (req) => req.user.userId;

const respond = (work, status = 200) => async (req, res) => {
    try {
        res.status(status).json({ success: true, data: await work(req) });
    }
    catch (error) {
        const code = error.statusCode || getErrorStatus(error);
        if (code >= 500) console.error("INDICATOR ERROR:", error);
        res.status(code).json({ success: false, message: error.message, errors: error.errors || [] });
    }
};


router.get("/measures", ...base, authorize(PERMISSIONS.INDICATOR_READ),
    respond(() => service.MEASURES.map(({ key, name, unit, module }) => ({ key, name, unit, module }))));

// the organization's limits: on track from / at risk from (%)
router.get("/settings", ...base, authorize(PERMISSIONS.INDICATOR_READ),
    respond(req => service.getSettings(org(req))));

// only the organization admin; { onTrack, atRisk } or { reset: true }
router.put("/settings", ...base, authorize(PERMISSIONS.ORGANIZATION_UPDATE), authorize(PERMISSIONS.INDICATOR_READ),
    respond(req => service.updateSettings(org(req), req.body || {}, user(req))));

router.get("/", ...base, authorize(PERMISSIONS.INDICATOR_READ),
    respond(req => service.listIndicators(org(req), req.query)));

router.post("/", ...base, authorize(PERMISSIONS.INDICATOR_CREATE),
    respond(req => service.createIndicator(req.body || {}, org(req), user(req)), 201));

router.get("/:id", ...base, authorize(PERMISSIONS.INDICATOR_READ),
    respond(req => service.getIndicator(req.params.id, org(req))));

router.put("/:id", ...base, authorize(PERMISSIONS.INDICATOR_UPDATE),
    respond(req => service.updateIndicator(req.params.id, req.body || {}, org(req), user(req))));

router.delete("/:id", ...base, authorize(PERMISSIONS.INDICATOR_DELETE),
    respond(req => service.deleteIndicator(req.params.id, org(req), user(req))));

router.put("/:id/values/:period", ...base, authorize(PERMISSIONS.INDICATOR_REPORT),
    respond(req => service.setValue(req.params.id, req.params.period, req.body || {}, org(req), user(req))));

router.delete("/:id/values/:period", ...base, authorize(PERMISSIONS.INDICATOR_REPORT),
    respond(req => service.deleteValue(req.params.id, req.params.period, org(req))));


module.exports = router;
