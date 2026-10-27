// =====================================================
// PROCUREMENT SETUP  /api/v1/procurement   (module "procurement")
// =====================================================
//
// GET    /settings              methods by amount (limits, quotes, committee)
// PUT    /settings              change them, or { reset: true }   organization.update
// GET    /committees            the committees (?status)          committee.read
// GET    /committees/members    users that can be members         committee.read
// POST   /committees            add                               committee.create
// GET    /committees/:id                                          committee.read
// PUT    /committees/:id                                          committee.update
// DELETE /committees/:id                                          committee.delete
// GET    /waiting-for-me        bid analyses waiting for my committee decision
//
// =====================================================

const express = require("express");

const router = express.Router();

const authMiddleware = require("../middleware/authMiddleware");
const subscriptionMiddleware = require("../middleware/subscriptionMiddleware");
const authorize = require("../middleware/authorize");
const PERMISSIONS = require("../constants/permissions");
const settings = require("../services/procurementSettingsService");
const committees = require("../services/committeeService");
const sourcing = require("../services/sourcingService");

const base = [
    authMiddleware,
    subscriptionMiddleware
];

const org = (req) => req.user.organizationId;
const user = (req) => req.user.userId;

// errors go to the central error handler
const respond = (work, { status = 200, message } = {}) => async (req, res, next) => {
    try {
        res.status(status).json({ success: true, message, data: await work(req) });
    }
    catch (error) {
        next(error);
    }
};


router.get("/settings", ...base, authorize(PERMISSIONS.PURCHASE_REQUEST_READ),
    respond(req => settings.getSettings(org(req))));

// only the organization admin; { methods } or { reset: true }
router.put("/settings", ...base, authorize(PERMISSIONS.ORGANIZATION_UPDATE), authorize(PERMISSIONS.PURCHASE_REQUEST_READ),
    respond(req => settings.updateSettings(org(req), req.body || {}, user(req)), { message: "Procurement settings saved" }));

router.get("/committees", ...base, authorize(PERMISSIONS.COMMITTEE_READ),
    respond(req => committees.getCommittees(org(req), req.query)));

router.get("/committees/members", ...base, authorize(PERMISSIONS.COMMITTEE_READ),
    respond(req => committees.getMemberOptions(org(req))));

router.post("/committees", ...base, authorize(PERMISSIONS.COMMITTEE_CREATE),
    respond(req => committees.createCommittee(req.body || {}, org(req), user(req)), { status: 201, message: "Committee added" }));

router.get("/committees/:id", ...base, authorize(PERMISSIONS.COMMITTEE_READ),
    respond(req => committees.getCommitteeById(req.params.id, org(req))));

router.put("/committees/:id", ...base, authorize(PERMISSIONS.COMMITTEE_UPDATE),
    respond(req => committees.updateCommittee(req.params.id, req.body || {}, org(req), user(req)), { message: "Committee updated" }));

router.delete("/committees/:id", ...base, authorize(PERMISSIONS.COMMITTEE_DELETE),
    respond(async req => { await committees.deleteCommittee(req.params.id, org(req), user(req)); return null; }, { message: "Committee deleted" }));

router.get("/waiting-for-me", ...base, authorize(PERMISSIONS.PURCHASE_REQUEST_READ),
    respond(req => sourcing.waitingForMe(org(req), user(req))));


module.exports = router;
