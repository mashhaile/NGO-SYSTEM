const express =
    require("express");

const router =
    express.Router();

const authMiddleware =
    require("../middleware/authMiddleware");

const requireRole =
    require("../middleware/roleMiddleware");

const controller =
    require("../controllers/adminOrganizationController");


// =====================================================
// SUPER ADMIN ORGANIZATION MANAGEMENT
// =====================================================


// =====================================================
// CREATE ORGANIZATION
// POST /api/v1/admin/organizations
// =====================================================

router.post(

    "/",

    authMiddleware,

    requireRole("super_admin"),

    controller.createOrganization

);


// =====================================================
// GET ALL ORGANIZATIONS
// GET /api/v1/admin/organizations
// =====================================================

router.get(

    "/",

    authMiddleware,

    requireRole("super_admin"),

    controller.getOrganizations

);


// =====================================================
// GET ORGANIZATION DETAILS
// GET /api/v1/admin/organizations/:id
// =====================================================

router.get(

    "/:id",

    authMiddleware,

    requireRole("super_admin"),

    controller.getOrganizationDetails

);


// =====================================================
// MODULES OF AN ORGANIZATION (on / off)
// GET /api/v1/admin/organizations/:id/modules
// PUT /api/v1/admin/organizations/:id/modules
//     { modules: { tor: false, funding: true } }
// =====================================================

const moduleService =
    require("../services/moduleService");

const { getErrorStatus } =
    require("../utils/errorStatus");

const respond = (work) => async (req, res) => {
    try {
        res.json({ success: true, data: await work(req) });
    }
    catch (error) {
        res.status(error.statusCode || getErrorStatus(error)).json({ success: false, message: error.message, errors: [] });
    }
};

router.get(
    "/:id/modules",
    authMiddleware,
    requireRole("super_admin"),
    respond(req => moduleService.listForOrganization(req.params.id))
);

router.put(
    "/:id/modules",
    authMiddleware,
    requireRole("super_admin"),
    respond(req => moduleService.updateForOrganization(req.params.id, req.body?.modules || {}, req.user?.userId))
);


// =====================================================
// UPDATE ORGANIZATION
// PATCH /api/v1/admin/organizations/:id
// =====================================================

router.patch(

    "/:id",

    authMiddleware,

    requireRole("super_admin"),

    controller.updateOrganization

);


// =====================================================
// ACTIVATE ORGANIZATION
// PATCH /api/v1/admin/organizations/:id/activate
// =====================================================

router.patch(

    "/:id/activate",

    authMiddleware,

    requireRole("super_admin"),

    controller.activateOrganization

);


// =====================================================
// SUSPEND ORGANIZATION
// PATCH /api/v1/admin/organizations/:id/suspend
// =====================================================

router.patch(

    "/:id/suspend",

    authMiddleware,

    requireRole("super_admin"),

    controller.suspendOrganization

);


// =====================================================
// DEACTIVATE ORGANIZATION
// PATCH /api/v1/admin/organizations/:id/deactivate
// =====================================================

router.patch(

    "/:id/deactivate",

    authMiddleware,

    requireRole("super_admin"),

    controller.deactivateOrganization

);


// =====================================================
// RESTORE ORGANIZATION
// PATCH /api/v1/admin/organizations/:id/restore
// =====================================================

router.patch(

    "/:id/restore",

    authMiddleware,

    requireRole("super_admin"),

    controller.restoreOrganization

);


// =====================================================
// SOFT DELETE ORGANIZATION
// DELETE /api/v1/admin/organizations/:id
// =====================================================

router.delete(

    "/:id",

    authMiddleware,

    requireRole("super_admin"),

    controller.deleteOrganization

);


module.exports =
    router;
