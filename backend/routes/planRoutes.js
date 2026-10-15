const express =
    require("express");


const router =
    express.Router();


const planController =
    require("../controllers/planController");


const authMiddleware =
    require("../middleware/authMiddleware");


const authorize =
    require("../middleware/authorize");


const PERMISSIONS =
    require("../constants/permissions");


// =====================================================
// PUBLIC PLANS
// =====================================================
//
// No authentication required.
//
// Returns only plans where:
// isActive = true
// isPublic = true
//
// IMPORTANT:
// Keep this route BEFORE /:id.
// =====================================================

router.get(

    "/public",

    planController.getPublicPlans

);


// =====================================================
// SUPER ADMIN - GET ALL PLANS
// =====================================================

router.get(

    "/",

    authMiddleware,

    authorize(
        PERMISSIONS.PLAN_READ
    ),

    planController.getAllPlans

);


// =====================================================
// SUPER ADMIN - GET PLAN BY ID
// =====================================================

router.get(

    "/:id",

    authMiddleware,

    authorize(
        PERMISSIONS.PLAN_READ
    ),

    planController.getPlanById

);


// =====================================================
// SUPER ADMIN - CREATE PLAN
// =====================================================

router.post(

    "/",

    authMiddleware,

    authorize(
        PERMISSIONS.PLAN_CREATE
    ),

    planController.createPlan

);


// =====================================================
// SUPER ADMIN - UPDATE PLAN
// =====================================================

router.put(

    "/:id",

    authMiddleware,

    authorize(
        PERMISSIONS.PLAN_UPDATE
    ),

    planController.updatePlan

);


// =====================================================
// SUPER ADMIN - ACTIVATE PLAN
// =====================================================

router.put(

    "/:id/activate",

    authMiddleware,

    authorize(
        PERMISSIONS.PLAN_UPDATE
    ),

    planController.activatePlan

);


// =====================================================
// SUPER ADMIN - DEACTIVATE PLAN
// =====================================================

router.put(

    "/:id/deactivate",

    authMiddleware,

    authorize(
        PERMISSIONS.PLAN_UPDATE
    ),

    planController.deactivatePlan

);


// =====================================================
// SUPER ADMIN - UPDATE VISIBILITY
// =====================================================

router.put(

    "/:id/visibility",

    authMiddleware,

    authorize(
        PERMISSIONS.PLAN_UPDATE
    ),

    planController.updatePlanVisibility

);


// =====================================================
// EXPORT
// =====================================================

module.exports =
    router;
