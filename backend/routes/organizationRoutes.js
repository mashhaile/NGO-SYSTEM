const express = require("express");

const router =
    express.Router();


// =====================================================
// CONTROLLER
// =====================================================

const organizationController =
    require("../controllers/organizationController");


// =====================================================
// MIDDLEWARE
// =====================================================

const authMiddleware =
    require("../middleware/authMiddleware");

const authorize =
    require("../middleware/authorize");

const PERMISSIONS =
    require("../constants/permissions");


// =====================================================
// PUBLIC
// CREATE ORGANIZATION
// =====================================================
//
// Public because organization registration creates:
// - Organization
// - Organization Admin
// - Free Subscription
// - Tenant initialization
//
// If only Super Admin should create organizations,
// add authMiddleware + ORGANIZATION_CREATE here.
// =====================================================

router.post(

    "/",

    organizationController.createOrganization

);


// =====================================================
// CURRENT ORGANIZATION
// =====================================================


// -----------------------------------------------------
// GET CURRENT ORGANIZATION
// -----------------------------------------------------

router.get(

    "/me",

    authMiddleware,

    authorize(
        PERMISSIONS.ORGANIZATION_READ
    ),

    organizationController.getMyOrganization

);


// -----------------------------------------------------
// UPDATE CURRENT ORGANIZATION
// -----------------------------------------------------

router.put(

    "/me",

    authMiddleware,

    authorize(
        PERMISSIONS.ORGANIZATION_UPDATE
    ),

    organizationController.updateMyOrganization

);


// =====================================================
// SUPER ADMIN
// ORGANIZATION MANAGEMENT
// =====================================================


// -----------------------------------------------------
// GET ALL ORGANIZATIONS
// -----------------------------------------------------

router.get(

    "/admin",

    authMiddleware,

    authorize(
        PERMISSIONS.ORGANIZATION_READ
    ),

    organizationController.getAllOrganizations

);


// -----------------------------------------------------
// GET ORGANIZATION BY ID
// -----------------------------------------------------

router.get(

    "/admin/:id",

    authMiddleware,

    authorize(
        PERMISSIONS.ORGANIZATION_READ
    ),

    organizationController.getOrganizationById

);


// -----------------------------------------------------
// UPDATE ORGANIZATION
// -----------------------------------------------------

router.put(

    "/admin/:id",

    authMiddleware,

    authorize(
        PERMISSIONS.ORGANIZATION_UPDATE
    ),

    organizationController.updateOrganization

);


// -----------------------------------------------------
// UPDATE ORGANIZATION STATUS
// -----------------------------------------------------

router.put(

    "/admin/:id/status",

    authMiddleware,

    authorize(
        PERMISSIONS.ORGANIZATION_UPDATE
    ),

    organizationController.updateOrganizationStatus

);


// -----------------------------------------------------
// SOFT DELETE ORGANIZATION
// -----------------------------------------------------

router.delete(

    "/admin/:id",

    authMiddleware,

    authorize(
        PERMISSIONS.ORGANIZATION_DELETE
    ),

    organizationController.deleteOrganization

);


// -----------------------------------------------------
// RESTORE ORGANIZATION
// -----------------------------------------------------

router.put(

    "/admin/:id/restore",

    authMiddleware,

    authorize(
        PERMISSIONS.ORGANIZATION_UPDATE
    ),

    organizationController.restoreOrganization

);


// =====================================================
// EXPORT
// =====================================================

module.exports =
    router;
