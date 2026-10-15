const express = require("express");

const router = express.Router();


// =====================================================
// MIDDLEWARE
// =====================================================

const authMiddleware =
    require("../middleware/authMiddleware");

const authorize =
    require("../middleware/authorize");

const subscriptionMiddleware =
    require("../middleware/subscriptionMiddleware");


// =====================================================
// CONTROLLER
// =====================================================

const {
    createEnterpriseMemberController,
    getEnterpriseMembersController,
    getEnterpriseMemberByIdController,
    updateEnterpriseMemberController,
    deleteEnterpriseMemberController,
    getMembersByEnterpriseController,
    getEnterprisesByMemberController
} =
    require("../controllers/enterpriseMemberController");


// =====================================================
// CREATE ENTERPRISE MEMBER
// =====================================================
// Add a beneficiary to an existing enterprise
//
// POST
// /api/enterprise-members
//
// Example body:
//
// {
//     "enterprise": "ENTERPRISE_ID",
//     "beneficiary": "BENEFICIARY_ID",
//     "role": "LOOKUP_ID",
//     "joinedDate": "2026-08-21"
// }
// =====================================================

router.post(

    "/",

    authMiddleware,

    subscriptionMiddleware,

    authorize("enterprise.update"),

    createEnterpriseMemberController

);


// =====================================================
// GET ALL ENTERPRISE MEMBERS
// =====================================================
//
// GET
// /api/enterprise-members
//
// Supports normal queryHelper filters/pagination.
// =====================================================

router.get(

    "/",

    authMiddleware,

    subscriptionMiddleware,

    authorize("enterprise.read"),

    getEnterpriseMembersController

);


// =====================================================
// GET MEMBERS BY ENTERPRISE
// =====================================================
//
// IMPORTANT:
// Must come before /:id
//
// GET
// /api/enterprise-members/enterprise/:enterpriseId
//
// Returns all beneficiaries belonging to
// one shared enterprise.
// =====================================================

router.get(

    "/enterprise/:enterpriseId",

    authMiddleware,

    subscriptionMiddleware,

    authorize("enterprise.read"),

    getMembersByEnterpriseController

);


// =====================================================
// GET ENTERPRISES BY BENEFICIARY
// =====================================================
//
// IMPORTANT:
// Must come before /:id
//
// GET
// /api/enterprise-members/beneficiary/:beneficiaryId
//
// Returns all enterprises in which a beneficiary
// participates.
// =====================================================

router.get(

    "/beneficiary/:beneficiaryId",

    authMiddleware,

    subscriptionMiddleware,

    authorize("enterprise.read"),

    getEnterprisesByMemberController

);


// =====================================================
// GET MEMBER BY ID
// =====================================================

router.get(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize("enterprise.read"),

    getEnterpriseMemberByIdController

);


// =====================================================
// UPDATE MEMBER
// =====================================================
//
// Example:
// change role
// change status
// change joined/left dates
// update custom fields
// =====================================================

router.put(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize("enterprise.update"),

    updateEnterpriseMemberController

);


// =====================================================
// DELETE MEMBER
// =====================================================
//
// Soft deletes the relationship.
// It does NOT delete the enterprise.
// It does NOT delete the beneficiary.
// =====================================================

router.delete(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize("enterprise.update"),

    deleteEnterpriseMemberController

);


// =====================================================
// EXPORT
// =====================================================

module.exports = router;