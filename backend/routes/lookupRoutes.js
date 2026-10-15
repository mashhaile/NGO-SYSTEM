const express = require("express");


const router =
    express.Router();


const authMiddleware =
    require("../middleware/authMiddleware");

const authorize =
    require("../middleware/authorize");

const subscriptionMiddleware =
    require("../middleware/subscriptionMiddleware");


const {

    createLookupController,

    createLookupsBulkController,

    getLookupsController,

    getLookupCategoriesByModuleController,

    getLookupByModuleAndCategoryController,

    getLookupByIdController,

    updateLookupController,

    deleteLookupController

} = require("../controllers/lookupController");



// =====================================================
// CREATE SINGLE LOOKUP
// =====================================================
//
// POST /lookups
//
// Example body:
//
// {
//     "module": "Beneficiary",
//     "category": "BloodGroup",
//     "value": "A+",
//     "code": "A_POS"
// }
//
// =====================================================

router.post(

    "/",

    authMiddleware,

    subscriptionMiddleware,

    authorize("lookup.create"),

    createLookupController

);



// =====================================================
// CREATE MULTIPLE LOOKUPS
// =====================================================
//
// POST /lookups/bulk
//
// Example body:
//
// {
//     "module": "Beneficiary",
//     "category": "BloodGroup",
//     "values": [
//         {
//             "value": "A+",
//             "code": "A_POS"
//         },
//         {
//             "value": "A-",
//             "code": "A_NEG"
//         }
//     ]
// }
//
// =====================================================

router.post(

    "/bulk",

    authMiddleware,

    subscriptionMiddleware,

    authorize("lookup.create"),

    createLookupsBulkController

);



// =====================================================
// GET ALL LOOKUPS
// =====================================================
//
// GET /lookups
//
// Optional filters:
//
// ?module=Beneficiary
// ?category=BloodGroup
// ?active=true
//
// Examples:
//
// GET /lookups
//
// GET /lookups?module=Beneficiary
//
// GET /lookups?module=Beneficiary&category=BloodGroup
//
// GET /lookups?module=Beneficiary&active=true
//
// =====================================================

router.get(

    "/",

    authMiddleware,

    subscriptionMiddleware,

    authorize("lookup.read"),

    getLookupsController

);



// =====================================================
// GET CATEGORIES BY MODULE
// =====================================================
//
// Returns categories that exist for the organization.
//
// Example:
//
// GET
// /lookups/module/Beneficiary/categories
//
// Response:
//
// [
//     "BloodGroup",
//     "EducationLevel",
//     "MaritalStatus",
//     "Occupation"
// ]
//
// =====================================================
//
// IMPORTANT:
//
// This route MUST appear before /:id.
//
// =====================================================

router.get(

    "/module/:module/categories",

    authMiddleware,

    subscriptionMiddleware,

    authorize("lookup.read"),

    getLookupCategoriesByModuleController

);



// =====================================================
// GET LOOKUPS BY MODULE + CATEGORY
// =====================================================
//
// This is the PRIMARY endpoint for normal
// configurable dropdowns.
//
// Example:
//
// GET
// /lookups/module/Beneficiary/category/BloodGroup
//
// =====================================================

router.get(

    "/module/:module/category/:category",

    authMiddleware,

    subscriptionMiddleware,

    authorize("lookup.read"),

    getLookupByModuleAndCategoryController

);



// =====================================================
// GET SINGLE LOOKUP
// =====================================================
//
// GET /lookups/:id
//
// IMPORTANT:
//
// This MUST remain after all named routes above.
//
// Otherwise:
//
// /lookups/module/Beneficiary/categories
//
// could be interpreted as:
//
// /lookups/:id
//
// =====================================================

router.get(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize("lookup.read"),

    getLookupByIdController

);



// =====================================================
// UPDATE LOOKUP
// =====================================================
//
// PUT /lookups/:id
//
// =====================================================

router.put(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize("lookup.update"),

    updateLookupController

);



// =====================================================
// DEACTIVATE LOOKUP
// =====================================================
//
// DELETE /lookups/:id
//
// IMPORTANT:
//
// This performs a soft/deactivation operation.
//
// The Lookup document is retained because existing
// beneficiaries/projects/etc. may reference it.
//
// =====================================================

router.delete(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize("lookup.delete"),

    deleteLookupController

);



// =====================================================
// EXPORT
// =====================================================

module.exports = router;