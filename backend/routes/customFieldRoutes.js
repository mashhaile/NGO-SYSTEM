const express = require("express");

const router = express.Router();


const authMiddleware =
    require("../middleware/authMiddleware");

const authorize =
    require("../middleware/authorize");

const validate =
    require("../middleware/validate");

const subscriptionMiddleware =
    require("../middleware/subscriptionMiddleware");


const {

    createCustomFieldSchema,

    updateCustomFieldSchema

} = require("../validators/customFieldValidator");


const {

    createCustomFieldController,

    getCustomFieldsController,

    getLookupFieldsByModuleController,

    getCustomFieldByIdController,

    updateCustomFieldController,

    deleteCustomFieldController

} = require("../controllers/customFieldController");


// =======================================
// CREATE CUSTOM FIELD
// =======================================

router.post(

    "/",

    authMiddleware,

    subscriptionMiddleware,

    authorize("customfield.create"),

    validate(createCustomFieldSchema),

    createCustomFieldController

);


// =======================================
// GET LOOKUP FIELDS BY MODULE
// =======================================
//
// IMPORTANT:
//
// This MUST come before:
//
// /module/:module
//
// because this is a more specific route.
//
// Example:
//
// GET /custom-fields/module/Beneficiary/lookup-fields
//
// Returns CustomFields configured with:
//
// optionSource: "lookup"
//
// =======================================




// =======================================
// GET CUSTOM FIELDS BY MODULE
// =======================================
//
// Example:
//
// GET /custom-fields/module/Beneficiary
//
// =======================================

router.get(

    "/module/:module",

    authMiddleware,

    subscriptionMiddleware,

    authorize("customfield.read"),

    getCustomFieldsController

);


// =======================================
// GET CUSTOM FIELD BY ID
// =======================================

router.get(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize("customfield.read"),

    getCustomFieldByIdController

);


// =======================================
// UPDATE CUSTOM FIELD
// =======================================

router.put(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize("customfield.update"),

    validate(updateCustomFieldSchema),

    updateCustomFieldController

);


// =======================================
// DELETE CUSTOM FIELD
// =======================================

router.delete(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize("customfield.delete"),

    deleteCustomFieldController

);


// =======================================
// EXPORT
// =======================================

module.exports = router;