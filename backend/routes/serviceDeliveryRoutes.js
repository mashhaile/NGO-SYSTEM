const express = require("express");

const router = express.Router();


// ======================================================
// MIDDLEWARE
// ======================================================

const authMiddleware =
    require("../middleware/authMiddleware");

const authorize =
    require("../middleware/authorize");

const validate =
    require("../middleware/validate");

const subscriptionMiddleware =
    require("../middleware/subscriptionMiddleware");

const limitMiddleware =
    require("../middleware/LimitMiddleware");


// ======================================================
// MODEL
// ======================================================

const ServiceDelivery =
    require("../models/ServiceDelivery");


// ======================================================
// VALIDATORS
// ======================================================

const {

    createServiceDeliverySchema,

    updateServiceDeliverySchema

} =
require("../validators/serviceDeliveryValidator");


// ======================================================
// CONTROLLERS
// ======================================================

const {

    createServiceDeliveryController,

    getServiceDeliveriesController,

    getServiceDeliveryByIdController,

    getExpenseOptionsController,

    getDoubleCountingController,

    setExpenseLinkController,

    updateServiceDeliveryController,

    deleteServiceDeliveryController

} =
require("../controllers/serviceDeliveryController");


// ======================================================
// CREATE SERVICE DELIVERY
// ======================================================
//
// SaaS protection:
//
// Authentication
//       ↓
// Organization + Subscription
//       ↓
// Permission
//       ↓
// Plan Resource Limit
//       ↓
// Validation
//       ↓
// Controller
//
// ======================================================

router.post(

    "/",

    authMiddleware,

    subscriptionMiddleware,

    authorize("service.create"),

    limitMiddleware(

        "serviceDeliveries",

        ServiceDelivery

    ),

    validate(

        createServiceDeliverySchema

    ),

    createServiceDeliveryController

);


// ======================================================
// GET ALL SERVICE DELIVERIES
// ======================================================

router.get(

    "/",

    authMiddleware,

    subscriptionMiddleware,

    authorize("service.read"),

    getServiceDeliveriesController

);


// ======================================================
// BOUGHT WITH AN EXPENSE (before "/:id")
// ======================================================
//
// The expenses an item may have been bought with, the
// possible double counting to review, and linking an item
// to its expense (or marking it as separate).
//
// ======================================================

router.get(
    "/expense-options",
    authMiddleware,
    subscriptionMiddleware,
    authorize("service.read"),
    getExpenseOptionsController
);

router.get(
    "/double-counting",
    authMiddleware,
    subscriptionMiddleware,
    authorize("service.read"),
    getDoubleCountingController
);

router.post(
    "/:id/items/:itemId/expense-link",
    authMiddleware,
    subscriptionMiddleware,
    authorize("service.update"),
    setExpenseLinkController
);


// ======================================================
// GET SINGLE SERVICE DELIVERY
// ======================================================

router.get(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize("service.read"),

    getServiceDeliveryByIdController

);


// ======================================================
// UPDATE SERVICE DELIVERY
// ======================================================

router.put(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize("service.update"),

    validate(

        updateServiceDeliverySchema

    ),

    updateServiceDeliveryController

);


// ======================================================
// DELETE SERVICE DELIVERY
// ======================================================

router.delete(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize("service.delete"),

    deleteServiceDeliveryController

);


module.exports = router;