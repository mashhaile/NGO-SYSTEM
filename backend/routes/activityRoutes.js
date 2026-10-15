const express =
    require("express");


const router =
    express.Router();


// ======================================================
// CONTROLLER
// ======================================================

const {

    createActivity,

    getActivities,

    getActivityById,

    updateActivity,

    deleteActivity,

    getActivityLookup

} =
require("../controllers/activityController");


// ======================================================
// MIDDLEWARE
// ======================================================

const authMiddleware =
    require("../middleware/authMiddleware");

const subscriptionMiddleware =
    require("../middleware/subscriptionMiddleware");

const authorize =
    require("../middleware/authorize");

const validate =
    require("../middleware/validate");

const limitMiddleware =
    require("../middleware/LimitMiddleware");


// ======================================================
// MODEL
// ======================================================

const Activity =
    require("../models/Activity");


// ======================================================
// VALIDATORS
// ======================================================

const {

    createActivitySchema,

    updateActivitySchema

} =
require("../validators/activityValidator");


// ======================================================
// ACTIVITY LOOKUP
// Must come before /:id
//
// Used by Activity Run dropdown
// ======================================================

router.get(

    "/lookup",

    authMiddleware,

    subscriptionMiddleware,

    authorize(
        "activity.read"
    ),

    getActivityLookup

);


// ======================================================
// CREATE ACTIVITY
// ======================================================

router.post(

    "/",

    authMiddleware,

    subscriptionMiddleware,

    authorize(
        "activity.create"
    ),

    limitMiddleware(

        "activities",

        Activity

    ),

    validate(
        createActivitySchema
    ),

    createActivity

);


// ======================================================
// GET ALL ACTIVITIES
// ======================================================

router.get(

    "/",

    authMiddleware,

    subscriptionMiddleware,

    authorize(
        "activity.read"
    ),

    getActivities

);


// ======================================================
// GET SINGLE ACTIVITY
// ======================================================

router.get(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize(
        "activity.read"
    ),

    getActivityById

);


// ======================================================
// UPDATE ACTIVITY
// ======================================================

router.put(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize(
        "activity.update"
    ),

    validate(
        updateActivitySchema
    ),

    updateActivity

);


// ======================================================
// DELETE ACTIVITY
// ======================================================

router.delete(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize(
        "activity.delete"
    ),

    deleteActivity

);


// ======================================================
// EXPORT
// ======================================================

module.exports =
    router;