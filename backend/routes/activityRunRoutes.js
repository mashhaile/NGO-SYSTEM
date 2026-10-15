const express = require("express");

const router =
    express.Router();


// ======================================================
// CONTROLLER
// ======================================================

const {

    createActivityRun,

    getActivityRuns,

    getActivityRunById,

    updateActivityRun,

    deleteActivityRun,

    getActivityRunLookup

} =
require("../controllers/activityRunController");


// ======================================================
// MIDDLEWARE
// ======================================================

const authMiddleware =
    require("../middleware/authMiddleware");

const subscriptionMiddleware =
    require("../middleware/subscriptionMiddleware");

const authorize =
    require("../middleware/authorize");


// ======================================================
// CREATE ACTIVITY RUN
// ======================================================

router.post(

    "/",

    authMiddleware,

    subscriptionMiddleware,

    authorize(
        "activity_run.create"
    ),

    createActivityRun

);


// ======================================================
// GET ALL ACTIVITY RUNS
// ======================================================

router.get(

    "/",

    authMiddleware,

    subscriptionMiddleware,

    authorize(
        "activity_run.read"
    ),

    getActivityRuns

);


// ======================================================
// ACTIVITY RUN LOOKUP
// Must come before /:id
// ======================================================

router.get(

    "/lookup",

    authMiddleware,

    subscriptionMiddleware,

    authorize(
        "activity_run.read"
    ),

    getActivityRunLookup

);


// ======================================================
// GET SINGLE ACTIVITY RUN
// ======================================================

router.get(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize(
        "activity_run.read"
    ),

    getActivityRunById

);


// ======================================================
// UPDATE ACTIVITY RUN
// ======================================================

router.put(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize(
        "activity_run.update"
    ),

    updateActivityRun

);


// ======================================================
// DELETE ACTIVITY RUN
// ======================================================

router.delete(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize(
        "activity_run.delete"
    ),

    deleteActivityRun

);


// ======================================================
// EXPORT
// ======================================================

module.exports = router;