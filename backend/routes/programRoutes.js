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

const Program =
    require("../models/program");


// ======================================================
// VALIDATORS
// ======================================================

const {

    createProgramSchema,

    updateProgramSchema

} = require("../validators/programvalidator");


// ======================================================
// CONTROLLERS
// ======================================================

const {

    createProgramController,

    getProgramsController,

    getProgramByIdController,

    updateProgramController,

    deleteProgramController,

    getProgramsLookupController

} = require("../controllers/programController");



// ======================================================
// CREATE PROGRAM
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
// Plan resource limit
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

    authorize("program.create"),

    limitMiddleware(

        "programs",

        Program

    ),

    validate(createProgramSchema),

    createProgramController

);



// ======================================================
// GET ALL PROGRAMS
// ======================================================

router.get(

    "/",

    authMiddleware,

    subscriptionMiddleware,

    authorize("program.read"),

    getProgramsController

);



// ======================================================
// PROGRAM LOOKUP
// ======================================================
//
// IMPORTANT:
// Must remain before "/:id"
// ======================================================

router.get(

    "/lookup",

    authMiddleware,

    subscriptionMiddleware,

    authorize("program.read"),

    getProgramsLookupController

);



// ======================================================
// GET PROGRAM BY ID
// ======================================================

router.get(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize("program.read"),

    getProgramByIdController

);



// ======================================================
// UPDATE PROGRAM
// ======================================================

router.put(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize("program.update"),

    validate(updateProgramSchema),

    updateProgramController

);



// ======================================================
// DELETE PROGRAM
// ======================================================

router.delete(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize("program.delete"),

    deleteProgramController

);



module.exports = router;