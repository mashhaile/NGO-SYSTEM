const express = require("express");

const router = express.Router();


// ======================================================
// CONTROLLER
// ======================================================

const projectController =
    require("../controllers/projectController");


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

const Project =
    require("../models/Project");


// ======================================================
// VALIDATORS
// ======================================================

const {
    createProjectSchema,
    updateProjectSchema
} =
require("../validators/projectValidator");


// ======================================================
// CREATE
// ======================================================

router.post(

    "/",

    authMiddleware,

    subscriptionMiddleware,

    authorize("project.create"),

    limitMiddleware(

        "projects",

        Project

    ),

    validate(

        createProjectSchema

    ),

    projectController.createProject

);


// ======================================================
// LIST
// ======================================================

router.get(

    "/",

    authMiddleware,

    subscriptionMiddleware,

    authorize("project.read"),

    projectController.getProjects

);


// ======================================================
// LOOKUP
// Must come before /:id
// ======================================================

router.get(

    "/lookup",

    authMiddleware,

    subscriptionMiddleware,

    authorize("project.read"),

    projectController.getProjectLookup

);


// ======================================================
// SINGLE
// ======================================================

router.get(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize("project.read"),

    projectController.getProjectById

);


// ======================================================
// UPDATE
// ======================================================

router.put(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize("project.update"),

    validate(

        updateProjectSchema

    ),

    projectController.updateProject

);


// ======================================================
// DELETE
// ======================================================

router.delete(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize("project.delete"),

    projectController.deleteProject

);


module.exports = router;