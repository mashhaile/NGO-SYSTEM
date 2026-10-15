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

const limitMiddleware =
    require("../middleware/LimitMiddleware");

const Donor =
    require("../models/Donor");

const {
    createDonorSchema,
    updateDonorSchema
} = require("../validators/donorValidator");

const {
    createDonorController,
    getDonorsController,
    getDonorLookupController,
    getDonorByIdController,
    updateDonorController,
    deleteDonorController
} = require("../controllers/donorController");


// ==========================================
// CREATE
// ==========================================

router.post(

    "/",

    authMiddleware,

    subscriptionMiddleware,

    authorize("donor.create"),

    limitMiddleware(

        "donors",

        Donor

    ),

    validate(createDonorSchema),

    createDonorController

);


// ==========================================
// GET ALL
// ==========================================

router.get(

    "/",

    authMiddleware,

    authorize("donor.read"),

    getDonorsController

);


// ==========================================
// DONOR LOOKUP
// IMPORTANT: BEFORE /:id
// ==========================================

router.get(

    "/lookup",

    authMiddleware,

    subscriptionMiddleware,

    authorize("donor.read"),

    getDonorLookupController

);


// ==========================================
// UPDATE
// ==========================================

router.put(

    "/:id",

    authMiddleware,

    authorize("donor.update"),

    validate(updateDonorSchema),

    updateDonorController

);


// ==========================================
// DELETE
// ==========================================

router.delete(

    "/:id",

    authMiddleware,

    authorize("donor.delete"),

    deleteDonorController

);


// ==========================================
// GET BY ID
// ==========================================

router.get(

    "/:id",

    authMiddleware,

    authorize("donor.read"),

    getDonorByIdController

);


module.exports = router;