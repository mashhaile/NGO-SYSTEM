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

const Donation =
    require("../models/donation");


// ======================================================
// VALIDATORS
// ======================================================

const {

    createDonationSchema,

    updateDonationSchema

} =
require("../validators/donationValidator");


// ======================================================
// CONTROLLERS
// ======================================================

const {

    createDonationController,

    getDonationsController,

    getDonationByIdController,

    updateDonationController,

    deleteDonationController

} =
require("../controllers/donationController");


// ======================================================
// CREATE DONATION
// ======================================================

router.post(

    "/",

    authMiddleware,

    subscriptionMiddleware,

    authorize(
        "donation.create"
    ),

    limitMiddleware(

        "donations",

        Donation

    ),

    validate(
        createDonationSchema
    ),

    createDonationController

);


// ======================================================
// GET ALL DONATIONS
// ======================================================

router.get(

    "/",

    authMiddleware,

    subscriptionMiddleware,

    authorize(
        "donation.read"
    ),

    getDonationsController

);


// ======================================================
// GET SINGLE DONATION
// ======================================================

router.get(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize(
        "donation.read"
    ),

    getDonationByIdController

);


// ======================================================
// UPDATE DONATION
// ======================================================

router.put(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize(
        "donation.update"
    ),

    validate(
        updateDonationSchema
    ),

    updateDonationController

);


// ======================================================
// DELETE DONATION
// ======================================================

router.delete(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize(
        "donation.delete"
    ),

    deleteDonationController

);


module.exports = router;