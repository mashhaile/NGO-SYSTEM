const express =
    require("express");

const router =
    express.Router();


const authMiddleware =
    require("../middleware/authMiddleware");

const subscriptionMiddleware =
    require("../middleware/subscriptionMiddleware");

const authorize =
    require("../middleware/authorize");


const {
    getDonationTrace,
    getDonorTrace,
    getUntracedSpending,
    downloadDonationStatement
} = require("../controllers/donationTraceController");



// =====================================================
// DONATION TRACE
// =====================================================
//
// GET /donation-trace/donations/:id            where a donation went
// GET /donation-trace/donations/:id/statement  donor statement PDF
// GET /donation-trace/donors/:id               all donations of a donor
// GET /donation-trace/untraced                 delivered items not linked to a donation
//
// =====================================================

const base = [
    authMiddleware,
    subscriptionMiddleware
];


router.get(
    "/untraced",
    ...base,
    authorize("donation.read"),
    getUntracedSpending
);

router.get(
    "/donations/:id/statement",
    ...base,
    authorize("donation.read"),
    downloadDonationStatement
);

router.get(
    "/donations/:id",
    ...base,
    authorize("donation.read"),
    getDonationTrace
);

router.get(
    "/donors/:id",
    ...base,
    authorize("donor.read"),
    getDonorTrace
);


module.exports = router;
