const express =
require("express");

const router =
express.Router();


const authMiddleware =
require("../middleware/authMiddleware");


const requireRole =
require("../middleware/roleMiddleware");


const {
    getPlatformAnalytics
}
=
require("../controllers/superAdminAnalyticsController");



router.get(

    "/",

    authMiddleware,

    requireRole("super_admin"),

    getPlatformAnalytics

);



module.exports =
router;