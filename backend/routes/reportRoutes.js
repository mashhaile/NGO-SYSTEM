const express = require("express");

const router = express.Router();

const authMiddleware = require("../middleware/authMiddleware");
const subscriptionMiddleware = require("../middleware/subscriptionMiddleware");
const featureMiddleware = require("../middleware/FeatureMiddleware");

const reportController = require("../controllers/reportController");


// ================= Report Catalog =================

router.get(
    "/",
    authMiddleware,
    subscriptionMiddleware,
    featureMiddleware("reports"),
    reportController.getReports
);


// ================= Generate Report =================

router.get(
    "/:reportName",
    authMiddleware,
    subscriptionMiddleware,
    featureMiddleware("reports"),
    reportController.getReport
);

module.exports = router;