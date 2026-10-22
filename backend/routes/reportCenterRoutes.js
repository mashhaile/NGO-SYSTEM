// =====================================================
// REPORT CENTER ROUTES
// =====================================================
//
//   GET /api/v1/report-center                     catalog
//   GET /api/v1/report-center/:key                a report
//   GET /api/v1/report-center/detail/:kind/:id    one record
//   ?format=excel|pdf|csv                          as a file
//
// =====================================================

const express = require("express");
const router = express.Router();

const authMiddleware = require("../middleware/authMiddleware");
const subscriptionMiddleware = require("../middleware/subscriptionMiddleware");
const featureMiddleware = require("../middleware/FeatureMiddleware");
const controller = require("../controllers/reportCenterController");

const guards = [authMiddleware, subscriptionMiddleware, featureMiddleware("reports")];

router.get("/", ...guards, controller.getCatalog);
router.get("/detail/:kind/:id", ...guards, controller.getDetail);
router.get("/:key", ...guards, controller.getReport);

module.exports = router;
