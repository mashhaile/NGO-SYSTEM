const express = require("express");

const router =
express.Router();


const authMiddleware =
require("../middleware/authMiddleware");


const authorize =
require("../middleware/authorize");


const controller =
require("../controllers/adminDashboardController");



router.get(

"/",

authMiddleware,

authorize("admin.dashboard.read"),

controller.getAdminDashboard

);



module.exports = router;