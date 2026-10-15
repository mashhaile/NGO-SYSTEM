const express =
require("express");


const router =
express.Router();


const authMiddleware =
require("../middleware/authMiddleware");


const authorize =
require("../middleware/authorize");


const controller =
require("../controllers/organizationAuditLogController");




// ==========================================
// Organization Audit Logs
// ==========================================


router.get(

    "/",

    authMiddleware,

    authorize(
        "organization.audit.read"
    ),

    controller.getAuditLogs

);




router.get(

    "/:id",

    authMiddleware,

    authorize(
        "organization.audit.read"
    ),

    controller.getAuditLogDetails

);




module.exports = router;