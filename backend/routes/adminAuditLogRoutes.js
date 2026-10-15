const express =
require("express");


const router =
express.Router();



const authMiddleware =
require("../middleware/authMiddleware");


const authorize =
require("../middleware/authorize");


const controller =
require("../controllers/adminAuditLogController");





// ==========================================
// Super Admin Audit Logs
// ==========================================


router.get(

    "/",

    authMiddleware,

    authorize(
        "admin.audit.read"
    ),

    controller.getAuditLogs

);





router.get(

    "/:id",

    authMiddleware,

    authorize(
        "admin.audit.read"
    ),

    controller.getAuditLogDetails

);





module.exports = router;