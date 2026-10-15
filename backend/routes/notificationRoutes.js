const express =
require("express");

const router =
express.Router();

const authMiddleware =
require("../middleware/authMiddleware");

const authorize =
require("../middleware/authorize");

const controller =
require("../controllers/notificationController");


// ==========================================
// User Notifications
// ==========================================

router.get(

    "/",

    authMiddleware,

    authorize("notification.read"),

    controller.getMyNotifications

);


// ==========================================
// Organization Notifications
// ==========================================

router.get(

    "/organization",

    authMiddleware,

    authorize("notification.read"),

    controller.getOrganizationNotifications

);


// ==========================================
// Mark Read
// ==========================================

router.patch(

    "/:id/read",

    authMiddleware,

    authorize("notification.read"),

    controller.markAsRead

);


// ==========================================
// Unread Count
// ==========================================

router.get(

    "/unread-count",

    authMiddleware,

    authorize("notification.read"),

    controller.getUnreadCount

);

module.exports = router;