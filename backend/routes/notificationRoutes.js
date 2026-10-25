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
// My Notifications (the bell)
// ==========================================
//
// Every signed-in user reads their own notifications; no
// role permission is needed for that.
//
// ==========================================

router.get(

    "/",

    authMiddleware,

    controller.getMyNotifications

);


router.get(

    "/unread-count",

    authMiddleware,

    controller.getUnreadCount

);


router.patch(

    "/read-all",

    authMiddleware,

    controller.markAllAsRead

);


router.patch(

    "/:id/read",

    authMiddleware,

    controller.markAsRead

);


// ==========================================
// Organization Notifications (everyone's)
// ==========================================

router.get(

    "/organization",

    authMiddleware,

    authorize("notification.read"),

    controller.getOrganizationNotifications

);

module.exports = router;
