const express = require("express");

const router = express.Router();


const attendanceController =
    require("../controllers/attendanceController");

const auth =
    require("../middleware/authMiddleware");

// Works whether authorize.js exports the function directly
// (module.exports = authorize) or as a named export ({ authorize }).
const authorizeModule =
    require("../middleware/authorize");

const authorize =
    authorizeModule.authorize || authorizeModule;

const PERMISSIONS =
    require("../constants/permissions");



// ==========================================
// Attendance Session Routes
// ==========================================


router.post(
    "/",
    auth,
    authorize(PERMISSIONS.ATTENDANCE_CREATE),
    attendanceController.createAttendance
);


router.get(
    "/",
    auth,
    authorize(PERMISSIONS.ATTENDANCE_READ),
    attendanceController.getAttendances
);


router.get(
    "/:id",
    auth,
    authorize(PERMISSIONS.ATTENDANCE_READ),
    attendanceController.getAttendanceById
);


router.put(
    "/:id",
    auth,
    authorize(PERMISSIONS.ATTENDANCE_UPDATE),
    attendanceController.updateAttendance
);


router.delete(
    "/:id",
    auth,
    authorize(PERMISSIONS.ATTENDANCE_DELETE),
    attendanceController.deleteAttendance
);



// ==========================================
// Attendance Records
// ==========================================


router.post(
    "/:id/records",
    auth,
    authorize(PERMISSIONS.ATTENDANCE_RECORD_CREATE),
    attendanceController.saveAttendanceRecords
);


router.get(
    "/:id/records",
    auth,
    authorize(PERMISSIONS.ATTENDANCE_RECORD_READ),
    attendanceController.getAttendanceRecords
);



module.exports = router;
