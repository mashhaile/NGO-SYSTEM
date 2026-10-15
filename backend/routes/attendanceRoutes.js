const express = require("express");

const router = express.Router();


const attendanceController = require("../controllers/attendanceController");


const auth = require("../middleware/authMiddleware");




// ==========================================
// Attendance Session Routes
// ==========================================


router.post(

    "/",

    auth,

    attendanceController.createAttendance

);



router.get(

    "/",

    auth,

    attendanceController.getAttendances

);



router.get(

    "/:id",

    auth,

    attendanceController.getAttendanceById

);



router.put(

    "/:id",

    auth,

    attendanceController.updateAttendance

);



router.delete(

    "/:id",

    auth,

    attendanceController.deleteAttendance

);





// ==========================================
// Attendance Records
// ==========================================


router.post(

    "/:id/records",

    auth,

    attendanceController.saveAttendanceRecords

);



router.get(

    "/:id/records",

    auth,

    attendanceController.getAttendanceRecords

);





module.exports = router;