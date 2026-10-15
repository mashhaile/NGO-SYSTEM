const express = require("express");

const router = express.Router();


const authMiddleware =
require("../middleware/authMiddleware");


const authorize =
require("../middleware/authorize");


const validate =
require("../middleware/validate");



const {

    createEnrollmentController,

    getEnrollmentsController,

    getEnrollmentByIdController,

    updateEnrollmentController,

    deleteEnrollmentController

} =
require("../controllers/enrollmentController");



const {

    createEnrollmentSchema,

    updateEnrollmentSchema

} =
require("../validators/enrollmentValidator");





// ==========================================
// CREATE ENROLLMENT
// ==========================================

router.post(

    "/",

    authMiddleware,

    authorize("enrollment.create"),

    validate(createEnrollmentSchema),

    createEnrollmentController

);





// ==========================================
// GET ALL ENROLLMENTS
// ==========================================

router.get(

    "/",

    authMiddleware,

    authorize("enrollment.read"),

    getEnrollmentsController

);





// ==========================================
// GET ENROLLMENT BY ID
// ==========================================

router.get(

    "/:id",

    authMiddleware,

    authorize("enrollment.read"),

    getEnrollmentByIdController

);





// ==========================================
// UPDATE ENROLLMENT
// ==========================================

router.put(

    "/:id",

    authMiddleware,

    authorize("enrollment.update"),

    validate(updateEnrollmentSchema),

    updateEnrollmentController

);





// ==========================================
// DELETE ENROLLMENT
// ==========================================

router.delete(

    "/:id",

    authMiddleware,

    authorize("enrollment.delete"),

    deleteEnrollmentController

);



module.exports = router;