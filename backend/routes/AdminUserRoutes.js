const express =
require("express");


const router =
express.Router();


const authMiddleware =
require("../middleware/authMiddleware");


const authorize =
require("../middleware/authorize");


const controller =
require("../controllers/adminUserController");




// ==========================================
// Super Admin User Management
// ==========================================


router.post(

    "/",

    authMiddleware,

    authorize(
        "admin.user.create"
    ),

    controller.createUser

);




router.get(

    "/",

    authMiddleware,

    authorize(
        "admin.user.read"
    ),

    controller.getUsers

);




router.get(

    "/:id",

    authMiddleware,

    authorize(
        "admin.user.read"
    ),

    controller.getUserDetails

);


// Reset any user's password (temporary password, shown once)

router.post(

    "/:id/reset-password",

    authMiddleware,

    authorize(
        "admin.user.update"
    ),

    controller.resetUserPassword

);




module.exports =
router;