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




module.exports =
router;