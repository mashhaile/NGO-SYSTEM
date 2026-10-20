const express = require("express");

const router = express.Router();

const {
    resetUserPasswordController,
    createUserController,
    getUsersController,
    updateUserController,
    deleteUserController,
    getStaffLookup
} = require("../controllers/userController");

const authMiddleware =
    require("../middleware/authMiddleware");

const subscriptionMiddleware =
    require("../middleware/subscriptionMiddleware");

const authorize =
    require("../middleware/authorize");

const limitMiddleware =
    require("../middleware/LimitMiddleware");

const User =
    require("../models/user");


// ==========================================
// CREATE USER
// ==========================================

router.post(

    "/",

    authMiddleware,

    subscriptionMiddleware,

    limitMiddleware(
        "users",
        User
    ),

    authorize(
        "user.create"
    ),

    createUserController

);



// ==========================================
// GET USERS
// ==========================================

router.get(

    "/",

    authMiddleware,

    subscriptionMiddleware,

    authorize(
        "user.read"
    ),

    getUsersController

);



// ==========================================
// USER LOOKUP
// ==========================================
// Used by forms that need to select staff/users.

router.get(

    "/lookup/staff",

    authMiddleware,

    subscriptionMiddleware,

    authorize(
        "user.read"
    ),

    getStaffLookup

);



// ==========================================
// UPDATE USER
// ==========================================

router.put(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize(
        "user.update"
    ),

    updateUserController

);



// ==========================================
// RESET PASSWORD (temporary password, shown once)
// ==========================================

router.post(

    "/:id/reset-password",

    authMiddleware,

    subscriptionMiddleware,

    authorize(
        "user.update"
    ),

    resetUserPasswordController

);



// ==========================================
// DEACTIVATE USER
// ==========================================

router.delete(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize(
        "user.delete"
    ),

    deleteUserController

);



module.exports = router;