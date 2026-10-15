const express = require("express");

const router = express.Router();

const {
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
    require("../middleware/limitMiddleware");

const User =
    require("../models/User");


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