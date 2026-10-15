const express = require("express");
const router = express.Router();

const {
    registerOrganizationController,
    loginController,
    meController,
} = require("../controllers/authController");
const authMiddleware = require("../middleware/authMiddleware");

// Register organization (public)
router.post("/register-organization", registerOrganizationController);
router.post("/login", loginController);
router.get("/me", authMiddleware, meController);

// TEST ROUTE (protected)
router.get("/test", authMiddleware, (req, res) => {
    res.json({
        success: true,
        message: "You are authenticated",
        user: req.user,
    });
});

module.exports = router;
