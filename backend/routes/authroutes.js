const express = require("express");
const router = express.Router();

const {
    loginController,
    changePasswordController,
    meController,
} = require("../controllers/authController");

const authMiddleware = require("../middleware/authMiddleware");


router.post("/login", loginController);

router.get("/me", authMiddleware, meController);

// Signed-in user changes their own password
// (body: currentPassword, newPassword).

router.post("/change-password", authMiddleware, changePasswordController);


// TEST ROUTE (protected)
router.get("/test", authMiddleware, (req, res) => {
    res.json({
        success: true,
        message: "You are authenticated",
        user: req.user,
    });
});


module.exports = router;
