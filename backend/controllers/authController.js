const {
    login,
    changePassword,
    getCurrentUser,
} = require("../services/authService");


// Organization sign-up is POST /api/v1/organizations
// (organizationController.createOrganization).


const loginController = async (req, res) => {
    try {
        const result = await login(req.body);

        res.json({
            success: true,
            message: "Login successful",
            data: result,
        });
    } catch (error) {
        // 401 wrong credentials, 423 locked, 403 inactive
        res.status(error.statusCode || 401).json({
            success: false,
            message: error.message,
        });
    }
};


const changePasswordController = async (req, res, next) => {
    try {
        const result = await changePassword(
            req.user.userId,
            req.body || {}
        );

        res.json({
            success: true,
            message: "Password changed successfully",
            data: result,
        });
    } catch (error) {
        next(error);
    }
};


const meController = async (req, res) => {
    try {
        const user = await getCurrentUser(req.user.userId);

        res.json({
            success: true,
            data: user,
        });
    } catch (error) {
        res.status(404).json({
            success: false,
            message: error.message,
        });
    }
};


module.exports = {
    loginController,
    changePasswordController,
    meController,
};
