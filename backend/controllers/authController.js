const {
    registerOrganization,
    login,
    getCurrentUser,
} = require("../services/authService");

// REGISTER ORGANIZATION
const registerOrganizationController = async (req, res) => {
    try {
        const result = await registerOrganization(req.body);

        res.status(201).json({
            success: true,
            message: "Organization registered successfully",
            data: result,
        });
    } catch (error) {
        res.status(400).json({
            success: false,
            message: error.message,
        });
    }
};

// LOGIN 
const loginController = async (req, res) => {
    try {
        const result = await login(req.body);

        res.json({
            success: true,
            message: "Login successful",
            data: result,
        });
    } catch (error) {
        res.status(401).json({
            success: false,
            message: error.message,
        });
    }
};
//Current user
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
    registerOrganizationController,
    loginController,
    meController,
};