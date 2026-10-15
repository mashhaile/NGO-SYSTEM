const dashboardReport = require("../services/reports/dashboardReport");

const getDashboard = async (req, res) => {
    try {

        const filters = {
            ...req.query
        };

        const context = {
            organizationId: req.user.organizationId,
            userId: req.user.userId,
            role: req.user.role
        };

        const dashboard =
            await dashboardReport.generate(
                filters,
                context
            );

        return res.status(200).json({
            success: true,
            message: "Dashboard loaded successfully",
            data: dashboard
        });

    } catch (error) {

        console.error(
            "Dashboard error:",
            error
        );

        return res.status(500).json({
            success: false,
            message:
                error.message ||
                "Failed to load dashboard",
            errors: []
        });
    }
};

module.exports = {
    getDashboard
};