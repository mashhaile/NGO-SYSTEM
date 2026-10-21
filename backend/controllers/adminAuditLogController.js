const {
    getErrorStatus,
    getErrorMessage
} = require("../utils/errorStatus");

const service =
require("../services/auditLogService");



// ==========================================
// Get Audit Logs
// ==========================================

const getAuditLogs = async (

    req,

    res

) => {

    try {

        const data =
            await service.getAuditLogs(
                req.query
            );

        res.json({

            success: true,

            data

        });

    }

    catch (error) {

        res.status(getErrorStatus(error)).json({

            success: false,

            message: getErrorMessage(error)

        });

    }

};



// ==========================================
// Get Audit Log Details
// ==========================================

const getAuditLogDetails = async (

    req,

    res

) => {

    try {

        const data =
            await service.getAuditLogById(
                req.params.id
            );

        if (!data) {

            return res.status(404).json({

                success: false,

                message: "Audit log not found"

            });

        }

        res.json({

            success: true,

            data

        });

    }

    catch (error) {

        res.status(getErrorStatus(error)).json({

            success: false,

            message: getErrorMessage(error)

        });

    }

};



// ==========================================
// Get Recent Activities
// ==========================================

const getRecentActivities = async (

    req,

    res

) => {

    try {

        const limit =
            Number(req.query.limit) || 10;

        const organizationId =
            req.query.organizationId || null;

        const data =
            await service.getRecentActivities(

                limit,

                organizationId

            );

        res.json({

            success: true,

            data

        });

    }

    catch (error) {

        res.status(getErrorStatus(error)).json({

            success: false,

            message: getErrorMessage(error)

        });

    }

};



// ==========================================
// Get Audit Statistics
// ==========================================

const getAuditStatistics = async (

    req,

    res

) => {

    try {

        const organizationId =
            req.query.organizationId || null;

        const data =
            await service.getAuditStatistics(
                organizationId
            );

        res.json({

            success: true,

            data

        });

    }

    catch (error) {

        res.status(getErrorStatus(error)).json({

            success: false,

            message: getErrorMessage(error)

        });

    }

};



// ==========================================
// Get User Activity
// ==========================================

const getUserActivity = async (

    req,

    res

) => {

    try {

        const limit =
            Number(req.query.limit) || 20;

        const data =
            await service.getUserActivity(

                req.params.userId,

                limit

            );

        res.json({

            success: true,

            data

        });

    }

    catch (error) {

        res.status(getErrorStatus(error)).json({

            success: false,

            message: getErrorMessage(error)

        });

    }

};




module.exports = {

    getAuditLogs,

    getAuditLogDetails,

    getRecentActivities,

    getAuditStatistics,

    getUserActivity

};