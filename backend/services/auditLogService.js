const AuditLog =
require("../models/AuditLog");




// Create audit log

const createAuditLog = async (
    data
) => {

    const log =
        await AuditLog.create(data);

    return log;

};




// Get audit logs

const getAuditLogs = async (
    filters = {}
) => {

    const {

        organizationId,

        userId,

        action,

        module,

        startDate,

        endDate,

        page = 1,

        limit = 20

    } = filters;



    const query = {};



    if (organizationId) {

        query.organizationId =
            organizationId;

    }



    if (userId) {

        query.userId =
            userId;

    }



    if (action) {

        query.action =
            action;

    }



    if (module) {

        query.module =
            module;

    }



    if (startDate || endDate) {

        query.createdAt = {};



        if (startDate) {

            query.createdAt.$gte =
                new Date(startDate);

        }



        if (endDate) {

            query.createdAt.$lte =
                new Date(endDate);

        }

    }



    const skip =
        (page - 1) * limit;



    const logs =
        await AuditLog.find(query)

            .populate(
                "userId",
                "name email role"
            )

            .populate(
                "organizationId",
                "name"
            )

            .sort({

                createdAt: -1

            })

            .skip(skip)

            .limit(Number(limit));



    const total =
        await AuditLog.countDocuments(query);



    return {

        logs,

        pagination: {

            total,

            page: Number(page),

            limit: Number(limit),

            pages:
                Math.ceil(
                    total / limit
                )

        }

    };

};




// Get single audit log

const getAuditLogById = async (
    id
) => {


    const log =
        await AuditLog.findById(id)

            .populate(
                "userId",
                "name email role"
            )

            .populate(
                "organizationId",
                "name"
            );



    return log;

};
// ==========================================
// Recent Activity
// ==========================================

const getRecentActivities = async (

    limit = 10,

    organizationId = null

) => {

    const query = {

        isDeleted: false

    };



    if (organizationId) {

        query.organizationId =
            organizationId;

    }



    return await AuditLog.find(query)

        .populate(

            "userId",

            "name email role"

        )

        .populate(

            "organizationId",

            "name"

        )

        .sort({

            createdAt: -1

        })

        .limit(limit);

};

// ==========================================
// Audit Statistics
// ==========================================

const getAuditStatistics = async (

    organizationId = null

) => {

    const match = {

        isDeleted: false

    };



    if (organizationId) {

        match.organizationId =
            organizationId;

    }



    return await AuditLog.aggregate([

        {

            $match: match

        },

        {

            $group: {

                _id: "$module",

                total: {

                    $sum: 1

                }

            }

        },

        {

            $sort: {

                total: -1

            }

        }

    ]);

};

// ==========================================
// User Activity
// ==========================================

const getUserActivity = async (

    userId,

    limit = 20

) => {

    return await AuditLog.find({

        userId,

        isDeleted: false

    })

    .sort({

        createdAt: -1

    })

    .limit(limit);

};


module.exports = {

    createAuditLog,

    getAuditLogs,

    getAuditLogById,

    getRecentActivities,

    getAuditStatistics,

    getUserActivity

};