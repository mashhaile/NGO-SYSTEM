const AuditLog =
require("../models/AuditLog");


// ==========================================
// Central Audit Logger
// ==========================================

const logActivity = async ({

    req,

    action,

    module,

    entityType,

    entityId = null,

    description,

    metadata = {},

    severity = "info"

}) => {


    try {


        await AuditLog.create({

            organizationId:
                req.user?.organizationId || null,


            userId:
                req.user?.userId || null,


            action,


            module,


            entityType,


            entityId,


            description,


            metadata,


            success:true,


            severity,


            ipAddress:
                req.ip || null,


            userAgent:
                req.headers["user-agent"] || null,


        });


    }


    catch(error){


        console.error(
            "Audit Log Error:",
            error.message
        );


        // Do not stop the main request
        // if audit logging fails

    }


};



module.exports = {

    logActivity

};