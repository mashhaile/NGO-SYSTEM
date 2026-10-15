const auditLogService =
require("./auditLogService");



const logAudit = async ({

    req,

    action,

    module,

    entityType,

    entityId = null,

    description = "",

    metadata = {},

    success = true,

    severity = "info"

}) => {

    try {

        await auditLogService.createAuditLog({

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

            success,

            severity,

            ipAddress:
                req.ip ||

                req.headers["x-forwarded-for"] ||

                null,

            userAgent:
                req.headers["user-agent"] ||

                null

        });

    }

    catch (error) {

        console.error(

            "Audit log failed:",

            error.message

        );

    }

};



module.exports = {

    logAudit

};