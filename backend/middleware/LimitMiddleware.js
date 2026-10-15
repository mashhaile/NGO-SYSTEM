const ApiError =
    require("../utils/ApiError");

const {
    ROLES
} = require("../config/constants");


// ======================================================
// LIMIT MIDDLEWARE
//
// USAGE:
//
// router.post(
//     "/",
//     authMiddleware,
//     authorize(PERMISSIONS.USER_CREATE),
//     subscriptionMiddleware,
//     limitMiddleware("users", User),
//     controller
// );
//
// PURPOSE:
//
// Checks subscription resource limits before CREATE.
//
// RBAC:
// authorize()
//
// SUBSCRIPTION:
// subscriptionMiddleware
//
// LIMIT:
// limitMiddleware()
//
// SUPER ADMIN:
// Unlimited.
// ======================================================

const limitMiddleware = (
    resource,
    model
) => {

    return async (
        req,
        res,
        next
    ) => {

        try {

            // ==================================================
            // VALIDATE RESOURCE
            // ==================================================

            if (
                !resource ||
                typeof resource !== "string"
            ) {

                throw new ApiError(
                    "Subscription resource is required.",
                    500
                );

            }


            const normalizedResource =
                resource.trim();


            if (!normalizedResource) {

                throw new ApiError(
                    "Subscription resource is required.",
                    500
                );

            }


            // ==================================================
            // VALIDATE MODEL
            // ==================================================

            if (
                !model ||
                typeof model.countDocuments !== "function"
            ) {

                throw new ApiError(
                    "Resource model is required.",
                    500
                );

            }


            // ==================================================
            // SUPER ADMIN
            // ==================================================

            if (
                req.user &&
                req.user.role ===
                    ROLES.SUPER_ADMIN
            ) {

                return next();

            }


            // ==================================================
            // SUBSCRIPTION CONTEXT
            // ==================================================

            if (!req.subscription) {

                throw new ApiError(
                    "Subscription information not available.",
                    500
                );

            }


            if (!req.plan) {

                throw new ApiError(
                    "Subscription plan information not available.",
                    500
                );

            }


            // ==================================================
            // ORGANIZATION CONTEXT
            // ==================================================

            const organizationId =
                req.user?.organizationId;


            if (!organizationId) {

                throw new ApiError(
                    "Organization information is missing.",
                    400
                );

            }


            // ==================================================
            // PLAN LIMITS
            // ==================================================

            const limits =
                req.plan.limits || {};


            const limit =
                limits[normalizedResource];


            // ==================================================
            // LIMIT NOT CONFIGURED
            // ==================================================

            if (
                limit === undefined ||
                limit === null
            ) {

                throw new ApiError(

                    `Resource '${normalizedResource}' is not configured in the ${req.plan.name} plan.`,

                    403,

                    [

                        {

                            type:
                                "RESOURCE_LIMIT_NOT_CONFIGURED",

                            resource:
                                normalizedResource,

                            plan:
                                req.plan.name

                        }

                    ]

                );

            }


            // ==================================================
            // VALIDATE LIMIT
            // ==================================================

            if (
                typeof limit !== "number" ||
                !Number.isFinite(limit)
            ) {

                throw new ApiError(

                    `Invalid subscription limit configured for resource '${normalizedResource}'.`,

                    500

                );

            }


            // ==================================================
            // UNLIMITED
            //
            // -1 = unlimited
            // ==================================================

            if (
                limit === -1
            ) {

                req.subscriptionLimit = {

                    resource:
                        normalizedResource,

                    current:
                        null,

                    limit:
                        -1,

                    remaining:
                        -1

                };

                return next();

            }


            // ==================================================
            // INVALID NEGATIVE LIMIT
            // ==================================================

            if (
                limit < 0
            ) {

                throw new ApiError(

                    `Invalid subscription limit configured for resource '${normalizedResource}'.`,

                    500

                );

            }


            // ==================================================
            // BUILD ORGANIZATION FILTER
            // ==================================================

            const filter = {

                organization:
                    organizationId

            };


            // ==================================================
            // SOFT DELETE SUPPORT
            // ==================================================

            if (
                model.schema &&
                model.schema.path("isDeleted")
            ) {

                filter.isDeleted =
                    false;

            }


            // ==================================================
            // CURRENT USAGE
            // ==================================================

            const currentUsage =
                await model.countDocuments(
                    filter
                );


            // ==================================================
            // LIMIT REACHED
            // ==================================================

            if (
                currentUsage >= limit
            ) {

                throw new ApiError(

                    `${normalizedResource} limit reached for your ${req.plan.name} plan.`,

                    403,

                    [

                        {

                            type:
                                "RESOURCE_LIMIT_REACHED",

                            resource:
                                normalizedResource,

                            current:
                                currentUsage,

                            limit,

                            plan:
                                req.plan.name

                        }

                    ]

                );

            }


            // ==================================================
            // ATTACH LIMIT CONTEXT
            // ==================================================

            req.subscriptionLimit = {

                resource:
                    normalizedResource,

                current:
                    currentUsage,

                limit,

                remaining:
                    limit - currentUsage

            };


            return next();

        }

        catch (error) {

            return next(error);

        }

    };

};


module.exports =
    limitMiddleware;