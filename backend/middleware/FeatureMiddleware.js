const ApiError =
    require("../utils/apiError");

const {
    ROLES
} = require("../config/constants");


// ======================================================
// FEATURE MIDDLEWARE
//
// PURPOSE:
//
// Checks whether the organization's subscription plan
// contains a requested feature.
//
// RBAC:
// authorize()
//
// SUBSCRIPTION:
// subscriptionMiddleware
//
// FEATURE:
// featureMiddleware()
//
// LIMIT:
// limitMiddleware()
//
// SUPER ADMIN:
// Always allowed.
// ======================================================

const featureMiddleware = (
    feature
) => {

    return (
        req,
        res,
        next
    ) => {

        try {

            // ==================================================
            // VALIDATE FEATURE
            // ==================================================

            if (
                !feature ||
                typeof feature !== "string"
            ) {

                throw new ApiError(
                    "Subscription feature is required.",
                    500
                );

            }


            const normalizedFeature =
                feature.trim();


            if (!normalizedFeature) {

                throw new ApiError(
                    "Subscription feature is required.",
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
            //
            // subscriptionMiddleware must run first.
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
            // PLAN FEATURES
            // ==================================================

            const features =
                req.plan.features || {};


            // ==================================================
            // SUPPORT NESTED FEATURES
            //
            // Example:
            //
            // reports
            // exports.pdf
            // exports.excel
            // apiAccess
            // customFields
            // ==================================================

            const keys =
                normalizedFeature.split(".");


            let value =
                features;


            for (
                const key
                of keys
            ) {

                if (
                    value &&
                    typeof value === "object" &&
                    Object.prototype.hasOwnProperty.call(
                        value,
                        key
                    )
                ) {

                    value =
                        value[key];

                }

                else {

                    value =
                        undefined;

                    break;

                }

            }


            // ==================================================
            // FEATURE NOT AVAILABLE
            // ==================================================

            if (value !== true) {

                throw new ApiError(

                    `Your ${req.plan.name} plan does not include '${normalizedFeature}'.`,

                    403,

                    [

                        {

                            type:
                                "FEATURE_NOT_AVAILABLE",

                            feature:
                                normalizedFeature,

                            plan:
                                req.plan.name

                        }

                    ]

                );

            }


            // ==================================================
            // ATTACH FEATURE CONTEXT
            // ==================================================

            req.subscriptionFeature = {

                feature:
                    normalizedFeature,

                enabled:
                    true

            };


            return next();

        }

        catch (error) {

            return next(error);

        }

    };

};


module.exports =
    featureMiddleware;