const Organization =
    require("../models/Organization");

const subscriptionService =
    require("../services/subscriptionService");

const ApiError =
    require("../utils/ApiError");

const {
    ROLES
} =
    require("../config/constants");


// ======================================================
// ORGANIZATION CONTEXT MIDDLEWARE
//
// PURPOSE:
//
// Loads:
// - organization
// - subscription
// - plan snapshot
// - plan features
// - plan limits
//
// IMPORTANT:
//
// This middleware DOES NOT require an active subscription.
//
// It is intended for:
//
// /subscription/current
// /subscription/summary
// /subscription/history
//
// Subscription status is handled separately.
//
// SUPER ADMIN:
// No organization context required.
// ======================================================

const organizationContextMiddleware = async (

    req,
    res,
    next

) => {

    try {

        // ==================================================
        // AUTHENTICATION
        // ==================================================

        if (!req.user) {

            throw new ApiError(

                "Authentication information is missing.",

                401

            );

        }


        // ==================================================
        // SUPER ADMIN
        // ==================================================

        if (

            req.user.role ===
            ROLES.SUPER_ADMIN

        ) {

            return next();

        }


        // ==================================================
        // ORGANIZATION ID
        // ==================================================

        const organizationId =
            req.user.organizationId;


        if (!organizationId) {

            throw new ApiError(

                "Organization information is missing.",

                400

            );

        }


        // ==================================================
        // LOAD ORGANIZATION
        // ==================================================

        const organization =
            await Organization.findOne({

                _id:
                    organizationId,

                isDeleted:
                    false

            });


        if (!organization) {

            throw new ApiError(

                "Organization not found.",

                404

            );

        }


        // ==================================================
        // LOAD SUBSCRIPTION
        //
        // IMPORTANT:
        //
        // Do NOT require active subscription here.
        //
        // This allows the organization to see:
        //
        // active
        // expired
        // cancelled
        // pending
        // etc.
        // ==================================================

        const subscription =
            await subscriptionService
                .getSubscriptionByOrganization(

                    organizationId

                );


        // ==================================================
        // ATTACH ORGANIZATION
        // ==================================================

        req.organization =
            organization;


        // ==================================================
        // ATTACH SUBSCRIPTION
        // ==================================================

        req.subscription =
            subscription || null;


        // ==================================================
        // ATTACH PLAN SNAPSHOT
        // ==================================================

        req.plan =
            subscription
                ? subscription.planSnapshot || null
                : null;


        // ==================================================
        // ATTACH FEATURES
        // ==================================================

        req.planFeatures =
            req.plan
                ? req.plan.features || {}
                : {};


        // ==================================================
        // ATTACH LIMITS
        // ==================================================

        req.planLimits =
            req.plan
                ? req.plan.limits || {}
                : {};


        // ==================================================
        // CONTINUE
        // ==================================================

        return next();

    }

    catch (error) {

        return next(error);

    }

};


module.exports =
    organizationContextMiddleware;