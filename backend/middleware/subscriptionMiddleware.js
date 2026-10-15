const mongoose =
    require("mongoose");

const Organization =
    require("../models/Organization");

const subscriptionService =
    require("../services/subscriptionService");

const ApiError =
    require("../utils/ApiError");

const {
    ROLES,
    ORGANIZATION_STATUS
} =
    require("../config/constants");


// =====================================================
// SUBSCRIPTION MIDDLEWARE
//
// ORGANIZATION CONTEXT
//
// authMiddleware already establishes:
//
// req.organizationId
// req.organization
//
// Super Admin:
// - organization context comes from
//   x-organization-id
//
// Organization User:
// - organization context comes from
//   authenticated user's organization
//
// This middleware is responsible for:
//
// - validating organization context
// - loading organization when necessary
// - checking subscription
// - attaching subscription/plan information
//
// =====================================================

const subscriptionMiddleware = async (

    req,
    res,
    next

) => {

    try {

        // =================================================
        // AUTHENTICATION
        // =================================================

        if (!req.user) {

            throw new ApiError(

                "Authentication information is missing.",

                401

            );

        }


        // =================================================
        // ORGANIZATION CONTEXT
        // =================================================

        let organizationId =
            req.organizationId;


        let organization =
            req.organization;


        // =================================================
        // FALLBACK
        //
        // This protects routes that may use this middleware
        // without the updated auth context.
        //
        // =================================================

        if (!organizationId) {

            if (
                req.user.role ===
                ROLES.SUPER_ADMIN
            ) {

                organizationId =
                    req.headers[
                        "x-organization-id"
                    ] || null;

            }

            else {

                organizationId =
                    req.user.organizationId;

            }

        }


        // =================================================
        // ORGANIZATION ID REQUIRED
        // =================================================

        if (!organizationId) {

            throw new ApiError(

                "Organization information is missing.",

                400

            );

        }


        // =================================================
        // VALIDATE ORGANIZATION ID
        // =================================================

        if (

            !mongoose.Types.ObjectId.isValid(
                organizationId
            )

        ) {

            throw new ApiError(

                "Invalid Organization ID.",

                400

            );

        }


        // =================================================
        // LOAD ORGANIZATION
        //
        // authMiddleware may already have loaded it.
        //
        // Avoid an unnecessary database query when
        // organization context already exists.
        //
        // =================================================

        if (!organization) {

            organization =
                await Organization.findOne({

                    _id:
                        organizationId,

                    isDeleted:
                        false

                });

        }


        // =================================================
        // ORGANIZATION NOT FOUND
        // =================================================

        if (!organization) {

            throw new ApiError(

                "Organization not found.",

                404

            );

        }


        // =================================================
        // SUPER ADMIN
        //
        // Super Admin can inspect/manage organizations
        // regardless of organization lifecycle or
        // subscription status.
        //
        // =================================================

        if (

            req.user.role ===
            ROLES.SUPER_ADMIN

        ) {

            req.organizationId =
                organizationId;


            req.organization =
                organization;


            // ---------------------------------------------
            // Subscription is optional.
            // ---------------------------------------------

            const subscription =
                await subscriptionService
                    .validateSubscription(
                        organizationId
                    );


            req.subscription =
                subscription || null;


            // ---------------------------------------------
            // Plan is optional.
            // ---------------------------------------------

            req.plan =
                subscription?.planSnapshot ||
                null;


            req.planFeatures =
                subscription?.planSnapshot?.features ||
                {};


            req.planLimits =
                subscription?.planSnapshot?.limits ||
                {};


            return next();

        }


        // =================================================
        // ORGANIZATION USER LIFECYCLE CHECK
        // =================================================

        switch (

            organization.status

        ) {

            case ORGANIZATION_STATUS.SUSPENDED:

                throw new ApiError(

                    "Organization is suspended. Please contact the platform administrator.",

                    403

                );


            case ORGANIZATION_STATUS.INACTIVE:

                throw new ApiError(

                    "Organization is inactive. Please contact the platform administrator.",

                    403

                );

        }


        // =================================================
        // VALIDATE SUBSCRIPTION
        // =================================================

        const subscription =
            await subscriptionService
                .validateSubscription(

                    organizationId

                );


        if (!subscription) {

            throw new ApiError(

                "No active subscription found for this organization.",

                403

            );

        }


        // =================================================
        // PLAN SNAPSHOT
        // =================================================

        const plan =
            subscription.planSnapshot;


        if (!plan) {

            throw new ApiError(

                "Subscription plan information is unavailable.",

                500

            );

        }


        // =================================================
        // ATTACH ORGANIZATION CONTEXT
        // =================================================

        req.organizationId =
            organizationId;


        req.organization =
            organization;


        // =================================================
        // ATTACH SUBSCRIPTION
        // =================================================

        req.subscription =
            subscription;


        // =================================================
        // ATTACH PLAN
        // =================================================

        req.plan =
            plan;


        // =================================================
        // ATTACH PLAN FEATURES
        // =================================================

        req.planFeatures =
            plan.features || {};


        // =================================================
        // ATTACH PLAN LIMITS
        // =================================================

        req.planLimits =
            plan.limits || {};


        // =================================================
        // CONTINUE
        // =================================================

        return next();

    }

    catch (error) {

        return next(error);

    }

};


// =====================================================
// EXPORT
// =====================================================

module.exports =
    subscriptionMiddleware;