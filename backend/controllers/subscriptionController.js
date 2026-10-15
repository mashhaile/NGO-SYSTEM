const mongoose =
    require("mongoose");


const Plan =
    require("../models/plan");


const subscriptionService =
    require("../services/subscriptionService");


const asyncHandler =
    require("../utils/asyncHandler");


const ApiResponse =
    require("../utils/apiresponse");


const ApiError =
    require("../utils/apiError");


const {
    BILLING_CYCLES
} =
    require("../config/constants");


// ======================================================
// HELPERS
// ======================================================

const validateObjectId = (
    value,
    fieldName
) => {

    if (!value) {

        throw new ApiError(
            `${fieldName} is required.`,
            400
        );

    }


    if (
        !mongoose.Types.ObjectId.isValid(
            value
        )
    ) {

        throw new ApiError(
            `Invalid ${fieldName}.`,
            400
        );

    }

};


// ======================================================
// GET AUTHENTICATED USER ID
// ======================================================

const getAuthenticatedUserId = (
    req
) => {

    const userId =
        req.user?.userId ||
        req.user?._id ||
        req.user?.id;


    if (!userId) {

        throw new ApiError(
            "Authenticated user ID is required.",
            401
        );

    }


    validateObjectId(
        userId,
        "Authenticated user ID"
    );


    return userId;

};


// ======================================================
// GET AUTHENTICATED ORGANIZATION ID
// ======================================================

const getAuthenticatedOrganizationId = (
    req
) => {

    const organizationId =
        req.user?.organizationId ||
        req.user?.organization;


    validateObjectId(
        organizationId,
        "Organization ID"
    );


    return organizationId;

};


// ======================================================
// NORMALIZE PLAN DATA
// ======================================================

const normalizePlanData = (
    data
) => {

    const normalized = {
        ...data
    };


    if (
        normalized.name !== undefined
    ) {

        normalized.name =
            String(
                normalized.name
            ).trim();

    }


    if (
        normalized.description !== undefined
    ) {

        normalized.description =
            String(
                normalized.description
            ).trim();

    }


    if (
        normalized.code !== undefined
    ) {

        normalized.code =
            String(
                normalized.code
            )
                .trim()
                .toUpperCase();

    }


    if (
        normalized.currency !== undefined
    ) {

        normalized.currency =
            String(
                normalized.currency
            )
                .trim()
                .toUpperCase();

    }


    if (
        normalized.price !== undefined
    ) {

        normalized.price =
            Number(
                normalized.price
            );

    }


    if (
        normalized.trialDays !== undefined
    ) {

        normalized.trialDays =
            Number(
                normalized.trialDays
            );

    }


    if (
        normalized.sortOrder !== undefined
    ) {

        normalized.sortOrder =
            Number(
                normalized.sortOrder
            );

    }


    return normalized;

};


// ======================================================
// VALIDATE PLAN INPUT
// ======================================================

const validatePlanInput = (
    data,
    isCreate = false
) => {

    // --------------------------------------------------
    // NAME
    // --------------------------------------------------

    if (
        isCreate &&
        !data.name
    ) {

        throw new ApiError(
            "Plan name is required.",
            400
        );

    }


    if (
        data.name !== undefined &&
        !String(data.name).trim()
    ) {

        throw new ApiError(
            "Plan name cannot be empty.",
            400
        );

    }


    // --------------------------------------------------
    // CODE
    // --------------------------------------------------

    if (
        isCreate &&
        !data.code
    ) {

        throw new ApiError(
            "Plan code is required.",
            400
        );

    }


    if (
        data.code !== undefined &&
        !/^[A-Z0-9_-]+$/.test(
            String(data.code)
        )
    ) {

        throw new ApiError(
            "Plan code may contain only letters, numbers, underscores, and hyphens.",
            400
        );

    }


    // --------------------------------------------------
    // PRICE
    // --------------------------------------------------

    if (
        data.price !== undefined
    ) {

        if (
            !Number.isFinite(
                Number(data.price)
            ) ||
            Number(data.price) < 0
        ) {

            throw new ApiError(
                "Plan price must be a valid non-negative number.",
                400
            );

        }

    }


    // --------------------------------------------------
    // CURRENCY
    // --------------------------------------------------

    if (
        data.currency !== undefined
    ) {

        if (
            typeof data.currency !== "string" ||
            !/^[A-Z]{3}$/.test(
                data.currency
            )
        ) {

            throw new ApiError(
                "Currency must be a valid 3-letter currency code.",
                400
            );

        }

    }


    // --------------------------------------------------
    // BILLING CYCLE
    // --------------------------------------------------

    if (
        data.billingCycle !== undefined &&
        !Object.values(
            BILLING_CYCLES
        ).includes(
            data.billingCycle
        )
    ) {

        throw new ApiError(
            "Invalid billing cycle.",
            400
        );

    }


    // --------------------------------------------------
    // TRIAL DAYS
    // --------------------------------------------------

    if (
        data.trialDays !== undefined
    ) {

        if (
            !Number.isFinite(
                Number(data.trialDays)
            ) ||
            Number(data.trialDays) < 0 ||
            Number(data.trialDays) > 365
        ) {

            throw new ApiError(
                "Trial days must be between 0 and 365.",
                400
            );

        }

    }


    // --------------------------------------------------
    // SORT ORDER
    // --------------------------------------------------

    if (
        data.sortOrder !== undefined
    ) {

        if (
            !Number.isFinite(
                Number(data.sortOrder)
            ) ||
            Number(data.sortOrder) < 0
        ) {

            throw new ApiError(
                "Sort order must be a valid non-negative number.",
                400
            );

        }

    }


    // --------------------------------------------------
    // LIMITS
    // --------------------------------------------------

    if (
        data.limits !== undefined
    ) {

        if (
            typeof data.limits !== "object" ||
            data.limits === null ||
            Array.isArray(data.limits)
        ) {

            throw new ApiError(
                "Plan limits must be a valid object.",
                400
            );

        }


        Object.entries(
            data.limits
        ).forEach(

            ([key, value]) => {

                const numberValue =
                    Number(value);


                if (
                    !Number.isFinite(
                        numberValue
                    ) ||
                    numberValue < -1
                ) {

                    throw new ApiError(
                        `Invalid plan limit for ${key}.`,
                        400
                    );

                }

            }

        );

    }


    // --------------------------------------------------
    // FEATURES
    // --------------------------------------------------

    if (
        data.features !== undefined
    ) {

        if (
            typeof data.features !== "object" ||
            data.features === null ||
            Array.isArray(data.features)
        ) {

            throw new ApiError(
                "Plan features must be a valid object.",
                400
            );

        }

    }


    // --------------------------------------------------
    // BOOLEAN FIELDS
    // --------------------------------------------------

    [
        "isActive",
        "isPublic"
    ]
    .forEach(

        field => {

            if (
                data[field] !== undefined &&
                typeof data[field] !== "boolean"
            ) {

                throw new ApiError(
                    `${field} must be a boolean.`,
                    400
                );

            }

        }

    );

};


// ======================================================
// CHECK PLAN DUPLICATES
// ======================================================

const checkPlanDuplicates = async (
    data,
    excludeId = null
) => {

    const conditions = [];


    if (
        data.name !== undefined
    ) {

        conditions.push({

            name:
                data.name

        });

    }


    if (
        data.code !== undefined
    ) {

        conditions.push({

            code:
                data.code

        });

    }


    if (
        conditions.length === 0
    ) {

        return;

    }


    const query = {

        $or:
            conditions

    };


    if (
        excludeId
    ) {

        query._id = {

            $ne:
                excludeId

        };

    }


    const existingPlan =
        await Plan.findOne(
            query
        );


    if (
        existingPlan
    ) {

        if (
            data.name &&
            existingPlan.name === data.name
        ) {

            throw new ApiError(
                "A plan with this name already exists.",
                409
            );

        }


        if (
            data.code &&
            existingPlan.code === data.code
        ) {

            throw new ApiError(
                "A plan with this code already exists.",
                409
            );

        }


        throw new ApiError(
            "A plan with this name or code already exists.",
            409
        );

    }

};


// ======================================================
// PUBLIC PLANS
// ======================================================

const getPublicPlans =
    asyncHandler(
        async (req, res) => {

            const plans =
                await Plan.find({

                    isActive:
                        true,

                    isPublic:
                        true

                })
                .sort({

                    sortOrder:
                        1,

                    price:
                        1,

                    createdAt:
                        -1

                });


            return ApiResponse.success(

                res,

                200,

                "Plans retrieved successfully.",

                plans

            );

        }
    );


// ======================================================
// ALIAS
// ======================================================

const getPlans =
    getPublicPlans;


// ======================================================
// GET ALL PLANS
// SUPER ADMIN
// ======================================================

const getAllPlans =
    asyncHandler(
        async (req, res) => {

            const plans =
                await Plan.find()
                .sort({

                    sortOrder:
                        1,

                    price:
                        1,

                    createdAt:
                        -1

                });


            return ApiResponse.success(

                res,

                200,

                "All plans retrieved successfully.",

                plans

            );

        }
    );


// ======================================================
// GET PLAN BY ID
// ======================================================

const getPlanById =
    asyncHandler(
        async (req, res) => {

            const planId =
                req.params.id;


            validateObjectId(
                planId,
                "Plan ID"
            );


            const plan =
                await Plan.findById(
                    planId
                );


            if (!plan) {

                throw new ApiError(
                    "Plan not found.",
                    404
                );

            }


            return ApiResponse.success(

                res,

                200,

                "Plan retrieved successfully.",

                plan

            );

        }
    );


// ======================================================
// CREATE PLAN
// SUPER ADMIN
// ======================================================

const createPlan =
    asyncHandler(
        async (req, res) => {

            const planData =
                normalizePlanData({

                    name:
                        req.body.name,

                    description:
                        req.body.description,

                    code:
                        req.body.code,

                    price:
                        req.body.price,

                    currency:
                        req.body.currency,

                    billingCycle:
                        req.body.billingCycle,

                    limits:
                        req.body.limits,

                    features:
                        req.body.features,

                    trialDays:
                        req.body.trialDays,

                    isActive:
                        req.body.isActive,

                    isPublic:
                        req.body.isPublic,

                    sortOrder:
                        req.body.sortOrder

                });


            validatePlanInput(
                planData,
                true
            );


            await checkPlanDuplicates(
                planData
            );


            try {

                const plan =
                    await Plan.create(
                        planData
                    );


                return ApiResponse.success(

                    res,

                    201,

                    "Plan created successfully.",

                    plan

                );

            } catch (error) {

                if (
                    error?.code === 11000
                ) {

                    throw new ApiError(
                        "A plan with this name or code already exists.",
                        409
                    );

                }


                throw error;

            }

        }
    );


// ======================================================
// UPDATE PLAN
// SUPER ADMIN
// ======================================================

const updatePlan =
    asyncHandler(
        async (req, res) => {

            const planId =
                req.params.id;


            validateObjectId(
                planId,
                "Plan ID"
            );


            const allowedFields = [

                "name",

                "description",

                "price",

                "currency",

                "billingCycle",

                "limits",

                "features",

                "trialDays",

                "isActive",

                "isPublic",

                "sortOrder"

            ];


            const updateData = {};


            allowedFields.forEach(

                field => {

                    if (
                        req.body[field] !== undefined
                    ) {

                        updateData[field] =
                            req.body[field];

                    }

                }

            );


            if (
                Object.keys(
                    updateData
                ).length === 0
            ) {

                throw new ApiError(
                    "No valid plan fields were provided for update.",
                    400
                );

            }


            const normalizedData =
                normalizePlanData(
                    updateData
                );


            validatePlanInput(
                normalizedData
            );


            await checkPlanDuplicates(

                normalizedData,

                planId

            );


            try {

                const plan =
                    await Plan.findByIdAndUpdate(

                        planId,

                        {

                            $set:
                                normalizedData

                        },

                        {

                            new:
                                true,

                            runValidators:
                                true

                        }

                    );


                if (!plan) {

                    throw new ApiError(
                        "Plan not found.",
                        404
                    );

                }


                return ApiResponse.success(

                    res,

                    200,

                    "Plan updated successfully.",

                    plan

                );

            } catch (error) {

                if (
                    error?.code === 11000
                ) {

                    throw new ApiError(
                        "A plan with this name or code already exists.",
                        409
                    );

                }


                throw error;

            }

        }
    );


// ======================================================
// ACTIVATE PLAN
// ======================================================

const activatePlan =
    asyncHandler(
        async (req, res) => {

            const planId =
                req.params.id;


            validateObjectId(
                planId,
                "Plan ID"
            );


            const plan =
                await Plan.findByIdAndUpdate(

                    planId,

                    {

                        $set: {

                            isActive:
                                true

                        }

                    },

                    {

                        new:
                            true,

                        runValidators:
                            true

                    }

                );


            if (!plan) {

                throw new ApiError(
                    "Plan not found.",
                    404
                );

            }


            return ApiResponse.success(

                res,

                200,

                "Plan activated successfully.",

                plan

            );

        }
    );


// ======================================================
// DEACTIVATE PLAN
// ======================================================

const deactivatePlan =
    asyncHandler(
        async (req, res) => {

            const planId =
                req.params.id;


            validateObjectId(
                planId,
                "Plan ID"
            );


            const plan =
                await Plan.findByIdAndUpdate(

                    planId,

                    {

                        $set: {

                            isActive:
                                false

                        }

                    },

                    {

                        new:
                            true,

                        runValidators:
                            true

                    }

                );


            if (!plan) {

                throw new ApiError(
                    "Plan not found.",
                    404
                );

            }


            return ApiResponse.success(

                res,

                200,

                "Plan deactivated successfully.",

                plan

            );

        }
    );


// ======================================================
// UPDATE PLAN VISIBILITY
// ======================================================

const updatePlanVisibility =
    asyncHandler(
        async (req, res) => {

            const planId =
                req.params.id;


            validateObjectId(
                planId,
                "Plan ID"
            );


            if (
                typeof req.body.isPublic !==
                "boolean"
            ) {

                throw new ApiError(
                    "isPublic must be a boolean.",
                    400
                );

            }


            const plan =
                await Plan.findByIdAndUpdate(

                    planId,

                    {

                        $set: {

                            isPublic:
                                req.body.isPublic

                        }

                    },

                    {

                        new:
                            true,

                        runValidators:
                            true

                    }

                );


            if (!plan) {

                throw new ApiError(
                    "Plan not found.",
                    404
                );

            }


            return ApiResponse.success(

                res,

                200,

                "Plan visibility updated successfully.",

                plan

            );

        }
    );


// ======================================================
// ASSIGN SUBSCRIPTION
// SUPER ADMIN
// ======================================================

const assignSubscription =
    asyncHandler(
        async (req, res) => {

            const {

                organizationId,

                planId,

                startDate

            } = req.body;


            validateObjectId(
                organizationId,
                "Organization ID"
            );


            validateObjectId(
                planId,
                "Plan ID"
            );


            const createdBy =
                getAuthenticatedUserId(
                    req
                );


            const subscription =
                await subscriptionService
                    .createSubscription({

                        organizationId,

                        planId,

                        createdBy,

                        startDate

                    });


            return ApiResponse.success(

                res,

                201,

                "Subscription assigned successfully.",

                subscription

            );

        }
    );


// ======================================================
// GET ORGANIZATION SUBSCRIPTION
// SUPER ADMIN
// ======================================================

const getOrganizationSubscription =
    asyncHandler(
        async (req, res) => {

            const organizationId =
                req.params.organizationId;


            validateObjectId(
                organizationId,
                "Organization ID"
            );


            const subscription =
                await subscriptionService
                    .getActiveSubscription(
                        organizationId
                    );


            if (!subscription) {

                return ApiResponse.success(

                    res,

                    200,

                    "No active subscription found.",

                    null

                );

            }


            return ApiResponse.success(

                res,

                200,

                "Organization subscription retrieved successfully.",

                subscription

            );

        }
    );


// ======================================================
// CHANGE ORGANIZATION PLAN
// SUPER ADMIN
// ======================================================

const changePlan =
    asyncHandler(
        async (req, res) => {

            const organizationId =
                req.params.organizationId;


            const {
                planId
            } = req.body;


            validateObjectId(
                organizationId,
                "Organization ID"
            );


            validateObjectId(
                planId,
                "Plan ID"
            );


            const createdBy =
                getAuthenticatedUserId(
                    req
                );


            const subscription =
                await subscriptionService
                    .changePlan({

                        organizationId,

                        planId,

                        createdBy

                    });


            return ApiResponse.success(

                res,

                200,

                "Subscription plan changed successfully.",

                subscription

            );

        }
    );


// ======================================================
// RENEW SUBSCRIPTION
// SUPER ADMIN
// ======================================================

const renewSubscription =
    asyncHandler(
        async (req, res) => {

            const organizationId =
                req.params.organizationId;


            validateObjectId(
                organizationId,
                "Organization ID"
            );


            const subscription =
                await subscriptionService
                    .renewSubscription(
                        organizationId
                    );


            return ApiResponse.success(

                res,

                200,

                "Subscription renewed successfully.",

                subscription

            );

        }
    );


// ======================================================
// CANCEL SUBSCRIPTION
// SUPER ADMIN
// ======================================================

const cancelSubscription =
    asyncHandler(
        async (req, res) => {

            const organizationId =
                req.params.organizationId;


            const {
                reason
            } = req.body;


            validateObjectId(
                organizationId,
                "Organization ID"
            );


            const subscription =
                await subscriptionService
                    .cancelSubscription(

                        organizationId,

                        reason

                    );


            return ApiResponse.success(

                res,

                200,

                "Subscription cancelled successfully.",

                subscription

            );

        }
    );


// ======================================================
// VALIDATE CURRENT SUBSCRIPTION
// ORGANIZATION
// ======================================================

const validateSubscription =
    asyncHandler(
        async (req, res) => {

            const organizationId =
                getAuthenticatedOrganizationId(
                    req
                );


            const subscription =
                await subscriptionService
                    .validateSubscription(
                        organizationId
                    );


            return ApiResponse.success(

                res,

                200,

                "Subscription is valid.",

                {

                    valid:
                        true,

                    subscription

                }

            );

        }
    );


// ======================================================
// GET CURRENT SUBSCRIPTION
// ORGANIZATION
// ======================================================

const getCurrentSubscription =
    asyncHandler(
        async (req, res) => {

            const organizationId =
                getAuthenticatedOrganizationId(
                    req
                );


            const subscription =
                await subscriptionService
                    .validateSubscription(
                        organizationId
                    );


            return ApiResponse.success(

                res,

                200,

                "Active subscription retrieved successfully.",

                subscription

            );

        }
    );


// ======================================================
// SUBSCRIPTION SUMMARY
// ORGANIZATION
// ======================================================

const getSubscriptionSummaryController =
    asyncHandler(
        async (req, res) => {

            const organizationId =
                getAuthenticatedOrganizationId(
                    req
                );


            const summary =
                await subscriptionService
                    .getSubscriptionSummary(
                        organizationId
                    );


            return ApiResponse.success(

                res,

                200,

                "Subscription summary retrieved successfully.",

                summary

            );

        }
    );


// ======================================================
// SUBSCRIPTION FEATURES
// ORGANIZATION
// ======================================================

const getFeatures =
    asyncHandler(
        async (req, res) => {

            const organizationId =
                getAuthenticatedOrganizationId(
                    req
                );


            const features =
                await subscriptionService
                    .getFeatures(
                        organizationId
                    );


            return ApiResponse.success(

                res,

                200,

                "Subscription features retrieved successfully.",

                features

            );

        }
    );


// ======================================================
// SUBSCRIPTION LIMITS
// ORGANIZATION
// ======================================================

const getLimits =
    asyncHandler(
        async (req, res) => {

            const organizationId =
                getAuthenticatedOrganizationId(
                    req
                );


            const limits =
                await subscriptionService
                    .getLimits(
                        organizationId
                    );


            return ApiResponse.success(

                res,

                200,

                "Subscription limits retrieved successfully.",

                limits

            );

        }
    );


// ======================================================
// CURRENT ORGANIZATION USAGE
// ======================================================

const getUsage =
    asyncHandler(
        async (req, res) => {

            const organizationId =
                getAuthenticatedOrganizationId(
                    req
                );


            const usage =
                await subscriptionService
                    .calculateUsage(
                        organizationId
                    );


            return ApiResponse.success(

                res,

                200,

                "Subscription usage retrieved successfully.",

                usage

            );

        }
    );


// ======================================================
// ORGANIZATION USAGE
// SUPER ADMIN
// ======================================================

const getOrganizationSubscriptionUsage =
    asyncHandler(
        async (req, res) => {

            const organizationId =
                req.params.organizationId;


            validateObjectId(
                organizationId,
                "Organization ID"
            );


            const usage =
                await subscriptionService
                    .calculateUsage(
                        organizationId
                    );


            return ApiResponse.success(

                res,

                200,

                "Subscription usage retrieved successfully.",

                usage

            );

        }
    );


// ======================================================
// EXPORTS
// ======================================================

module.exports = {

    // --------------------------------------------------
    // Plans
    // --------------------------------------------------

    createPlan,

    getPlans,

    getPublicPlans,

    getAllPlans,

    getPlanById,

    updatePlan,

    activatePlan,

    deactivatePlan,

    updatePlanVisibility,


    // --------------------------------------------------
    // Super Admin subscription management
    // --------------------------------------------------

    assignSubscription,

    getOrganizationSubscription,

    getOrganizationSubscriptionUsage,

    changePlan,

    renewSubscription,

    cancelSubscription,


    // --------------------------------------------------
    // Organization subscription information
    // --------------------------------------------------

    validateSubscription,

    getCurrentSubscription,

    getSubscriptionSummaryController,

    getFeatures,

    getLimits,

    getUsage

};