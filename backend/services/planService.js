const Plan = require("../models/plan");

const ApiError = require("../utils/apiError");

const {
    BILLING_CYCLES
} = require("../config/constants");



// =====================================================
// GET PUBLIC PLANS
// =====================================================

const getPublicPlans = async () => {

    const plans =
        await Plan.find({

            isActive:
                true,

            isPublic:
                true

        })
        .sort({

            sortOrder:
                1

        })
        .lean();


    return plans;

};



// =====================================================
// GET ALL PLANS
// SUPER ADMIN
// =====================================================

const getAllPlans = async () => {

    const plans =
        await Plan.find({})
            .sort({

                sortOrder:
                    1,

                createdAt:
                    -1

            })
            .lean();


    return plans;

};



// =====================================================
// GET PLAN BY ID
// =====================================================

const getPlanById = async (
    planId
) => {

    if (!planId) {

        throw new ApiError(
            "Plan ID is required.",
            400
        );

    }


    const plan =
        await Plan.findById(
            planId
        ).lean();


    if (!plan) {

        throw new ApiError(
            "Plan not found.",
            404
        );

    }


    return plan;

};



// =====================================================
// CREATE PLAN
// SUPER ADMIN
// =====================================================

const createPlan = async (
    planData
) => {

    if (!planData) {

        throw new ApiError(
            "Plan information is required.",
            400
        );

    }


    const {

        name,

        code,

        description,

        price,

        currency,

        billingCycle,

        limits,

        features,

        moduleAccess,

        trialDays,

        isActive,

        isPublic,

        sortOrder

    } = planData;



    // =================================================
    // REQUIRED FIELDS
    // =================================================

    if (!name) {

        throw new ApiError(
            "Plan name is required.",
            400
        );

    }


    if (!code) {

        throw new ApiError(
            "Plan code is required.",
            400
        );

    }



    // =================================================
    // NORMALIZE CODE
    // =================================================

    const normalizedCode =
        code
            .trim()
            .toUpperCase();



    // =================================================
    // CHECK DUPLICATE CODE
    // =================================================

    const existingPlan =
        await Plan.findOne({

            code:
                normalizedCode

        });


    if (existingPlan) {

        throw new ApiError(
            "Plan code already exists.",
            400
        );

    }



    // =================================================
    // CHECK DUPLICATE NAME
    // =================================================

    const existingName =
        await Plan.findOne({

            name:
                name.trim()

        });


    if (existingName) {

        throw new ApiError(
            "Plan name already exists.",
            400
        );

    }



    // =================================================
    // BILLING CYCLE
    // =================================================

    if (
        billingCycle &&
        !Object.values(
            BILLING_CYCLES
        ).includes(
            billingCycle
        )
    ) {

        throw new ApiError(
            "Invalid billing cycle.",
            400
        );

    }



    // =================================================
    // CREATE PLAN
    // =================================================

    const plan =
        await Plan.create({

            name:
                name.trim(),

            code:
                normalizedCode,

            description:
                description || "",

            price:
                price ?? 0,

            currency:
                currency || "USD",

            billingCycle:
                billingCycle ||
                BILLING_CYCLES.MONTHLY,

            limits:
                limits || {},

            features:
                features || {},

            moduleAccess:
                moduleAccess || {},

             trialDays:
                billingCycle === BILLING_CYCLES.LIFETIME
                     ? 0
                    : 30,

            isActive:
                isActive ?? true,

            isPublic:
                isPublic ?? true,

            sortOrder:
                sortOrder ?? 0

        });


    return plan;

};



// =====================================================
// UPDATE PLAN
// SUPER ADMIN
// =====================================================

const updatePlan = async (
    planId,
    planData
) => {

    if (!planId) {

        throw new ApiError(
            "Plan ID is required.",
            400
        );

    }


    if (!planData) {

        throw new ApiError(
            "Plan information is required.",
            400
        );

    }



    // =================================================
    // NEVER ALLOW CODE TO CHANGE
    // =================================================

    const allowedFields = [

        "name",

        "description",

        "price",

        "currency",

        "billingCycle",

        "limits",

        "features",

        "moduleAccess",

        "isPublic",

        "sortOrder"

    ];



    const updateData = {};



    for (
        const field
        of allowedFields
    ) {

        if (
            Object.prototype.hasOwnProperty.call(
                planData,
                field
            )
        ) {

            updateData[field] =
                planData[field];

        }

    }



    // =================================================
    // NOTHING TO UPDATE
    // =================================================

    if (
        Object.keys(
            updateData
        ).length === 0
    ) {

        throw new ApiError(
            "No plan information provided for update.",
            400
        );

    }



    // =================================================
    // NORMALIZE NAME
    // =================================================

    if (
        Object.prototype.hasOwnProperty.call(
            updateData,
            "name"
        )
    ) {

        if (
            typeof updateData.name !==
            "string" ||
            !updateData.name.trim()
        ) {

            throw new ApiError(
                "Plan name must be a valid string.",
                400
            );

        }


        updateData.name =
            updateData.name.trim();

    }



    // =================================================
    // NORMALIZE CURRENCY
    // =================================================

    if (
        Object.prototype.hasOwnProperty.call(
            updateData,
            "currency"
        )
    ) {

        if (
            typeof updateData.currency !==
            "string"
        ) {

            throw new ApiError(
                "Currency must be a valid string.",
                400
            );

        }


        updateData.currency =
            updateData.currency
                .trim()
                .toUpperCase();

    }



    // =================================================
    // VALIDATE BILLING CYCLE
    // =================================================

    if (
        updateData.billingCycle &&
        !Object.values(
            BILLING_CYCLES
        ).includes(
            updateData.billingCycle
        )
    ) {

        throw new ApiError(
            "Invalid billing cycle.",
            400
        );

    }

    // =================================================
// ENFORCE TRIAL POLICY
// =================================================

if (
    Object.prototype.hasOwnProperty.call(
        updateData,
        "billingCycle"
    )
) {

    updateData.trialDays =
        updateData.billingCycle ===
        BILLING_CYCLES.LIFETIME
            ? 0
            : 30;

}

    // =================================================
    // VALIDATE PRICE
    // =================================================

    if (
        Object.prototype.hasOwnProperty.call(
            updateData,
            "price"
        )
    ) {

        if (
            typeof updateData.price !==
            "number" ||
            updateData.price < 0
        ) {

            throw new ApiError(
                "Price must be a number greater than or equal to 0.",
                400
            );

        }

    }



    // =================================================
    // VALIDATE TRIAL DAYS
    // =================================================

    if (
        Object.prototype.hasOwnProperty.call(
            updateData,
            "trialDays"
        )
    ) {

        if (
            typeof updateData.trialDays !==
            "number" ||
            updateData.trialDays < 0 ||
            updateData.trialDays > 365
        ) {

            throw new ApiError(
                "Trial days must be between 0 and 365.",
                400
            );

        }

    }



    // =================================================
    // CHECK DUPLICATE NAME
    // =================================================

    if (updateData.name) {

        const existingPlan =
            await Plan.findOne({

                name:
                    updateData.name,

                _id: {
                    $ne:
                        planId
                }

            });


        if (existingPlan) {

            throw new ApiError(
                "Plan name already exists.",
                400
            );

        }

    }



    // =================================================
    // UPDATE PLAN
    // =================================================

    const plan =
        await Plan.findByIdAndUpdate(

            planId,

            {

                $set:
                    updateData

            },

            {

                new:
                    true,

                runValidators:
                    true

            }

        ).lean();


    if (!plan) {

        throw new ApiError(
            "Plan not found.",
            404
        );

    }


    return plan;

};



// =====================================================
// ACTIVATE PLAN
// =====================================================

const activatePlan = async (
    planId
) => {

    if (!planId) {

        throw new ApiError(
            "Plan ID is required.",
            400
        );

    }


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

        ).lean();


    if (!plan) {

        throw new ApiError(
            "Plan not found.",
            404
        );

    }


    return plan;

};



// =====================================================
// DEACTIVATE PLAN
// =====================================================

const deactivatePlan = async (
    planId
) => {

    if (!planId) {

        throw new ApiError(
            "Plan ID is required.",
            400
        );

    }


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

        ).lean();


    if (!plan) {

        throw new ApiError(
            "Plan not found.",
            404
        );

    }


    return plan;

};



// =====================================================
// UPDATE PLAN VISIBILITY
// =====================================================

const updatePlanVisibility = async (
    planId,
    isPublic
) => {

    if (!planId) {

        throw new ApiError(
            "Plan ID is required.",
            400
        );

    }


    if (
        typeof isPublic !==
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

                    isPublic

                }

            },

            {

                new:
                    true,

                runValidators:
                    true

            }

        ).lean();


    if (!plan) {

        throw new ApiError(
            "Plan not found.",
            404
        );

    }


    return plan;

};



// =====================================================
// EXPORTS
// =====================================================

module.exports = {

    getPublicPlans,

    getAllPlans,

    getPlanById,

    createPlan,

    updatePlan,

    activatePlan,

    deactivatePlan,

    updatePlanVisibility

};