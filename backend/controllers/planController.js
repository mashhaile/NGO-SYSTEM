const planService =
    require("../services/planService");

const ApiResponse =
    require("../utils/ApiResponse");

const asyncHandler =
    require("../utils/asyncHandler");


// =====================================================
// PUBLIC PLANS
// =====================================================

const getPublicPlans =
    asyncHandler(async (req, res) => {

        const result =
            await planService.getPublicPlans();

        return ApiResponse.success(

            res,

            200,

            "Plans retrieved successfully.",

            result

        );

    });


// =====================================================
// GET ALL PLANS
// SUPER ADMIN
// =====================================================

const getAllPlans =
    asyncHandler(async (req, res) => {

        const result =
            await planService.getAllPlans();

        return ApiResponse.success(

            res,

            200,

            "Plans retrieved successfully.",

            result

        );

    });


// =====================================================
// GET PLAN
// SUPER ADMIN
// =====================================================

const getPlanById =
    asyncHandler(async (req, res) => {

        const result =
            await planService.getPlanById(
                req.params.id
            );

        return ApiResponse.success(

            res,

            200,

            "Plan retrieved successfully.",

            result

        );

    });


// =====================================================
// CREATE PLAN
// SUPER ADMIN
// =====================================================

const createPlan =
    asyncHandler(async (req, res) => {

        const result =
            await planService.createPlan(
                req.body
            );

        return ApiResponse.success(

            res,

            201,

            "Plan created successfully.",

            result

        );

    });


// =====================================================
// UPDATE PLAN
// SUPER ADMIN
// =====================================================

const updatePlan =
    asyncHandler(async (req, res) => {

        const result =
            await planService.updatePlan(

                req.params.id,

                req.body

            );

        return ApiResponse.success(

            res,

            200,

            "Plan updated successfully.",

            result

        );

    });


// =====================================================
// ACTIVATE PLAN
// SUPER ADMIN
// =====================================================

const activatePlan =
    asyncHandler(async (req, res) => {

        const result =
            await planService.activatePlan(
                req.params.id
            );

        return ApiResponse.success(

            res,

            200,

            "Plan activated successfully.",

            result

        );

    });


// =====================================================
// DEACTIVATE PLAN
// SUPER ADMIN
// =====================================================

const deactivatePlan =
    asyncHandler(async (req, res) => {

        const result =
            await planService.deactivatePlan(
                req.params.id
            );

        return ApiResponse.success(

            res,

            200,

            "Plan deactivated successfully.",

            result

        );

    });


// =====================================================
// UPDATE VISIBILITY
// SUPER ADMIN
// =====================================================

const updatePlanVisibility =
    asyncHandler(async (req, res) => {

        // -------------------------------------------------
        // VALIDATE REQUEST VALUE
        // -------------------------------------------------

        if (
            typeof req.body.isPublic !==
            "boolean"
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "isPublic must be a boolean."

            });

        }


        const result =
            await planService.updatePlanVisibility(

                req.params.id,

                req.body.isPublic

            );

        return ApiResponse.success(

            res,

            200,

            "Plan visibility updated successfully.",

            result

        );

    });


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
