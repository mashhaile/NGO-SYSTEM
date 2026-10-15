import {
    getActivePlansApi,
    getAllPlansApi,
    createPlanApi,
    updatePlanApi
} from "../api/planApi";


// =====================================================
// GET ACTIVE PLANS
// =====================================================

export const getActivePlansService =
    async () => {

        return await getActivePlansApi();

    };


// =====================================================
// GET ALL PLANS
// SUPER ADMIN
// =====================================================

export const getAllPlansService =
    async () => {

        return await getAllPlansApi();

    };


// =====================================================
// CREATE PLAN
// SUPER ADMIN
// =====================================================

export const createPlanService =
    async (data) => {

        return await createPlanApi(
            data
        );

    };


// =====================================================
// UPDATE PLAN
// SUPER ADMIN
// =====================================================

export const updatePlanService =
    async (
        id,
        data
    ) => {

        return await updatePlanApi(
            id,
            data
        );

    };