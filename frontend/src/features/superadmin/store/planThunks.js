import {
    createAsyncThunk
} from "@reduxjs/toolkit";

import {
    getAllPlansService,
    getActivePlansService,
    createPlanService,
    updatePlanService
} from "../services/planService";


// =====================================================
// GET ALL PLANS
// =====================================================

export const getAllPlansThunk =
    createAsyncThunk(

        "superadminPlans/getAll",

        async (
            _,
            { rejectWithValue }
        ) => {

            try {

                return await getAllPlansService();

            } catch (error) {

                return rejectWithValue(

                    error?.response?.data?.message ||

                    error?.response?.data?.error ||

                    error?.message ||

                    "Failed to retrieve plans."

                );

            }

        }

    );


// =====================================================
// GET ACTIVE PLANS
// =====================================================

export const getActivePlansThunk =
    createAsyncThunk(

        "superadminPlans/getActive",

        async (
            _,
            { rejectWithValue }
        ) => {

            try {

                return await getActivePlansService();

            } catch (error) {

                return rejectWithValue(

                    error?.response?.data?.message ||

                    error?.message ||

                    "Failed to retrieve active plans."

                );

            }

        }

    );


// =====================================================
// CREATE PLAN
// =====================================================

export const createPlanThunk =
    createAsyncThunk(

        "superadminPlans/create",

        async (
            data,
            { rejectWithValue }
        ) => {

            try {

                return await createPlanService(
                    data
                );

            } catch (error) {

                return rejectWithValue(

                    error?.response?.data?.message ||

                    error?.response?.data?.error ||

                    error?.message ||

                    "Failed to create plan."

                );

            }

        }

    );


// =====================================================
// UPDATE PLAN
// =====================================================

export const updatePlanThunk =
    createAsyncThunk(

        "superadminPlans/update",

        async (
            {
                id,
                data
            },
            { rejectWithValue }
        ) => {

            try {

                return await updatePlanService(
                    id,
                    data
                );

            } catch (error) {

                return rejectWithValue(

                    error?.response?.data?.message ||

                    error?.response?.data?.error ||

                    error?.message ||

                    "Failed to update plan."

                );

            }

        }

    );