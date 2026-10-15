import {
    createSlice
} from "@reduxjs/toolkit";


// =====================================================
// INITIAL STATE
// =====================================================

const initialState = {

    plans: [],

    selectedPlan: null,

    loading: false,

    error: null,

    success: false,

    message: null

};


// =====================================================
// SLICE
// =====================================================

const planSlice = createSlice({

    name: "superadminPlans",

    initialState,

    reducers: {

        clearPlanError: (state) => {

            state.error = null;

        },


        clearPlanSuccess: (state) => {

            state.success = false;

            state.message = null;

        },


        clearSelectedPlan: (state) => {

            state.selectedPlan = null;

        }

    },


    extraReducers: (builder) => {

        // -------------------------------------------------
        // GET PLANS
        // -------------------------------------------------

        builder

            .addCase(
                "superadminPlans/getAll/pending",
                (state) => {

                    state.loading = true;

                    state.error = null;

                }
            )

            .addCase(
                "superadminPlans/getAll/fulfilled",
                (state, action) => {

                    state.loading = false;

                    state.plans =
                        action.payload?.data || [];

                }
            )

            .addCase(
                "superadminPlans/getAll/rejected",
                (state, action) => {

                    state.loading = false;

                    state.error =
                        action.payload ||
                        action.error?.message ||
                        "Failed to retrieve plans.";

                }
            )


        // -------------------------------------------------
        // GET ACTIVE PLANS
        // -------------------------------------------------

            .addCase(
                "superadminPlans/getActive/pending",
                (state) => {

                    state.loading = true;

                    state.error = null;

                }
            )

            .addCase(
                "superadminPlans/getActive/fulfilled",
                (state, action) => {

                    state.loading = false;

                    state.plans =
                        action.payload?.data || [];

                }
            )

            .addCase(
                "superadminPlans/getActive/rejected",
                (state, action) => {

                    state.loading = false;

                    state.error =
                        action.payload ||
                        action.error?.message ||
                        "Failed to retrieve active plans.";

                }
            )


        // -------------------------------------------------
        // CREATE PLAN
        // -------------------------------------------------

            .addCase(
                "superadminPlans/create/pending",
                (state) => {

                    state.loading = true;

                    state.error = null;

                    state.success = false;

                }
            )

            .addCase(
                "superadminPlans/create/fulfilled",
                (state, action) => {

                    state.loading = false;

                    state.success = true;

                    state.message =
                        action.payload?.message ||
                        "Plan created successfully.";

                    const plan =
                        action.payload?.data;

                    if (plan) {

                        state.plans.push(plan);

                    }

                }
            )

            .addCase(
                "superadminPlans/create/rejected",
                (state, action) => {

                    state.loading = false;

                    state.success = false;

                    state.error =
                        action.payload ||
                        action.error?.message ||
                        "Failed to create plan.";

                }
            )


        // -------------------------------------------------
        // UPDATE PLAN
        // -------------------------------------------------

            .addCase(
                "superadminPlans/update/pending",
                (state) => {

                    state.loading = true;

                    state.error = null;

                    state.success = false;

                }
            )

            .addCase(
                "superadminPlans/update/fulfilled",
                (state, action) => {

                    state.loading = false;

                    state.success = true;

                    state.message =
                        action.payload?.message ||
                        "Plan updated successfully.";

                    const updatedPlan =
                        action.payload?.data;

                    if (updatedPlan) {

                        const index =
                            state.plans.findIndex(
                                plan =>
                                    plan._id ===
                                    updatedPlan._id
                            );

                        if (index !== -1) {

                            state.plans[index] =
                                updatedPlan;

                        }

                        state.selectedPlan =
                            updatedPlan;

                    }

                }
            )

            .addCase(
                "superadminPlans/update/rejected",
                (state, action) => {

                    state.loading = false;

                    state.success = false;

                    state.error =
                        action.payload ||
                        action.error?.message ||
                        "Failed to update plan.";

                }
            );

    }

});


// =====================================================
// ACTIONS
// =====================================================

export const {
    clearPlanError,
    clearPlanSuccess,
    clearSelectedPlan
} = planSlice.actions;


// =====================================================
// SELECTORS
// =====================================================

export const selectPlans =
    state =>
        state.superadminPlans?.plans || [];


export const selectSelectedPlan =
    state =>
        state.superadminPlans?.selectedPlan || null;


export const selectPlanLoading =
    state =>
        state.superadminPlans?.loading || false;


export const selectPlanError =
    state =>
        state.superadminPlans?.error || null;


export const selectPlanSuccess =
    state =>
        state.superadminPlans?.success || false;


export const selectPlanMessage =
    state =>
        state.superadminPlans?.message || null;


// =====================================================
// REDUCER
// =====================================================

export default planSlice.reducer;