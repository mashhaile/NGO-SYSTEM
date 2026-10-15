import {
    createSlice
} from "@reduxjs/toolkit";


import {
    getPlatformAnalyticsThunk
} from "./superAdminAnalyticsThunks";


// =====================================================
// INITIAL STATE
// =====================================================

const initialState = {

    analytics: null,

    loading: false,

    error: null,

    success: false,

    message: ""

};


// =====================================================
// SLICE
// =====================================================

const superAdminAnalyticsSlice =
    createSlice({

        name: "superAdminAnalytics",

        initialState,

        reducers: {

            // =========================================
            // CLEAR ERROR
            // =========================================

            clearAnalyticsError: (
                state
            ) => {

                state.error = null;

            },


            // =========================================
            // CLEAR SUCCESS
            // =========================================

            clearAnalyticsSuccess: (
                state
            ) => {

                state.success = false;

                state.message = "";

            },


            // =========================================
            // CLEAR ANALYTICS
            // =========================================

            clearAnalytics: (
                state
            ) => {

                state.analytics = null;

                state.error = null;

                state.success = false;

                state.message = "";

            }

        },


        extraReducers: (
            builder
        ) => {

            builder


                // =====================================
                // GET PLATFORM ANALYTICS - PENDING
                // =====================================

                .addCase(

                    getPlatformAnalyticsThunk.pending,

                    (
                        state
                    ) => {

                        state.loading = true;

                        state.error = null;

                        state.success = false;

                    }

                )


                // =====================================
                // GET PLATFORM ANALYTICS - FULFILLED
                // =====================================

                .addCase(

                    getPlatformAnalyticsThunk.fulfilled,

                    (
                        state,
                        action
                    ) => {

                        state.loading = false;

                        state.error = null;

                        state.success = true;


                        state.analytics =
                            action.payload?.data ||
                            null;


                        state.message =
                            action.payload?.message ||
                            "";

                    }

                )


                // =====================================
                // GET PLATFORM ANALYTICS - REJECTED
                // =====================================

                .addCase(

                    getPlatformAnalyticsThunk.rejected,

                    (
                        state,
                        action
                    ) => {

                        state.loading = false;

                        state.success = false;

                        state.analytics = null;


                        state.error =
                            action.payload ||
                            "Failed to retrieve platform analytics.";

                    }

                );

        }

    });


// =====================================================
// ACTIONS
// =====================================================

export const {

    clearAnalyticsError,

    clearAnalyticsSuccess,

    clearAnalytics

} =
    superAdminAnalyticsSlice.actions;


// =====================================================
// SELECTORS
// =====================================================

export const selectSuperAdminAnalytics = (
    state
) =>
    state.superAdminAnalytics
        ?.analytics;


export const selectSuperAdminAnalyticsLoading = (
    state
) =>
    state.superAdminAnalytics
        ?.loading;


export const selectSuperAdminAnalyticsError = (
    state
) =>
    state.superAdminAnalytics
        ?.error;


export const selectSuperAdminAnalyticsSuccess = (
    state
) =>
    state.superAdminAnalytics
        ?.success;


export const selectSuperAdminAnalyticsMessage = (
    state
) =>
    state.superAdminAnalytics
        ?.message;


// =====================================================
// DEFAULT EXPORT
// =====================================================

export default
    superAdminAnalyticsSlice.reducer;
