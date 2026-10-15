import {
    createAsyncThunk
} from "@reduxjs/toolkit";


import {
    getPlatformAnalyticsService
} from "../services/superAdminAnalyticsService";


// =====================================================
// GET PLATFORM ANALYTICS
// =====================================================

export const getPlatformAnalyticsThunk =
    createAsyncThunk(

        "superAdminAnalytics/getPlatformAnalytics",

        async (
            _,
            { rejectWithValue }
        ) => {

            try {

                const response =
                    await getPlatformAnalyticsService();


                if (!response?.success) {

                    return rejectWithValue(

                        response?.message ||
                        "Failed to retrieve platform analytics."

                    );

                }


                return response;

            }

            catch (error) {

                return rejectWithValue(

                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to retrieve platform analytics."

                );

            }

        }

    );