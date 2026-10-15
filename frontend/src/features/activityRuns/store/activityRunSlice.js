import { createSlice } from "@reduxjs/toolkit";

import {
    getActivityRunsThunk,
    getActivityRunByIdThunk,
    createActivityRunThunk,
    updateActivityRunThunk,
    deleteActivityRunThunk
} from "./activityRunThunks";

const initialState = {
    data: [],
    pagination: {},
    current: null,
    loading: false,
    error: null
};

const activityRunSlice = createSlice({
    name: "activityRuns",
    initialState,
    reducers: {},
    extraReducers: (builder) => {

        builder

        // ==========================
        // GET ALL
        // ==========================

        .addCase(getActivityRunsThunk.pending, (state) => {
            state.loading = true;
            state.error = null;
        })

        .addCase(getActivityRunsThunk.fulfilled, (state, action) => {

            state.loading = false;

            // Handles BOTH response formats
            if (Array.isArray(action.payload.data)) {

                state.data = action.payload.data;
                state.pagination = action.payload.pagination || {};

            } else {

                state.data = action.payload.data?.data || [];
                state.pagination = action.payload.data?.pagination || {};

            }

        })

        .addCase(getActivityRunsThunk.rejected, (state, action) => {
            state.loading = false;
            state.error = action.payload;
        })



        // ==========================
        // GET ONE
        // ==========================

        .addCase(getActivityRunByIdThunk.fulfilled, (state, action) => {
            state.current = action.payload;
        })



        // ==========================
        // CREATE
        // ==========================

        .addCase(createActivityRunThunk.pending, (state) => {
            state.loading = true;
        })

        .addCase(createActivityRunThunk.fulfilled, (state, action) => {

            state.loading = false;

            if (!Array.isArray(state.data)) {
                state.data = [];
            }

            state.data.unshift(action.payload);

        })

        .addCase(createActivityRunThunk.rejected, (state, action) => {
            state.loading = false;
            state.error = action.payload;
        })



        // ==========================
        // UPDATE
        // ==========================

        .addCase(updateActivityRunThunk.fulfilled, (state, action) => {

            const index = state.data.findIndex(
                item => item._id === action.payload._id
            );

            if (index !== -1) {
                state.data[index] = action.payload;
            }

            state.current = action.payload;

        })



        // ==========================
        // DELETE
        // ==========================

        .addCase(deleteActivityRunThunk.fulfilled, (state, action) => {

            state.data = state.data.filter(
                item => item._id !== action.payload
            );

        });

    }
});

export default activityRunSlice.reducer;