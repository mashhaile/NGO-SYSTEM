import { createAsyncThunk } from "@reduxjs/toolkit";

import {
    getActivityRunsService,
    getActivityRunByIdService,
    createActivityRunService,
    updateActivityRunService,
    deleteActivityRunService
} from "../services/activityRunService";



// ==========================================
// GET ALL
// ==========================================

export const getActivityRunsThunk = createAsyncThunk(
    "activityRuns/getAll",
    async (params, { rejectWithValue }) => {
        try {
            const response = await getActivityRunsService(params);

            return response.data;
        } catch (error) {
            return rejectWithValue(
                error.response?.data?.message || error.message
            );
        }
    }
);



// ==========================================
// GET ONE
// ==========================================

export const getActivityRunByIdThunk = createAsyncThunk(
    "activityRuns/getOne",
    async (id, { rejectWithValue }) => {
        try {
            const response = await getActivityRunByIdService(id);
            return response.data.data;
        } catch (error) {
            return rejectWithValue(
                error.response?.data?.message || error.message
            );
        }
    }
);



// ==========================================
// CREATE
// ==========================================

export const createActivityRunThunk = createAsyncThunk(
    "activityRuns/create",
    async (data, { rejectWithValue }) => {
        try {
            const response = await createActivityRunService(data);
            return response.data.data;
        } catch (error) {
            return rejectWithValue(
                error.response?.data?.message || error.message
            );
        }
    }
);



// ==========================================
// UPDATE
// ==========================================

export const updateActivityRunThunk = createAsyncThunk(
    "activityRuns/update",
    async ({ id, data }, { rejectWithValue }) => {
        try {
            const response = await updateActivityRunService(id, data);
            return response.data.data;
        } catch (error) {
            return rejectWithValue(
                error.response?.data?.message || error.message
            );
        }
    }
);



// ==========================================
// DELETE
// ==========================================

export const deleteActivityRunThunk = createAsyncThunk(
    "activityRuns/delete",
    async (id, { rejectWithValue }) => {
        try {
            await deleteActivityRunService(id);
            return id;
        } catch (error) {
            return rejectWithValue(
                error.response?.data?.message || error.message
            );
        }
    }
);