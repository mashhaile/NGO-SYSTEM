import { createAsyncThunk } from "@reduxjs/toolkit";

import {
    loginService,
    getCurrentUserService,
    logoutService
} from "../services/authService";


export const loginThunk = createAsyncThunk(
    "auth/login",

    async (credentials, thunkAPI) => {

        try {

            const response =
                await loginService(credentials);

            return response.data;

        } catch (error) {

            return thunkAPI.rejectWithValue(
                error.response?.data?.message ||
                error.message
            );

        }

    }
);


export const loadCurrentUserThunk = createAsyncThunk(
    "auth/loadCurrentUser",

    async (_, thunkAPI) => {

        try {

            const response =
                await getCurrentUserService();

            return response.data;

        } catch (error) {

            return thunkAPI.rejectWithValue(
                error.response?.data?.message ||
                error.message
            );

        }

    }
);


export const logoutThunk = createAsyncThunk(
    "auth/logout",

    async () => {

        logoutService();

        return true;

    }
);