import {
    createAsyncThunk
} from "@reduxjs/toolkit";


import {

    getEnterprisesService,

    getEnterpriseByIdService,

    createEnterpriseService,

    updateEnterpriseService,

    deleteEnterpriseService

} from "../services/enterpriseService";


// =========================================================
// GET ENTERPRISES
// =========================================================

export const getEnterprisesThunk = createAsyncThunk(

    "enterprises/getAll",

    async (
        params = {},
        thunkAPI
    ) => {

        try {

            const response =
                await getEnterprisesService(
                    params
                );


            return response.data;

        }

        catch (error) {

            return thunkAPI.rejectWithValue(

                error.response?.data?.message ||

                error.message ||

                "Failed loading enterprises"

            );

        }

    }

);


// =========================================================
// GET ENTERPRISE BY ID
// =========================================================

export const getEnterpriseByIdThunk = createAsyncThunk(

    "enterprises/getById",

    async (
        id,
        thunkAPI
    ) => {

        try {

            const response =
                await getEnterpriseByIdService(
                    id
                );


            return response.data;

        }

        catch (error) {

            return thunkAPI.rejectWithValue(

                error.response?.data?.message ||

                error.message ||

                "Failed loading enterprise"

            );

        }

    }

);


// =========================================================
// CREATE ENTERPRISE
// =========================================================

export const createEnterpriseThunk = createAsyncThunk(

    "enterprises/create",

    async (
        data,
        thunkAPI
    ) => {

        try {

            const response =
                await createEnterpriseService(
                    data
                );


            return response.data;

        }

        catch (error) {

            return thunkAPI.rejectWithValue(

                error.response?.data?.message ||

                error.message ||

                "Failed creating enterprise"

            );

        }

    }

);


// =========================================================
// UPDATE ENTERPRISE
// =========================================================

export const updateEnterpriseThunk = createAsyncThunk(

    "enterprises/update",

    async (
        {
            id,
            data
        },
        thunkAPI
    ) => {

        try {

            if (!id) {

                return thunkAPI.rejectWithValue(
                    "Enterprise ID is required"
                );

            }


            const response =
                await updateEnterpriseService(

                    id,

                    data

                );


            return response.data;

        }

        catch (error) {

            return thunkAPI.rejectWithValue(

                error.response?.data?.message ||

                error.message ||

                "Failed updating enterprise"

            );

        }

    }

);


// =========================================================
// DELETE ENTERPRISE
// =========================================================

export const deleteEnterpriseThunk = createAsyncThunk(

    "enterprises/delete",

    async (
        id,
        thunkAPI
    ) => {

        try {

            if (!id) {

                return thunkAPI.rejectWithValue(
                    "Enterprise ID is required"
                );

            }


            const response =
                await deleteEnterpriseService(
                    id
                );


            return {

                id,

                response:
                    response.data

            };

        }

        catch (error) {

            return thunkAPI.rejectWithValue(

                error.response?.data?.message ||

                error.message ||

                "Failed deleting enterprise"

            );

        }

    }

);