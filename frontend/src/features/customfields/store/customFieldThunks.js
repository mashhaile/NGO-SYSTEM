import {
    createAsyncThunk
} from "@reduxjs/toolkit";


import {
    getCustomFieldsService
} from "../services/customFieldService";


// =====================================================
// GET CUSTOM FIELDS BY MODULE
// =====================================================

export const getCustomFieldsThunk =
    createAsyncThunk(

        "customFields/getAll",

        async (
            module,
            thunkAPI
        ) => {

            try {

                if (!module) {

                    throw new Error(
                        "Custom field module is required"
                    );

                }


                return await getCustomFieldsService(
                    module
                );

            }

            catch (error) {

                return thunkAPI.rejectWithValue(

                    error.response?.data?.message ||

                    error.message ||

                    "Failed to load custom fields"

                );

            }

        }

    );