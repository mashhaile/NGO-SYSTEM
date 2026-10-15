import {
    createAsyncThunk
} from "@reduxjs/toolkit";


import {
    getBeneficiariesService,
    createBeneficiaryService,
    updateBeneficiaryService,
    deleteBeneficiaryService
} from "../services/beneficiaryService";


// =====================================================
// GET BENEFICIARIES
// =====================================================

export const getBeneficiariesThunk =
    createAsyncThunk(

        "beneficiaries/getAll",

        async (
            params = {},
            thunkAPI
        ) => {

            try {

                const response =
                    await getBeneficiariesService(
                        params
                    );


                return response;

            } catch (error) {

                return thunkAPI.rejectWithValue(

                    error.response?.data?.message ||
                    error.message ||
                    "Failed loading beneficiaries"

                );

            }

        }

    );


// =====================================================
// CREATE BENEFICIARY
// =====================================================

export const createBeneficiaryThunk =
    createAsyncThunk(

        "beneficiaries/create",

        async (
            data,
            thunkAPI
        ) => {

            try {

                const response =
                    await createBeneficiaryService(
                        data
                    );


                return response;

            } catch (error) {

                return thunkAPI.rejectWithValue(

                    error.response?.data?.message ||
                    error.message ||
                    "Failed creating beneficiary"

                );

            }

        }

    );


// =====================================================
// UPDATE BENEFICIARY
// =====================================================

export const updateBeneficiaryThunk =
    createAsyncThunk(

        "beneficiaries/update",

        async (
            {
                id,
                data
            },
            thunkAPI
        ) => {

            try {

                const response =
                    await updateBeneficiaryService(
                        id,
                        data
                    );


                return response;

            } catch (error) {

                return thunkAPI.rejectWithValue(

                    error.response?.data?.message ||
                    error.message ||
                    "Failed updating beneficiary"

                );

            }

        }

    );


// =====================================================
// DELETE BENEFICIARY
// =====================================================

export const deleteBeneficiaryThunk =
    createAsyncThunk(

        "beneficiaries/delete",

        async (
            id,
            thunkAPI
        ) => {

            try {

                const response =
                    await deleteBeneficiaryService(
                        id
                    );


                return {
                    id,
                    response
                };

            } catch (error) {

                return thunkAPI.rejectWithValue(

                    error.response?.data?.message ||
                    error.message ||
                    "Failed deleting beneficiary"

                );

            }

        }

    );