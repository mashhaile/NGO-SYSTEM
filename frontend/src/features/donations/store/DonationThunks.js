import {
    createAsyncThunk
} from "@reduxjs/toolkit";

import {
    getDonationsService,
    getDonationByIdService,
    createDonationService,
    updateDonationService,
    deleteDonationService
} from "../services/DonationService";


// =====================================================
// GET ALL DONATIONS
// =====================================================

export const getDonationsThunk =
    createAsyncThunk(

        "donations/getAll",

        async (
            params = {},
            { rejectWithValue }
        ) => {

            try {

                const response =
                    await getDonationsService(
                        params
                    );

                return response;

            } catch (error) {

                return rejectWithValue(

                    error.response?.data?.message ||

                    error.message ||

                    "Failed to fetch donations"

                );

            }

        }

    );


// =====================================================
// GET DONATION BY ID
// =====================================================

export const getDonationByIdThunk =
    createAsyncThunk(

        "donations/getOne",

        async (
            id,
            { rejectWithValue }
        ) => {

            try {

                const response =
                    await getDonationByIdService(
                        id
                    );

                return response;

            } catch (error) {

                return rejectWithValue(

                    error.response?.data?.message ||

                    error.message ||

                    "Failed to fetch donation"

                );

            }

        }

    );


// =====================================================
// CREATE DONATION
// =====================================================

export const createDonationThunk =
    createAsyncThunk(

        "donations/create",

        async (
            data,
            { rejectWithValue }
        ) => {

            try {

                const response =
                    await createDonationService(
                        data
                    );

                return response;

            } catch (error) {

                return rejectWithValue(

                    error.response?.data?.message ||

                    error.message ||

                    "Failed to create donation"

                );

            }

        }

    );


// =====================================================
// UPDATE DONATION
// =====================================================

export const updateDonationThunk =
    createAsyncThunk(

        "donations/update",

        async (
            { id, data },
            { rejectWithValue }
        ) => {

            try {

                const response =
                    await updateDonationService(
                        id,
                        data
                    );

                return response;

            } catch (error) {

                return rejectWithValue(

                    error.response?.data?.message ||

                    error.message ||

                    "Failed to update donation"

                );

            }

        }

    );


// =====================================================
// DELETE DONATION
// =====================================================

export const deleteDonationThunk =
    createAsyncThunk(

        "donations/delete",

        async (
            id,
            { rejectWithValue }
        ) => {

            try {

                await deleteDonationService(
                    id
                );

                return id;

            } catch (error) {

                return rejectWithValue(

                    error.response?.data?.message ||

                    error.message ||

                    "Failed to delete donation"

                );

            }

        }

    );