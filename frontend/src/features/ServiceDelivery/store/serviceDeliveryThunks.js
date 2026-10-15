import {
    createAsyncThunk
} from "@reduxjs/toolkit";


import {
    getServiceDeliveriesService,
    createServiceDeliveryService,
    updateServiceDeliveryService,
    deleteServiceDeliveryService,
    getServiceDeliveryByIdService
} from "../services/serviceDeliveryService";


// =====================================================
// ERROR HELPER
// =====================================================

const getErrorMessage = (
    error,
    fallback
) => {

    return (
        error?.response?.data?.message ||
        error?.response?.data?.error ||
        error?.response?.data ||
        error?.message ||
        fallback
    );

};


// =====================================================
// GET ALL SERVICE DELIVERIES
// =====================================================

export const getServiceDeliveries =
    createAsyncThunk(

        "serviceDelivery/getAll",

        async (
            params = {},
            {
                rejectWithValue
            }
        ) => {

            try {

                const response =
                    await getServiceDeliveriesService(
                        params
                    );


                return response.data;

            }

            catch (error) {

                return rejectWithValue(
                    getErrorMessage(
                        error,
                        "Failed to load service deliveries."
                    )
                );

            }

        }

    );


// =====================================================
// GET ONE SERVICE DELIVERY
// =====================================================

export const getServiceDeliveryById =
    createAsyncThunk(

        "serviceDelivery/getById",

        async (
            id,
            {
                rejectWithValue
            }
        ) => {

            if (!id) {

                return rejectWithValue(
                    "Service delivery ID is required."
                );

            }


            try {

                const response =
                    await getServiceDeliveryByIdService(
                        id
                    );


                return response.data;

            }

            catch (error) {

                return rejectWithValue(
                    getErrorMessage(
                        error,
                        "Failed to load service delivery."
                    )
                );

            }

        }

    );


// =====================================================
// CREATE SERVICE DELIVERY
// =====================================================

export const createServiceDelivery =
    createAsyncThunk(

        "serviceDelivery/create",

        async (
            data,
            {
                rejectWithValue
            }
        ) => {

            if (
                !data ||
                typeof data !== "object"
            ) {

                return rejectWithValue(
                    "Service delivery data is required."
                );

            }


            try {

                const response =
                    await createServiceDeliveryService(
                        data
                    );


                return response.data;

            }

            catch (error) {

                return rejectWithValue(
                    getErrorMessage(
                        error,
                        "Failed to create service delivery."
                    )
                );

            }

        }

    );


// =====================================================
// UPDATE SERVICE DELIVERY
// =====================================================

export const updateServiceDelivery =
    createAsyncThunk(

        "serviceDelivery/update",

        async (
            {
                id,
                data
            },
            {
                rejectWithValue
            }
        ) => {

            if (!id) {

                return rejectWithValue(
                    "Service delivery ID is required."
                );

            }


            if (
                !data ||
                typeof data !== "object"
            ) {

                return rejectWithValue(
                    "Service delivery data is required."
                );

            }


            try {

                const response =
                    await updateServiceDeliveryService(
                        id,
                        data
                    );


                return response.data;

            }

            catch (error) {

                return rejectWithValue(
                    getErrorMessage(
                        error,
                        "Failed to update service delivery."
                    )
                );

            }

        }

    );


// =====================================================
// DELETE SERVICE DELIVERY
// =====================================================

export const deleteServiceDelivery =
    createAsyncThunk(

        "serviceDelivery/delete",

        async (
            id,
            {
                rejectWithValue
            }
        ) => {

            if (!id) {

                return rejectWithValue(
                    "Service delivery ID is required."
                );

            }


            try {

                await deleteServiceDeliveryService(
                    id
                );


                return id;

            }

            catch (error) {

                return rejectWithValue(
                    getErrorMessage(
                        error,
                        "Failed to delete service delivery."
                    )
                );

            }

        }

    );