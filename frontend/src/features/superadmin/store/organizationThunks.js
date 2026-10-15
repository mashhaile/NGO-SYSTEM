import {
    createAsyncThunk
} from "@reduxjs/toolkit";


import {
    createOrganizationApi,
    getOrganizationsApi,
    getOrganizationByIdApi,
    updateOrganizationApi,
    activateOrganizationApi,
    suspendOrganizationApi,
    deactivateOrganizationApi,
    restoreOrganizationApi,
    deleteOrganizationApi
} from "../api/organizationApi";


// =====================================================
// CREATE ORGANIZATION
// SUPER ADMIN
// =====================================================

export const createOrganizationThunk =
    createAsyncThunk(

        "superadmin/organizations/create",

        async (
            data,
            { rejectWithValue }
        ) => {

            try {

                const response =
                    await createOrganizationApi(
                        data
                    );


                if (!response?.success) {

                    return rejectWithValue(

                        response?.message ||
                        "Failed to create organization."

                    );

                }


                return response;

            }
            catch (error) {

                return rejectWithValue(

                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to create organization."

                );

            }

        }

    );


// =====================================================
// GET ORGANIZATIONS
// SUPER ADMIN
// =====================================================

export const getOrganizationsThunk =
    createAsyncThunk(

        "superadmin/organizations/getAll",

        async (
            params = {},
            { rejectWithValue }
        ) => {

            try {

                const response =
                    await getOrganizationsApi(
                        params
                    );


                if (!response?.success) {

                    return rejectWithValue(

                        response?.message ||
                        "Failed to retrieve organizations."

                    );

                }


                return response;

            }
            catch (error) {

                return rejectWithValue(

                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to retrieve organizations."

                );

            }

        }

    );


// =====================================================
// GET ORGANIZATION DETAILS
// SUPER ADMIN
// =====================================================

export const getOrganizationByIdThunk =
    createAsyncThunk(

        "superadmin/organizations/getById",

        async (
            id,
            { rejectWithValue }
        ) => {

            try {

                const response =
                    await getOrganizationByIdApi(
                        id
                    );


                if (!response?.success) {

                    return rejectWithValue(

                        response?.message ||
                        "Failed to retrieve organization."

                    );

                }


                return response;

            }
            catch (error) {

                return rejectWithValue(

                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to retrieve organization."

                );

            }

        }

    );


// =====================================================
// UPDATE ORGANIZATION
// SUPER ADMIN
// =====================================================

export const updateOrganizationThunk =
    createAsyncThunk(

        "superadmin/organizations/update",

        async (
            {
                id,
                data
            },
            { rejectWithValue }
        ) => {

            try {

                if (!id) {

                    return rejectWithValue(
                        "Organization ID is required."
                    );

                }


                const response =
                    await updateOrganizationApi(
                        id,
                        data
                    );


                if (!response?.success) {

                    return rejectWithValue(

                        response?.message ||
                        "Failed to update organization."

                    );

                }


                return response;

            }
            catch (error) {

                return rejectWithValue(

                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to update organization."

                );

            }

        }

    );


// =====================================================
// ACTIVATE ORGANIZATION
// SUPER ADMIN
// =====================================================

export const activateOrganizationThunk =
    createAsyncThunk(

        "superadmin/organizations/activate",

        async (
            id,
            { rejectWithValue }
        ) => {

            try {

                const response =
                    await activateOrganizationApi(
                        id
                    );


                if (!response?.success) {

                    return rejectWithValue(

                        response?.message ||
                        "Failed to activate organization."

                    );

                }


                return response;

            }
            catch (error) {

                return rejectWithValue(

                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to activate organization."

                );

            }

        }

    );


// =====================================================
// SUSPEND ORGANIZATION
// SUPER ADMIN
// =====================================================

export const suspendOrganizationThunk =
    createAsyncThunk(

        "superadmin/organizations/suspend",

        async (
            id,
            { rejectWithValue }
        ) => {

            try {

                const response =
                    await suspendOrganizationApi(
                        id
                    );


                if (!response?.success) {

                    return rejectWithValue(

                        response?.message ||
                        "Failed to suspend organization."

                    );

                }


                return response;

            }
            catch (error) {

                return rejectWithValue(

                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to suspend organization."

                );

            }

        }

    );


// =====================================================
// DEACTIVATE ORGANIZATION
// SUPER ADMIN
// =====================================================

export const deactivateOrganizationThunk =
    createAsyncThunk(

        "superadmin/organizations/deactivate",

        async (
            id,
            { rejectWithValue }
        ) => {

            try {

                const response =
                    await deactivateOrganizationApi(
                        id
                    );


                if (!response?.success) {

                    return rejectWithValue(

                        response?.message ||
                        "Failed to deactivate organization."

                    );

                }


                return response;

            }
            catch (error) {

                return rejectWithValue(

                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to deactivate organization."

                );

            }

        }

    );


// =====================================================
// RESTORE ORGANIZATION
// SUPER ADMIN
// =====================================================

export const restoreOrganizationThunk =
    createAsyncThunk(

        "superadmin/organizations/restore",

        async (
            id,
            { rejectWithValue }
        ) => {

            try {

                const response =
                    await restoreOrganizationApi(
                        id
                    );


                if (!response?.success) {

                    return rejectWithValue(

                        response?.message ||
                        "Failed to restore organization."

                    );

                }


                return response;

            }
            catch (error) {

                return rejectWithValue(

                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to restore organization."

                );

            }

        }

    );


// =====================================================
// DELETE ORGANIZATION
// SUPER ADMIN
// =====================================================

export const deleteOrganizationThunk =
    createAsyncThunk(

        "superadmin/organizations/delete",

        async (
            id,
            { rejectWithValue }
        ) => {

            try {

                const response =
                    await deleteOrganizationApi(
                        id
                    );


                if (!response?.success) {

                    return rejectWithValue(

                        response?.message ||
                        "Failed to delete organization."

                    );

                }


                return response;

            }
            catch (error) {

                return rejectWithValue(

                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to delete organization."

                );

            }

        }

    );
