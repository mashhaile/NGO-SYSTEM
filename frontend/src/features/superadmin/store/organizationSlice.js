import {
    createSlice
} from "@reduxjs/toolkit";


import {
    createOrganizationThunk,
    getOrganizationsThunk,
    getOrganizationByIdThunk,
    updateOrganizationThunk,
    activateOrganizationThunk,
    suspendOrganizationThunk,
    deactivateOrganizationThunk,
    restoreOrganizationThunk,
    deleteOrganizationThunk
} from "./organizationThunks";


// =====================================================
// INITIAL STATE
// =====================================================

const initialState = {

    organizations: [],

    organization: null,

    subscription: null,

    plan: null,

    usage: {},

    limits: {},

    usagePercentage: {},

    loading: false,

    error: null,

    success: false,

    message: "",

    pagination: {

        page: 1,

        limit: 10,

        total: 0,

        totalPages: 0

    }

};


// =====================================================
// SLICE
// =====================================================

const organizationSlice = createSlice({

    name: "superadminOrganizations",

    initialState,

    reducers: {

        clearOrganizationError: (state) => {

            state.error = null;

        },


        clearOrganizationSuccess: (state) => {

            state.success = false;

            state.message = "";

        },


        clearSelectedOrganization: (state) => {

            state.organization = null;

            state.subscription = null;

            state.plan = null;

            state.usage = {};

            state.limits = {};

            state.usagePercentage = {};

        }

    },


    extraReducers: (builder) => {

        builder


            // =================================================
            // CREATE ORGANIZATION
            // =================================================

            .addCase(
                createOrganizationThunk.pending,
                (state) => {

                    state.loading = true;

                    state.error = null;

                    state.success = false;

                    state.message = "";

                }
            )


            .addCase(
                createOrganizationThunk.fulfilled,
                (state, action) => {

                    state.loading = false;

                    state.error = null;

                    state.success = true;


                    const response =
                        action.payload;


                    const data =
                        response?.data;


                    const createdOrganization =
                        data?.organization;


                    if (
                        createdOrganization
                    ) {

                        state.organization =
                            createdOrganization;


                        state.subscription =
                            data?.subscription ||
                            null;


                        state.plan =
                            data?.plan ||
                            null;


                        state.usage =
                            data?.usage ||
                            {};


                        state.limits =
                            data?.limits ||
                            {};


                        state.usagePercentage =
                            data?.usagePercentage ||
                            {};


                        state.organizations =
                            [
                                createdOrganization,
                                ...state.organizations
                            ];

                    }


                    state.message =
                        response?.message ||
                        data?.message ||
                        "Organization created successfully.";

                }
            )


            .addCase(
                createOrganizationThunk.rejected,
                (state, action) => {

                    state.loading = false;

                    state.success = false;

                    state.error =
                        action.payload ||
                        "Failed to create organization.";

                }
            )


            // =================================================
            // GET ORGANIZATIONS
            // =================================================

            .addCase(
                getOrganizationsThunk.pending,
                (state) => {

                    state.loading = true;

                    state.error = null;

                }
            )


            .addCase(
                getOrganizationsThunk.fulfilled,
                (state, action) => {

                    state.loading = false;

                    state.error = null;


                    const response =
                        action.payload;


                    const data =
                        response?.data;


                    state.organizations =
                        Array.isArray(
                            data?.organizations
                        )
                            ? data.organizations
                            : Array.isArray(
                                data
                            )
                                ? data
                                : [];


                if (data?.pagination) {

    state.pagination = {

        page:
            data.pagination.page ??
            1,

        limit:
            data.pagination.limit ??
            10,

        total:
            data.pagination.total ??
            0,

        totalPages:
            data.pagination.totalPages ??
            0

    };

}


                    state.message =
                        response?.message ||
                        "";

                }
            )


            .addCase(
                getOrganizationsThunk.rejected,
                (state, action) => {

                    state.loading = false;

                    state.error =
                        action.payload ||
                        "Failed to retrieve organizations.";

                }
            )


            // =================================================
            // GET ORGANIZATION BY ID
            // =================================================

            .addCase(
                getOrganizationByIdThunk.pending,
                (state) => {

                    state.loading = true;

                    state.error = null;

                }
            )


            .addCase(
                getOrganizationByIdThunk.fulfilled,
                (state, action) => {

                    state.loading = false;

                    state.error = null;


                    const response =
                        action.payload;


                    const data =
                        response?.data;


                    state.organization =
                        data?.organization ||
                        null;


                    state.subscription =
                        data?.subscription ||
                        null;


                    state.plan =
                        data?.plan ||
                        null;


                    state.usage =
                        data?.usage ||
                        {};


                    state.limits =
                        data?.limits ||
                        {};


                    state.usagePercentage =
                        data?.usagePercentage ||
                        {};


                    state.message =
                        response?.message ||
                        "";

                }
            )


            .addCase(
                getOrganizationByIdThunk.rejected,
                (state, action) => {

                    state.loading = false;

                    state.organization = null;

                    state.subscription = null;

                    state.plan = null;

                    state.usage = {};

                    state.limits = {};

                    state.usagePercentage = {};

                    state.error =
                        action.payload ||
                        "Failed to retrieve organization.";

                }
            )


            // =================================================
            // UPDATE ORGANIZATION
            // =================================================

            .addCase(
                updateOrganizationThunk.pending,
                (state) => {

                    state.loading = true;

                    state.error = null;

                    state.success = false;

                    state.message = "";

                }
            )


            .addCase(
                updateOrganizationThunk.fulfilled,
                (state, action) => {

                    state.loading = false;

                    state.error = null;

                    state.success = true;


                    const response =
                        action.payload;


                    const updatedOrganization =
                        response?.data?.organization;


                    if (
                        updatedOrganization
                    ) {

                        state.organization =
                            updatedOrganization;


                        const id =
                            updatedOrganization._id;


                        const index =
                            state.organizations.findIndex(
                                organization =>
                                    organization._id === id
                            );


                        if (
                            index !== -1
                        ) {

                            state.organizations[index] =
                                {
                                    ...state.organizations[index],
                                    ...updatedOrganization
                                };

                        }

                    }


                    state.message =
                        response?.message ||
                        "Organization updated successfully.";

                }
            )


            .addCase(
                updateOrganizationThunk.rejected,
                (state, action) => {

                    state.loading = false;

                    state.success = false;

                    state.error =
                        action.payload ||
                        "Failed to update organization.";

                }
            )


            // =================================================
            // ACTIVATE
            // =================================================

            .addCase(
                activateOrganizationThunk.pending,
                (state) => {

                    state.loading = true;

                    state.error = null;

                    state.success = false;

                }
            )


            .addCase(
                activateOrganizationThunk.fulfilled,
                (state, action) => {

                    state.loading = false;

                    state.error = null;

                    state.success = true;


                    state.message =
                        action.payload?.message ||
                        "Organization activated successfully.";


                    const updatedOrganization =
                        action.payload?.data;


                    if (
                        updatedOrganization
                    ) {

                        state.organization =
                            updatedOrganization;


                        const id =
                            updatedOrganization._id;


                        const index =
                            state.organizations.findIndex(
                                organization =>
                                    organization._id === id
                            );


                        if (
                            index !== -1
                        ) {

                            state.organizations[index] =
                                {
                                    ...state.organizations[index],
                                    ...updatedOrganization
                                };

                        }

                    }

                }
            )


            .addCase(
                activateOrganizationThunk.rejected,
                (state, action) => {

                    state.loading = false;

                    state.success = false;

                    state.error =
                        action.payload ||
                        "Failed to activate organization.";

                }
            )


            // =================================================
            // SUSPEND
            // =================================================

            .addCase(
                suspendOrganizationThunk.pending,
                (state) => {

                    state.loading = true;

                    state.error = null;

                    state.success = false;

                }
            )


            .addCase(
                suspendOrganizationThunk.fulfilled,
                (state, action) => {

                    state.loading = false;

                    state.error = null;

                    state.success = true;


                    state.message =
                        action.payload?.message ||
                        "Organization suspended successfully.";


                    const updatedOrganization =
                        action.payload?.data;


                    if (
                        updatedOrganization
                    ) {

                        state.organization =
                            updatedOrganization;


                        const id =
                            updatedOrganization._id;


                        const index =
                            state.organizations.findIndex(
                                organization =>
                                    organization._id === id
                            );


                        if (
                            index !== -1
                        ) {

                            state.organizations[index] =
                                {
                                    ...state.organizations[index],
                                    ...updatedOrganization
                                };

                        }

                    }

                }
            )


            .addCase(
                suspendOrganizationThunk.rejected,
                (state, action) => {

                    state.loading = false;

                    state.success = false;

                    state.error =
                        action.payload ||
                        "Failed to suspend organization.";

                }
            )


            // =================================================
            // DEACTIVATE
            // =================================================

            .addCase(
                deactivateOrganizationThunk.pending,
                (state) => {

                    state.loading = true;

                    state.error = null;

                    state.success = false;

                }
            )


            .addCase(
                deactivateOrganizationThunk.fulfilled,
                (state, action) => {

                    state.loading = false;

                    state.error = null;

                    state.success = true;


                    state.message =
                        action.payload?.message ||
                        "Organization deactivated successfully.";


                    const updatedOrganization =
                        action.payload?.data;


                    if (
                        updatedOrganization
                    ) {

                        state.organization =
                            updatedOrganization;


                        const id =
                            updatedOrganization._id;


                        const index =
                            state.organizations.findIndex(
                                organization =>
                                    organization._id === id
                            );


                        if (
                            index !== -1
                        ) {

                            state.organizations[index] =
                                {
                                    ...state.organizations[index],
                                    ...updatedOrganization
                                };

                        }

                    }

                }
            )


            .addCase(
                deactivateOrganizationThunk.rejected,
                (state, action) => {

                    state.loading = false;

                    state.success = false;

                    state.error =
                        action.payload ||
                        "Failed to deactivate organization.";

                }
            )


            // =================================================
            // RESTORE
            // =================================================

            .addCase(
                restoreOrganizationThunk.pending,
                (state) => {

                    state.loading = true;

                    state.error = null;

                    state.success = false;

                }
            )


            .addCase(
                restoreOrganizationThunk.fulfilled,
                (state, action) => {

                    state.loading = false;

                    state.error = null;

                    state.success = true;


                    state.message =
                        action.payload?.message ||
                        "Organization restored successfully.";


                    const updatedOrganization =
                        action.payload?.data;


                    if (
                        updatedOrganization
                    ) {

                        state.organization =
                            updatedOrganization;


                        const id =
                            updatedOrganization._id;


                        const index =
                            state.organizations.findIndex(
                                organization =>
                                    organization._id === id
                            );


                        if (
                            index !== -1
                        ) {

                            state.organizations[index] =
                                {
                                    ...state.organizations[index],
                                    ...updatedOrganization
                                };

                        }

                    }

                }
            )


            .addCase(
                restoreOrganizationThunk.rejected,
                (state, action) => {

                    state.loading = false;

                    state.success = false;

                    state.error =
                        action.payload ||
                        "Failed to restore organization.";

                }
            )


            // =================================================
            // DELETE
            // =================================================

            .addCase(
                deleteOrganizationThunk.pending,
                (state) => {

                    state.loading = true;

                    state.error = null;

                    state.success = false;

                }
            )


            .addCase(
                deleteOrganizationThunk.fulfilled,
                (state, action) => {

                    state.loading = false;

                    state.error = null;

                    state.success = true;


                    state.message =
                        action.payload?.message ||
                        "Organization deleted successfully.";


                    const deletedOrganization =
                        action.payload?.data;


                    const deletedId =
                        deletedOrganization?._id;


                    if (
                        deletedId
                    ) {

                        state.organizations =
                            state.organizations.filter(
                                organization =>
                                    organization._id !==
                                    deletedId
                            );


                        if (
                            state.organization?._id ===
                            deletedId
                        ) {

                            state.organization =
                                null;

                            state.subscription =
                                null;

                            state.plan =
                                null;

                            state.usage =
                                {};

                            state.limits =
                                {};

                            state.usagePercentage =
                                {};

                        }

                    }

                }
            )


            .addCase(
                deleteOrganizationThunk.rejected,
                (state, action) => {

                    state.loading = false;

                    state.success = false;

                    state.error =
                        action.payload ||
                        "Failed to delete organization.";

                }
            );

    }

});


// =====================================================
// ACTIONS
// =====================================================

export const {

    clearOrganizationError,

    clearOrganizationSuccess,

    clearSelectedOrganization

} = organizationSlice.actions;


// =====================================================
// SELECTORS
// =====================================================

export const selectOrganizations = (
    state
) =>
    state.superadminOrganizations
        .organizations;


export const selectOrganization = (
    state
) =>
    state.superadminOrganizations
        .organization;


export const selectOrganizationSubscription = (
    state
) =>
    state.superadminOrganizations
        .subscription;


export const selectOrganizationPlan = (
    state
) =>
    state.superadminOrganizations
        .plan;


export const selectOrganizationUsage = (
    state
) =>
    state.superadminOrganizations
        .usage;


export const selectOrganizationLimits = (
    state
) =>
    state.superadminOrganizations
        .limits;


export const selectOrganizationUsagePercentage = (
    state
) =>
    state.superadminOrganizations
        .usagePercentage;


export const selectOrganizationLoading = (
    state
) =>
    state.superadminOrganizations
        .loading;


export const selectOrganizationError = (
    state
) =>
    state.superadminOrganizations
        .error;


export const selectOrganizationSuccess = (
    state
) =>
    state.superadminOrganizations
        .success;


export const selectOrganizationMessage = (
    state
) =>
    state.superadminOrganizations
        .message;


export const selectOrganizationPagination = (
    state
) =>
    state.superadminOrganizations
        .pagination;


// =====================================================
// EXPORT
// =====================================================

export default organizationSlice.reducer;
