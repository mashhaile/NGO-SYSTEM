import {
    createSlice
} from "@reduxjs/toolkit";


import {
    getEnterprisesThunk,
    getEnterpriseByIdThunk,
    createEnterpriseThunk,
    updateEnterpriseThunk,
    deleteEnterpriseThunk
} from "./enterpriseThunks";


// =========================================================
// INITIAL STATE
// =========================================================

const initialState = {

    enterprises: [],

    selectedEnterprise: null,

    pagination: {

        page: 1,

        limit: 10,

        totalRecords: 0,

        totalActive: 0,

        totalInactive: 0,

        totalPages: 0,

        hasNextPage: false,

        hasPreviousPage: false

    },

    loading: false,

    actionLoading: false,

    error: null,

    successMessage: null

};


// =========================================================
// SLICE
// =========================================================

const enterpriseSlice = createSlice({

    name: "enterprises",

    initialState,


    reducers: {

        // =================================================
        // CLEAR MESSAGE
        // =================================================

        clearEnterpriseMessage: (
            state
        ) => {

            state.successMessage = null;

            state.error = null;

        },


        // =================================================
        // CLEAR SELECTED ENTERPRISE
        // =================================================

        clearSelectedEnterprise: (
            state
        ) => {

            state.selectedEnterprise = null;

        },


        // =================================================
        // RESET STATE
        // =================================================

        resetEnterpriseState: () =>
            initialState

    },


    extraReducers: (
        builder
    ) => {


        // =================================================
        // GET ENTERPRISES
        // =================================================

        builder.addCase(

            getEnterprisesThunk.pending,

            (state) => {

                state.loading = true;

                state.error = null;

            }

        );


        builder.addCase(

            getEnterprisesThunk.fulfilled,

            (
                state,
                action
            ) => {

                state.loading = false;


                const response =
                    action.payload || {};


                state.enterprises =
                    Array.isArray(
                        response.data
                    )
                        ? response.data
                        : [];


                state.pagination = {

                    page:
                        response.pagination?.page ||
                        1,

                    limit:
                        response.pagination?.limit ||
                        10,

                    totalRecords:
                        response.pagination?.totalRecords ||
                        0,

                    totalActive:
                        response.pagination?.totalActive ||
                        0,

                    totalInactive:
                        response.pagination?.totalInactive ||
                        0,

                    totalPages:
                        response.pagination?.totalPages ||
                        0,

                    hasNextPage:
                        response.pagination?.hasNextPage ||
                        false,

                    hasPreviousPage:
                        response.pagination?.hasPreviousPage ||
                        false

                };

            }

        );


        builder.addCase(

            getEnterprisesThunk.rejected,

            (
                state,
                action
            ) => {

                state.loading = false;

                state.error =
                    action.payload ||
                    "Failed loading enterprises";

            }

        );


        // =================================================
        // GET ENTERPRISE BY ID
        // =================================================

        builder.addCase(

            getEnterpriseByIdThunk.pending,

            (state) => {

                state.loading = true;

                state.error = null;

                state.selectedEnterprise = null;

            }

        );


        builder.addCase(

            getEnterpriseByIdThunk.fulfilled,

            (
                state,
                action
            ) => {

                state.loading = false;


                const response =
                    action.payload || {};


                state.selectedEnterprise =
                    response.data ||
                    response;

            }

        );


        builder.addCase(

            getEnterpriseByIdThunk.rejected,

            (
                state,
                action
            ) => {

                state.loading = false;

                state.error =
                    action.payload ||
                    "Failed loading enterprise";

            }

        );


        // =================================================
        // CREATE ENTERPRISE
        // =================================================

        builder.addCase(

            createEnterpriseThunk.pending,

            (state) => {

                state.actionLoading = true;

                state.error = null;

                state.successMessage = null;

            }

        );


        builder.addCase(

            createEnterpriseThunk.fulfilled,

            (
                state,
                action
            ) => {

                state.actionLoading = false;


                const response =
                    action.payload || {};


                const enterprise =
                    response.data ||
                    response;


                if (
                    enterprise?._id
                ) {

                    state.enterprises.unshift(
                        enterprise
                    );

                }


                state.successMessage =
                    "Enterprise created successfully";

            }

        );


        builder.addCase(

            createEnterpriseThunk.rejected,

            (
                state,
                action
            ) => {

                state.actionLoading = false;

                state.error =
                    action.payload ||
                    "Create enterprise failed";

            }

        );


        // =================================================
        // UPDATE ENTERPRISE
        // =================================================

        builder.addCase(

            updateEnterpriseThunk.pending,

            (state) => {

                state.actionLoading = true;

                state.error = null;

                state.successMessage = null;

            }

        );


        builder.addCase(

            updateEnterpriseThunk.fulfilled,

            (
                state,
                action
            ) => {

                state.actionLoading = false;


                const response =
                    action.payload || {};


                const updated =
                    response.data ||
                    response;


                if (
                    !updated?._id
                ) {

                    state.error =
                        "Enterprise updated but no enterprise data was returned";

                    return;

                }


                // =========================================
                // UPDATE ENTERPRISE IN CURRENT LIST
                // =========================================

                const index =
                    state.enterprises.findIndex(

                        item =>
                            item._id ===
                            updated._id

                    );


                if (
                    index !== -1
                ) {

                    state.enterprises[index] =
                        updated;

                }


                // =========================================
                // UPDATE SELECTED ENTERPRISE
                // =========================================

                state.selectedEnterprise =
                    updated;


                // =========================================
                // SUCCESS
                // =========================================

                state.successMessage =
                    "Enterprise updated successfully";

            }

        );


        builder.addCase(

            updateEnterpriseThunk.rejected,

            (
                state,
                action
            ) => {

                state.actionLoading = false;

                state.error =
                    action.payload ||
                    "Update enterprise failed";

            }

        );


        // =================================================
        // DELETE ENTERPRISE
        // =================================================

        builder.addCase(

            deleteEnterpriseThunk.pending,

            (state) => {

                state.actionLoading = true;

                state.error = null;

                state.successMessage = null;

            }

        );


        builder.addCase(

            deleteEnterpriseThunk.fulfilled,

            (
                state,
                action
            ) => {

                state.actionLoading = false;


                const response =
                    action.payload || {};


                const id =
                    response.id ||
                    response.data?._id ||
                    response.data ||
                    response;


                if (
                    !id
                ) {

                    state.error =
                        "Enterprise deleted but no enterprise ID was returned";

                    return;

                }


                state.enterprises =

                    state.enterprises.filter(

                        item =>
                            item._id !== id

                    );


                if (
                    state.selectedEnterprise?._id ===
                    id
                ) {

                    state.selectedEnterprise =
                        null;

                }


                state.successMessage =
                    "Enterprise deleted successfully";

            }

        );


        builder.addCase(

            deleteEnterpriseThunk.rejected,

            (
                state,
                action
            ) => {

                state.actionLoading = false;

                state.error =
                    action.payload ||
                    "Delete enterprise failed";

            }

        );

    }

});


// =========================================================
// ACTIONS
// =========================================================

export const {

    clearEnterpriseMessage,

    clearSelectedEnterprise,

    resetEnterpriseState

} = enterpriseSlice.actions;


// =========================================================
// REDUCER
// =========================================================

export default enterpriseSlice.reducer;