import { createSlice } from "@reduxjs/toolkit";

import {
    getBeneficiariesThunk,
    createBeneficiaryThunk,
    updateBeneficiaryThunk,
    deleteBeneficiaryThunk
} from "./beneficiaryThunks";


// =====================================================
// INITIAL STATE
// =====================================================

const initialState = {

    beneficiaries: [],

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


// =====================================================
// SLICE
// =====================================================

const beneficiarySlice = createSlice({

    name: "beneficiaries",

    initialState,

    reducers: {

        // =============================================
        // CLEAR MESSAGES
        // =============================================

        clearBeneficiaryMessage: (state) => {

            state.successMessage = null;

            state.error = null;

        },


        // =============================================
        // RESET STATE
        // =============================================

        resetBeneficiaryState: () => initialState

    },


    extraReducers: (builder) => {


        // =================================================
        // GET BENEFICIARIES
        // =================================================

        builder.addCase(
            getBeneficiariesThunk.pending,
            (state) => {

                state.loading = true;

                state.error = null;

            }
        );


        builder.addCase(
            getBeneficiariesThunk.fulfilled,
            (state, action) => {

                state.loading = false;

                const result =
                    action.payload?.data;


                // -----------------------------------------
                // BENEFICIARIES
                // -----------------------------------------

                state.beneficiaries =
                    Array.isArray(result?.data)
                        ? result.data
                        : [];


                // -----------------------------------------
                // PAGINATION
                // -----------------------------------------

                state.pagination =
                    result?.pagination || {
                        page: 1,
                        limit: 10,
                        totalRecords: 0,
                        totalActive: 0,
                        totalInactive: 0,
                        totalPages: 0,
                        hasNextPage: false,
                        hasPreviousPage: false
                    };

            }
        );


        builder.addCase(
            getBeneficiariesThunk.rejected,
            (state, action) => {

                state.loading = false;

                state.error =
                    action.payload ||
                    "Failed loading beneficiaries";

            }
        );


        // =================================================
        // CREATE BENEFICIARY
        // =================================================

        builder.addCase(
            createBeneficiaryThunk.pending,
            (state) => {

                state.actionLoading = true;

                state.error = null;

            }
        );


        builder.addCase(
            createBeneficiaryThunk.fulfilled,
            (state, action) => {

                state.actionLoading = false;

                const beneficiary =
                    action.payload?.data ||
                    action.payload;


                if (
                    beneficiary &&
                    !Array.isArray(beneficiary) &&
                    beneficiary._id
                ) {

                    state.beneficiaries.unshift(
                        beneficiary
                    );

                }


                state.pagination.totalRecords =
                    (
                        Number(
                            state.pagination.totalRecords
                        ) || 0
                    ) + 1;


                if (
                    beneficiary?.status === "Inactive"
                ) {

                    state.pagination.totalInactive =
                        (
                            Number(
                                state.pagination.totalInactive
                            ) || 0
                        ) + 1;

                } else {

                    state.pagination.totalActive =
                        (
                            Number(
                                state.pagination.totalActive
                            ) || 0
                        ) + 1;

                }


                state.successMessage =
                    "Beneficiary created successfully";

            }
        );


        builder.addCase(
            createBeneficiaryThunk.rejected,
            (state, action) => {

                state.actionLoading = false;

                state.error =
                    action.payload ||
                    "Create failed";

            }
        );


        // =================================================
        // UPDATE BENEFICIARY
        // =================================================

        builder.addCase(
            updateBeneficiaryThunk.pending,
            (state) => {

                state.actionLoading = true;

                state.error = null;

            }
        );


        builder.addCase(
            updateBeneficiaryThunk.fulfilled,
            (state, action) => {

                state.actionLoading = false;

                const updated =
                    action.payload?.data ||
                    action.payload;


                if (!updated?._id) {

                    state.successMessage =
                        "Beneficiary updated successfully";

                    return;

                }


                const index =
                    state.beneficiaries.findIndex(
                        (item) =>
                            String(
                                item?._id ||
                                item?.id
                            ) ===
                            String(updated._id)
                    );


                if (index !== -1) {

                    const previous =
                        state.beneficiaries[index];

                    state.beneficiaries[index] =
                        updated;


                    // -------------------------------------
                    // UPDATE ACTIVE / INACTIVE COUNTS
                    // -------------------------------------

                    if (
                        previous?.status !==
                        updated?.status
                    ) {

                        if (
                            previous?.status ===
                            "Active"
                        ) {

                            state.pagination.totalActive =
                                Math.max(
                                    0,
                                    (
                                        Number(
                                            state.pagination
                                                .totalActive
                                        ) || 0
                                    ) - 1
                                );

                            state.pagination.totalInactive =
                                (
                                    Number(
                                        state.pagination
                                            .totalInactive
                                    ) || 0
                                ) + 1;

                        } else {

                            state.pagination.totalInactive =
                                Math.max(
                                    0,
                                    (
                                        Number(
                                            state.pagination
                                                .totalInactive
                                        ) || 0
                                    ) - 1
                                );

                            state.pagination.totalActive =
                                (
                                    Number(
                                        state.pagination
                                            .totalActive
                                    ) || 0
                                ) + 1;

                        }

                    }

                }


                state.successMessage =
                    "Beneficiary updated successfully";

            }
        );


        builder.addCase(
            updateBeneficiaryThunk.rejected,
            (state, action) => {

                state.actionLoading = false;

                state.error =
                    action.payload ||
                    "Update failed";

            }
        );


        // =================================================
        // DELETE BENEFICIARY
        // =================================================

        builder.addCase(
            deleteBeneficiaryThunk.pending,
            (state) => {

                state.actionLoading = true;

                state.error = null;

            }
        );


        builder.addCase(
            deleteBeneficiaryThunk.fulfilled,
            (state, action) => {

                state.actionLoading = false;


                const deletedId =
                    action.payload?.id ||
                    action.payload?.response?.data?._id ||
                    action.payload?.response?.data?.id;


                if (deletedId) {

                    const deletedBeneficiary =
                        state.beneficiaries.find(
                            (item) =>
                                String(
                                    item?._id ||
                                    item?.id
                                ) ===
                                String(deletedId)
                        );


                    state.beneficiaries =
                        state.beneficiaries.filter(
                            (item) =>
                                String(
                                    item?._id ||
                                    item?.id
                                ) !==
                                String(deletedId)
                        );


                    // -------------------------------------
                    // UPDATE COUNTS
                    // -------------------------------------

                    if (deletedBeneficiary) {

                        state.pagination.totalRecords =
                            Math.max(
                                0,
                                (
                                    Number(
                                        state.pagination
                                            .totalRecords
                                    ) || 0
                                ) - 1
                            );


                        if (
                            deletedBeneficiary.status ===
                            "Inactive"
                        ) {

                            state.pagination.totalInactive =
                                Math.max(
                                    0,
                                    (
                                        Number(
                                            state.pagination
                                                .totalInactive
                                        ) || 0
                                    ) - 1
                                );

                        } else {

                            state.pagination.totalActive =
                                Math.max(
                                    0,
                                    (
                                        Number(
                                            state.pagination
                                                .totalActive
                                        ) || 0
                                    ) - 1
                                );

                        }

                    }

                }


                state.successMessage =
                    "Beneficiary deleted successfully";

            }
        );


        builder.addCase(
            deleteBeneficiaryThunk.rejected,
            (state, action) => {

                state.actionLoading = false;

                state.error =
                    action.payload ||
                    "Delete failed";

            }
        );

    }

});


// =====================================================
// ACTIONS
// =====================================================

export const {
    clearBeneficiaryMessage,
    resetBeneficiaryState
} = beneficiarySlice.actions;


// =====================================================
// REDUCER
// =====================================================

export default beneficiarySlice.reducer;
