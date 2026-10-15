import {
    createSlice
} from "@reduxjs/toolkit";

import {
    getDonationsThunk,
    getDonationByIdThunk,
    createDonationThunk,
    updateDonationThunk,
    deleteDonationThunk
} from "./DonationThunks";

const initialState = {
    donations: [],
    currentDonation: null,

    loading: false,
    detailsLoading: false,
    saving: false,
    deleting: false,

    error: null
};

const donationSlice = createSlice({

    name: "donations",

    initialState,

    reducers: {

        clearDonationError: (state) => {
            state.error = null;
        },

        clearCurrentDonation: (state) => {
            state.currentDonation = null;
        }

    },

    extraReducers: (builder) => {

        // ==========================================
        // GET ALL
        // ==========================================

        builder

            .addCase(
                getDonationsThunk.pending,
                (state) => {

                    state.loading = true;
                    state.error = null;

                }
            )

            .addCase(
                getDonationsThunk.fulfilled,
                (state, action) => {

                    state.loading = false;

                    const payload =
                        action.payload;

                    state.donations =
                        Array.isArray(payload?.data)
                            ? payload.data
                            : [];

                }
            )

            .addCase(
                getDonationsThunk.rejected,
                (state, action) => {

                    state.loading = false;

                    state.error =
                        action.payload ||
                        action.error?.message ||
                        "Failed to fetch donations";

                }
            );

        // ==========================================
        // GET ONE
        // ==========================================

        builder

            .addCase(
                getDonationByIdThunk.pending,
                (state) => {

                    state.detailsLoading = true;
                    state.error = null;

                }
            )

            .addCase(
                getDonationByIdThunk.fulfilled,
                (state, action) => {

                    state.detailsLoading = false;

                    const payload =
                        action.payload;

                    state.currentDonation =
                        payload?.data || null;

                }
            )

            .addCase(
                getDonationByIdThunk.rejected,
                (state, action) => {

                    state.detailsLoading = false;

                    state.error =
                        action.payload ||
                        action.error?.message ||
                        "Failed to fetch donation";

                }
            );

        // ==========================================
        // CREATE
        // ==========================================

        builder

            .addCase(
                createDonationThunk.pending,
                (state) => {

                    state.saving = true;
                    state.error = null;

                }
            )

            .addCase(
                createDonationThunk.fulfilled,
                (state, action) => {

                    state.saving = false;

                    const donation =
                        action.payload?.data;

                    if (
                        donation &&
                        donation._id
                    ) {

                        state.donations.unshift(
                            donation
                        );

                    }

                }
            )

            .addCase(
                createDonationThunk.rejected,
                (state, action) => {

                    state.saving = false;

                    state.error =
                        action.payload ||
                        action.error?.message ||
                        "Failed to create donation";

                }
            );

        // ==========================================
        // UPDATE
        // ==========================================

        builder

            .addCase(
                updateDonationThunk.pending,
                (state) => {

                    state.saving = true;
                    state.error = null;

                }
            )

            .addCase(
                updateDonationThunk.fulfilled,
                (state, action) => {

                    state.saving = false;

                    const updatedDonation =
                        action.payload?.data;

                    if (
                        !updatedDonation ||
                        !updatedDonation._id
                    ) {
                        return;
                    }

                    const index =
                        state.donations.findIndex(
                            (item) =>
                                item._id ===
                                updatedDonation._id
                        );

                    if (index !== -1) {

                        state.donations[index] =
                            updatedDonation;

                    }

                    state.currentDonation =
                        updatedDonation;

                }
            )

            .addCase(
                updateDonationThunk.rejected,
                (state, action) => {

                    state.saving = false;

                    state.error =
                        action.payload ||
                        action.error?.message ||
                        "Failed to update donation";

                }
            );

        // ==========================================
        // DELETE
        // ==========================================

        builder

            .addCase(
                deleteDonationThunk.pending,
                (state) => {

                    state.deleting = true;
                    state.error = null;

                }
            )

            .addCase(
                deleteDonationThunk.fulfilled,
                (state, action) => {

                    state.deleting = false;

                    state.donations =
                        state.donations.filter(
                            (item) =>
                                item._id !==
                                action.payload
                        );

                    if (
                        state.currentDonation?._id ===
                        action.payload
                    ) {

                        state.currentDonation = null;

                    }

                }
            )

            .addCase(
                deleteDonationThunk.rejected,
                (state, action) => {

                    state.deleting = false;

                    state.error =
                        action.payload ||
                        action.error?.message ||
                        "Failed to delete donation";

                }
            );
    }
});

export const {
    clearDonationError,
    clearCurrentDonation
} = donationSlice.actions;

export default donationSlice.reducer;