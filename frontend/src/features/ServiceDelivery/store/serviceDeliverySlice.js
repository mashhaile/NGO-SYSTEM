import {
    createSlice
} from "@reduxjs/toolkit";


import {
    getServiceDeliveries,
    getServiceDeliveryById,
    createServiceDelivery,
    updateServiceDelivery,
    deleteServiceDelivery
} from "./serviceDeliveryThunks";


// =====================================================
// RESPONSE NORMALIZATION HELPERS
// =====================================================

const normalizeListResponse = (
    payload
) => {

    /*
     * Supported response shapes:
     *
     * 1.
     * {
     *     data: [],
     *     pagination: {}
     * }
     *
     * 2.
     * {
     *     data: {
     *         data: [],
     *         pagination: {}
     *     }
     * }
     *
     * 3.
     * {
     *     serviceDeliveries: [],
     *     pagination: {}
     * }
     *
     * 4.
     * {
     *     data: [],
     *     total: 1,
     *     page: 1,
     *     limit: 10,
     *     totalPages: 1
     * }
     */


    const root =
        payload &&
        typeof payload === "object"
            ? payload
            : {};


    const nested =
        root.data &&
        !Array.isArray(
            root.data
        ) &&
        typeof root.data === "object"
            ? root.data
            : null;


    const records =
        Array.isArray(
            root.data
        )
            ? root.data
            : Array.isArray(
                nested?.data
            )
                ? nested.data
                : Array.isArray(
                    root.serviceDeliveries
                )
                    ? root.serviceDeliveries
                    : Array.isArray(
                        nested?.serviceDeliveries
                    )
                        ? nested.serviceDeliveries
                        : [];


    const paginationSource =
        root.pagination &&
        typeof root.pagination === "object"
            ? root.pagination
            : nested?.pagination &&
                typeof nested.pagination === "object"
                    ? nested.pagination
                    : root;


    const total =
        Number(
            paginationSource?.total ??
            paginationSource?.totalCount ??
            paginationSource?.count ??
            paginationSource?.totalRecords ??
            records.length
        );


    const page =
        Number(
            paginationSource?.page ??
            paginationSource?.currentPage ??
            1
        );


    const limit =
        Number(
            paginationSource?.limit ??
            paginationSource?.pageSize ??
            10
        );


    const totalPages =
        Number(
            paginationSource?.totalPages ??
            paginationSource?.pages ??
            (
                limit > 0
                    ? Math.ceil(
                        total /
                        limit
                    )
                    : 0
            )
        );


    return {

        data:
            records,

        pagination: {

            total:
                Number.isFinite(
                    total
                )
                    ? total
                    : records.length,

            page:
                Number.isFinite(
                    page
                ) &&
                page > 0
                    ? page
                    : 1,

            limit:
                Number.isFinite(
                    limit
                ) &&
                limit > 0
                    ? limit
                    : 10,

            totalPages:
                Number.isFinite(
                    totalPages
                ) &&
                totalPages >= 0
                    ? totalPages
                    : 0

        }

    };

};


const normalizeSingleResponse = (
    payload
) => {

    if (
        !payload ||
        typeof payload !== "object"
    ) {

        return null;

    }


    if (
        payload.data &&
        typeof payload.data === "object" &&
        !Array.isArray(
            payload.data
        )
    ) {

        return (
            payload.data
        );

    }


    return payload;

};


// =====================================================
// INITIAL STATE
// =====================================================

const initialState = {

    serviceDeliveries: [],

    currentServiceDelivery: null,

    loading: false,

    error: null,

    pagination: {

        total: 0,

        page: 1,

        limit: 10,

        totalPages: 0

    }

};


// =====================================================
// SLICE
// =====================================================

const serviceDeliverySlice =
    createSlice({

        name: "serviceDelivery",

        initialState,

        reducers: {

            clearServiceDeliveryError: (
                state
            ) => {

                state.error = null;

            },


            clearCurrentServiceDelivery: (
                state
            ) => {

                state.currentServiceDelivery =
                    null;

            }

        },


        extraReducers: (
            builder
        ) => {

            builder


                // =========================================
                // GET ALL SERVICE DELIVERIES
                // =========================================

                .addCase(
                    getServiceDeliveries.pending,
                    (
                        state
                    ) => {

                        state.loading = true;

                        state.error = null;

                    }
                )


                .addCase(
                    getServiceDeliveries.fulfilled,
                    (
                        state,
                        action
                    ) => {

                        state.loading = false;

                        state.error = null;


                        const normalized =
                            normalizeListResponse(
                                action.payload
                            );


                        state.serviceDeliveries =
                            normalized.data;


                        state.pagination =
                            normalized.pagination;

                    }
                )


                .addCase(
                    getServiceDeliveries.rejected,
                    (
                        state,
                        action
                    ) => {

                        state.loading = false;

                        state.error =
                            action.payload ||
                            action.error?.message ||
                            "Failed to load service deliveries.";

                    }
                )


                // =========================================
                // GET SERVICE DELIVERY BY ID
                // =========================================

                .addCase(
                    getServiceDeliveryById.pending,
                    (
                        state
                    ) => {

                        state.loading = true;

                        state.error = null;

                    }
                )


                .addCase(
                    getServiceDeliveryById.fulfilled,
                    (
                        state,
                        action
                    ) => {

                        state.loading = false;

                        state.error = null;


                        state.currentServiceDelivery =
                            normalizeSingleResponse(
                                action.payload
                            );

                    }
                )


                .addCase(
                    getServiceDeliveryById.rejected,
                    (
                        state,
                        action
                    ) => {

                        state.loading = false;

                        state.error =
                            action.payload ||
                            action.error?.message ||
                            "Failed to load service delivery.";

                        state.currentServiceDelivery =
                            null;

                    }
                )


                // =========================================
                // CREATE SERVICE DELIVERY
                // =========================================

                .addCase(
                    createServiceDelivery.pending,
                    (
                        state
                    ) => {

                        state.loading = true;

                        state.error = null;

                    }
                )


                .addCase(
                    createServiceDelivery.fulfilled,
                    (
                        state,
                        action
                    ) => {

                        state.loading = false;

                        state.error = null;


                        const created =
                            normalizeSingleResponse(
                                action.payload
                            );


                        if (
                            created
                        ) {

                            state.serviceDeliveries.unshift(
                                created
                            );


                            state.currentServiceDelivery =
                                created;


                            /*
                             * Keep the list statistics
                             * synchronized when a delivery
                             * is created without requiring
                             * a full reload.
                             */

                            state.pagination.total =
                                Number(
                                    state.pagination.total || 0
                                ) + 1;


                            if (
                                state.pagination.limit > 0
                            ) {

                                state.pagination.totalPages =
                                    Math.ceil(
                                        state.pagination.total /
                                        state.pagination.limit
                                    );

                            }

                        }

                    }
                )


                .addCase(
                    createServiceDelivery.rejected,
                    (
                        state,
                        action
                    ) => {

                        state.loading = false;

                        state.error =
                            action.payload ||
                            action.error?.message ||
                            "Failed to create service delivery.";

                    }
                )


                // =========================================
                // UPDATE SERVICE DELIVERY
                // =========================================

                .addCase(
                    updateServiceDelivery.pending,
                    (
                        state
                    ) => {

                        state.loading = true;

                        state.error = null;

                    }
                )


                .addCase(
                    updateServiceDelivery.fulfilled,
                    (
                        state,
                        action
                    ) => {

                        state.loading = false;

                        state.error = null;


                        const updated =
                            normalizeSingleResponse(
                                action.payload
                            );


                        if (
                            !updated
                        ) {

                            return;

                        }


                        const updatedId =
                            String(
                                updated?._id || ""
                            );


                        if (
                            !updatedId
                        ) {

                            return;

                        }


                        const index =
                            state.serviceDeliveries.findIndex(
                                (
                                    item
                                ) =>
                                    String(
                                        item?._id || ""
                                    ) ===
                                    updatedId
                            );


                        if (
                            index !== -1
                        ) {

                            state.serviceDeliveries[
                                index
                            ] = updated;

                        }


                        if (
                            state.currentServiceDelivery &&
                            String(
                                state.currentServiceDelivery?._id || ""
                            ) ===
                            updatedId
                        ) {

                            state.currentServiceDelivery =
                                updated;

                        }

                    }
                )


                .addCase(
                    updateServiceDelivery.rejected,
                    (
                        state,
                        action
                    ) => {

                        state.loading = false;

                        state.error =
                            action.payload ||
                            action.error?.message ||
                            "Failed to update service delivery.";

                    }
                )


                // =========================================
                // DELETE SERVICE DELIVERY
                // =========================================

                .addCase(
                    deleteServiceDelivery.pending,
                    (
                        state
                    ) => {

                        state.loading = true;

                        state.error = null;

                    }
                )


                .addCase(
                    deleteServiceDelivery.fulfilled,
                    (
                        state,
                        action
                    ) => {

                        state.loading = false;

                        state.error = null;


                        const deletedId =
                            String(
                                action.payload?._id ||
                                action.payload?.id ||
                                action.payload ||
                                ""
                            );


                        state.serviceDeliveries =
                            state.serviceDeliveries.filter(
                                (
                                    item
                                ) =>
                                    String(
                                        item?._id || ""
                                    ) !==
                                    deletedId
                            );


                        if (
                            state.currentServiceDelivery &&
                            String(
                                state.currentServiceDelivery?._id || ""
                            ) ===
                            deletedId
                        ) {

                            state.currentServiceDelivery =
                                null;

                        }


                        /*
                         * Keep pagination statistics
                         * synchronized after deletion.
                         */

                        if (
                            state.pagination.total > 0
                        ) {

                            state.pagination.total -= 1;

                        }


                        if (
                            state.pagination.limit > 0
                        ) {

                            state.pagination.totalPages =
                                Math.ceil(
                                    state.pagination.total /
                                    state.pagination.limit
                                );

                        }

                    }
                )


                .addCase(
                    deleteServiceDelivery.rejected,
                    (
                        state,
                        action
                    ) => {

                        state.loading = false;

                        state.error =
                            action.payload ||
                            action.error?.message ||
                            "Failed to delete service delivery.";

                    }
                );

        }

    });


// =====================================================
// ACTIONS
// =====================================================

export const {
    clearServiceDeliveryError,
    clearCurrentServiceDelivery
} = serviceDeliverySlice.actions;


// =====================================================
// REDUCER
// =====================================================

export default serviceDeliverySlice.reducer;