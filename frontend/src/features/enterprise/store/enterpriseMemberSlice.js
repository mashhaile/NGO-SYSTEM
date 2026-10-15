import {
    createSlice
} from "@reduxjs/toolkit";


import {
    createEnterpriseMemberThunk,
    getEnterpriseMembersThunk,
    getMembersByEnterpriseThunk,
    getEnterprisesByMemberThunk,
    getEnterpriseMemberByIdThunk,
    updateEnterpriseMemberThunk,
    deleteEnterpriseMemberThunk
} from "./enterpriseMemberThunks";



// =====================================================
// DEFAULT PAGINATION
// =====================================================

const defaultPagination = {

    page: 1,

    limit: 10,

    total: 0,

    totalPages: 0,

    hasNextPage: false,

    hasPreviousPage: false

};



// =====================================================
// RESPONSE DATA HELPER
// =====================================================

const getResponseData = (
    payload
) => {

    // =========================================
    // LIST RESPONSE
    // =========================================

    if (
        Array.isArray(
            payload?.data?.data
        )
    ) {

        return payload.data.data;

    }


    // =========================================
    // SINGLE OBJECT RESPONSE
    // =========================================

    if (
        payload?.data &&
        typeof payload.data === "object" &&
        !Array.isArray(
            payload.data
        )
    ) {

        return payload.data;

    }


    // =========================================
    // DIRECT ARRAY
    // =========================================

    if (
        Array.isArray(
            payload
        )
    ) {

        return payload;

    }


    // =========================================
    // NOTHING
    // =========================================

    return null;

};



// =====================================================
// PAGINATION HELPER
// =====================================================

const getResponsePagination = (
    payload
) => {

    return {

        ...defaultPagination,

        ...(
            payload?.data?.pagination ||

            payload?.pagination ||

            {}

        )

    };

};



// =====================================================
// INITIAL STATE
// =====================================================

const initialState = {

    // =========================================
    // ALL MEMBERS
    // =========================================

    members: [],


    // =========================================
    // SELECTED MEMBER
    // =========================================

    selectedMember: null,


    // =========================================
    // BENEFICIARY ENTERPRISES
    // =========================================

    beneficiaryEnterprises: [],


    // =========================================
    // ENTERPRISE MEMBERS
    // =========================================

    enterpriseMembers: [],


    // =========================================
    // PAGINATION
    // =========================================

    pagination: {

        ...defaultPagination

    },


    // =========================================
    // LOADING
    // =========================================

    loading: false,


    // =========================================
    // ACTION LOADING
    // =========================================

    actionLoading: false,


    // =========================================
    // ERROR
    // =========================================

    error: null,


    // =========================================
    // SUCCESS
    // =========================================

    successMessage: null

};



// =====================================================
// SLICE
// =====================================================

const enterpriseMemberSlice = createSlice({

    name:
        "enterpriseMembers",

    initialState,

    reducers: {


        // =================================================
        // CLEAR MESSAGE
        // =================================================

        clearEnterpriseMemberMessage: (
            state
        ) => {

            state.successMessage = null;

            state.error = null;

        },


        // =================================================
        // CLEAR SELECTED MEMBER
        // =================================================

        clearSelectedEnterpriseMember: (
            state
        ) => {

            state.selectedMember = null;

        },


        // =================================================
        // CLEAR BENEFICIARY ENTERPRISES
        // =================================================

        clearBeneficiaryEnterprises: (
            state
        ) => {

            state.beneficiaryEnterprises = [];

        },


        // =================================================
        // CLEAR ENTERPRISE MEMBERS
        // =================================================

        clearEnterpriseMembers: (
            state
        ) => {

            state.enterpriseMembers = [];

        },


        // =================================================
        // CLEAR ALL MEMBERS
        // =================================================

        clearMembers: (
            state
        ) => {

            state.members = [];

        },


        // =================================================
        // RESET
        // =================================================

        resetEnterpriseMemberState: () => {

            return {

                ...initialState,

                pagination: {

                    ...defaultPagination

                }

            };

        }

    },


    // =====================================================
    // EXTRA REDUCERS
    // =====================================================

    extraReducers: (
        builder
    ) => {


        // =================================================
        // GET ALL MEMBERS
        // =================================================

        builder.addCase(

            getEnterpriseMembersThunk.pending,

            (
                state
            ) => {

                state.loading = true;

                state.error = null;

            }

        );


        builder.addCase(

            getEnterpriseMembersThunk.fulfilled,

            (
                state,
                action
            ) => {

                state.loading = false;

                const data =
                    getResponseData(
                        action.payload
                    );


                state.members =

                    Array.isArray(data)

                        ? data

                        : [];


                state.pagination =
                    getResponsePagination(
                        action.payload
                    );

            }

        );


        builder.addCase(

            getEnterpriseMembersThunk.rejected,

            (
                state,
                action
            ) => {

                state.loading = false;

                state.members = [];

                state.error =
                    action.payload ||

                    "Failed loading enterprise members";

            }

        );



        // =================================================
        // GET MEMBERS BY ENTERPRISE
        // =================================================

        builder.addCase(

            getMembersByEnterpriseThunk.pending,

            (
                state
            ) => {

                state.loading = true;

                state.error = null;

            }

        );


        builder.addCase(

            getMembersByEnterpriseThunk.fulfilled,

            (
                state,
                action
            ) => {

                state.loading = false;

                const data =
                    getResponseData(
                        action.payload
                    );


                state.enterpriseMembers =

                    Array.isArray(data)

                        ? data

                        : [];


                state.pagination =
                    getResponsePagination(
                        action.payload
                    );

            }

        );


        builder.addCase(

            getMembersByEnterpriseThunk.rejected,

            (
                state,
                action
            ) => {

                state.loading = false;

                state.enterpriseMembers = [];

                state.error =
                    action.payload ||

                    "Failed loading enterprise members";

            }

        );



        // =================================================
        // GET ENTERPRISES BY BENEFICIARY
        // =================================================

        builder.addCase(

            getEnterprisesByMemberThunk.pending,

            (
                state
            ) => {

                state.loading = true;

                state.error = null;

            }

        );


        builder.addCase(

            getEnterprisesByMemberThunk.fulfilled,

            (
                state,
                action
            ) => {

                state.loading = false;

                const data =
                    getResponseData(
                        action.payload
                    );


                state.beneficiaryEnterprises =

                    Array.isArray(data)

                        ? data

                        : [];


                state.pagination =
                    getResponsePagination(
                        action.payload
                    );

            }

        );


        builder.addCase(

            getEnterprisesByMemberThunk.rejected,

            (
                state,
                action
            ) => {

                state.loading = false;

                state.beneficiaryEnterprises = [];

                state.error =
                    action.payload ||

                    "Failed loading beneficiary enterprises";

            }

        );



        // =================================================
        // GET MEMBER BY ID
        // =================================================

        builder.addCase(

            getEnterpriseMemberByIdThunk.pending,

            (
                state
            ) => {

                state.loading = true;

                state.error = null;

                state.selectedMember = null;

            }

        );


        builder.addCase(

            getEnterpriseMemberByIdThunk.fulfilled,

            (
                state,
                action
            ) => {

                state.loading = false;

                const data =
                    getResponseData(
                        action.payload
                    );


                if (
                    Array.isArray(data)
                ) {

                    state.selectedMember =
                        data[0] || null;

                }

                else {

                    state.selectedMember =
                        data || null;

                }

            }

        );


        builder.addCase(

            getEnterpriseMemberByIdThunk.rejected,

            (
                state,
                action
            ) => {

                state.loading = false;

                state.selectedMember = null;

                state.error =
                    action.payload ||

                    "Failed loading enterprise member";

            }

        );



        // =================================================
        // CREATE
        // =================================================

        builder.addCase(

            createEnterpriseMemberThunk.pending,

            (
                state
            ) => {

                state.actionLoading = true;

                state.error = null;

                state.successMessage = null;

            }

        );


        builder.addCase(

            createEnterpriseMemberThunk.fulfilled,

            (
                state,
                action
            ) => {

                state.actionLoading = false;

                const data =
                    getResponseData(
                        action.payload
                    );


                const createdMember =

                    Array.isArray(data)

                        ? (
                            data[0] ||
                            null
                        )

                        : data;


                if (
                    createdMember
                ) {

                    state.members.unshift(
                        createdMember
                    );


                    state.enterpriseMembers.unshift(
                        createdMember
                    );


                    state.selectedMember =
                        createdMember;

                }


                state.successMessage =
                    "Enterprise member added successfully";

            }

        );


        builder.addCase(

            createEnterpriseMemberThunk.rejected,

            (
                state,
                action
            ) => {

                state.actionLoading = false;

                state.error =
                    action.payload ||

                    "Failed creating enterprise member";

            }

        );



        // =================================================
        // UPDATE
        // =================================================

        builder.addCase(

            updateEnterpriseMemberThunk.pending,

            (
                state
            ) => {

                state.actionLoading = true;

                state.error = null;

                state.successMessage = null;

            }

        );


        builder.addCase(

            updateEnterpriseMemberThunk.fulfilled,

            (
                state,
                action
            ) => {

                state.actionLoading = false;


                const data =
                    getResponseData(
                        action.payload
                    );


                const updated =

                    Array.isArray(data)

                        ? (
                            data[0] ||
                            null
                        )

                        : data;


                if (
                    !updated
                ) {

                    return;

                }


                // =========================================
                // UPDATE ALL MEMBERS
                // =========================================

                const membersIndex =
                    state.members.findIndex(

                        item =>
                            item?._id ===
                            updated?._id

                    );


                if (
                    membersIndex !== -1
                ) {

                    state.members[
                        membersIndex
                    ] = updated;

                }


                // =========================================
                // UPDATE ENTERPRISE MEMBERS
                // =========================================

                const enterpriseIndex =
                    state.enterpriseMembers.findIndex(

                        item =>
                            item?._id ===
                            updated?._id

                    );


                if (
                    enterpriseIndex !== -1
                ) {

                    state.enterpriseMembers[
                        enterpriseIndex
                    ] = updated;

                }


                // =========================================
                // UPDATE SELECTED MEMBER
                // =========================================

                state.selectedMember =
                    updated;


                state.successMessage =
                    "Enterprise member updated successfully";

            }

        );


        builder.addCase(

            updateEnterpriseMemberThunk.rejected,

            (
                state,
                action
            ) => {

                state.actionLoading = false;

                state.error =
                    action.payload ||

                    "Failed updating enterprise member";

            }

        );



        // =================================================
        // DELETE
        // =================================================

        builder.addCase(

            deleteEnterpriseMemberThunk.pending,

            (
                state
            ) => {

                state.actionLoading = true;

                state.error = null;

                state.successMessage = null;

            }

        );


        builder.addCase(

            deleteEnterpriseMemberThunk.fulfilled,

            (
                state,
                action
            ) => {

                state.actionLoading = false;


                const id =
                    action.payload?.id ||

                    action.payload?._id;


                if (!id) {

                    state.successMessage =
                        "Enterprise member deleted successfully";

                    return;

                }


                // =========================================
                // REMOVE FROM ALL MEMBERS
                // =========================================

                state.members =
                    state.members.filter(

                        item =>
                            item?._id !== id

                    );


                // =========================================
                // REMOVE FROM ENTERPRISE MEMBERS
                // =========================================

                state.enterpriseMembers =
                    state.enterpriseMembers.filter(

                        item =>
                            item?._id !== id

                    );


                // =========================================
                // REMOVE FROM BENEFICIARY ENTERPRISES
                // =========================================

                state.beneficiaryEnterprises =
                    state.beneficiaryEnterprises.filter(

                        item =>
                            item?._id !== id

                    );


                // =========================================
                // CLEAR SELECTED
                // =========================================

                if (
                    state.selectedMember?._id ===
                    id
                ) {

                    state.selectedMember = null;

                }


                // =========================================
                // PAGINATION
                // =========================================

                if (
                    state.pagination.total > 0
                ) {

                    state.pagination.total -= 1;

                }


                state.successMessage =
                    "Enterprise member deleted successfully";

            }

        );


        builder.addCase(

            deleteEnterpriseMemberThunk.rejected,

            (
                state,
                action
            ) => {

                state.actionLoading = false;

                state.error =
                    action.payload ||

                    "Failed deleting enterprise member";

            }

        );

    }

});



// =====================================================
// EXPORT ACTIONS
// =====================================================

export const {

    clearEnterpriseMemberMessage,

    clearSelectedEnterpriseMember,

    clearBeneficiaryEnterprises,

    clearEnterpriseMembers,

    clearMembers,

    resetEnterpriseMemberState

} = enterpriseMemberSlice.actions;



// =====================================================
// EXPORT REDUCER
// =====================================================

export default enterpriseMemberSlice.reducer;
