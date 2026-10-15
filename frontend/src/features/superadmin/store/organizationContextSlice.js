import {
    createSlice
} from "@reduxjs/toolkit";


// =====================================================
// INITIAL STATE
// =====================================================

const initialState = {

    selectedOrganizationId: null,

    selectedOrganization: null

};


// =====================================================
// SLICE
// =====================================================

const organizationContextSlice = createSlice({

    name: "organizationContext",

    initialState,

    reducers: {

        // =============================================
        // SET ORGANIZATION
        // =============================================

        setOrganizationContext: (
            state,
            action
        ) => {

            const organization =
                action.payload || null;

            state.selectedOrganization =
                organization;

            state.selectedOrganizationId =
                organization?._id ||
                organization?.id ||
                null;

        },


        // =============================================
        // SET ORGANIZATION ID ONLY
        // =============================================

        setOrganizationId: (
            state,
            action
        ) => {

            state.selectedOrganizationId =
                action.payload || null;

        },


        // =============================================
        // CLEAR ORGANIZATION
        // =============================================

        clearOrganizationContext: (
            state
        ) => {

            state.selectedOrganizationId =
                null;

            state.selectedOrganization =
                null;

        }

    }

});


// =====================================================
// ACTIONS
// =====================================================

export const {
    setOrganizationContext,
    setOrganizationId,
    clearOrganizationContext
} =
    organizationContextSlice.actions;


// =====================================================
// SELECTORS
// =====================================================

export const selectSelectedOrganizationId =
    state =>
        state.organizationContext
            ?.selectedOrganizationId || null;


export const selectSelectedOrganization =
    state =>
        state.organizationContext
            ?.selectedOrganization || null;


// =====================================================
// REDUCER
// =====================================================

export const organizationContextReducer =
    organizationContextSlice.reducer;


export default organizationContextReducer;