import { createSlice } from "@reduxjs/toolkit";

import {
    getToken,
    removeToken
} from "../../../services/storageService";

import {
    loginThunk,
    loadCurrentUserThunk,
    refreshCurrentUserThunk,
    logoutThunk
} from "./authThunks";


// ==========================================
// INITIAL STATE
// ==========================================

const token = getToken();

const initialState = {

    user: null,

    token: token,

    isAuthenticated: !!token,

    initialized: false,

    loading: false,

    error: null

};


// ==========================================
// AUTH SLICE
// ==========================================

const authSlice = createSlice({

    name: "auth",

    initialState,

    reducers: {

        // ==================================
        // AUTH LOADING
        // ==================================

        authLoading: (state) => {

            state.loading = true;

            state.error = null;

        },


        // ==================================
        // AUTH INITIALIZED
        // ==================================

        authInitialized: (state) => {

            state.initialized = true;

            state.loading = false;

        },


        // ==================================
        // AUTH ERROR
        // ==================================

        authError: (state, action) => {

            state.error = action.payload;

            state.loading = false;

            state.initialized = true;

            state.isAuthenticated = false;

            state.user = null;

        },


        // ==================================
        // SET CURRENT USER
        // ==================================

        setCurrentUser: (state, action) => {

            state.user = action.payload;

            state.isAuthenticated = true;

            state.initialized = true;

            state.loading = false;

            state.error = null;

        }

    },


    // ==========================================
    // ASYNC ACTIONS
    // ==========================================

    extraReducers: (builder) => {


        // ==================================
        // LOGIN
        // ==================================

        builder.addCase(

            loginThunk.pending,

            (state) => {

                state.loading = true;

                state.error = null;

            }

        );


        builder.addCase(

            loginThunk.fulfilled,

            (state, action) => {

                state.user =
                    action.payload.user;

                state.token =
                    action.payload.token;

                state.isAuthenticated = true;

                state.initialized = true;

                state.loading = false;

                state.error = null;

            }

        );


        builder.addCase(

            loginThunk.rejected,

            (state, action) => {

                state.user = null;

                state.token = null;

                state.isAuthenticated = false;

                state.initialized = true;

                state.loading = false;

                state.error =
                    action.payload;

            }

        );


        // ==================================
        // LOAD CURRENT USER
        // ==================================

        builder.addCase(

            loadCurrentUserThunk.pending,

            (state) => {

                state.loading = true;

                state.error = null;

            }

        );


        builder.addCase(

            loadCurrentUserThunk.fulfilled,

            (state, action) => {

                state.user =
                    action.payload;

                state.token =
                    getToken();

                state.isAuthenticated = true;

                state.initialized = true;

                state.loading = false;

                state.error = null;

            }

        );


        // quiet refresh: only a successful answer updates the user
        builder.addCase(

            refreshCurrentUserThunk.fulfilled,

            (state, action) => {

                if (state.isAuthenticated && action.payload) {
                    state.user = action.payload;
                }

            }

        );


        builder.addCase(

            loadCurrentUserThunk.rejected,

            (state, action) => {

                state.user = null;

                state.token = null;

                state.isAuthenticated = false;

                state.initialized = true;

                state.loading = false;

                state.error =
                    action.payload;

                removeToken();

            }

        );


        // ==================================
        // LOGOUT
        // ==================================

        builder.addCase(

            logoutThunk.fulfilled,

            (state) => {

                state.user = null;

                state.token = null;

                state.isAuthenticated = false;

                state.initialized = true;

                state.loading = false;

                state.error = null;

            }

        );

    }

});


// ==========================================
// ACTIONS
// ==========================================

export const {

    authLoading,

    authInitialized,

    authError,

    setCurrentUser

} = authSlice.actions;


// ==========================================
// REDUCER
// ==========================================

export default authSlice.reducer;