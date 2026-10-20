import axios from "axios";

import {
    getToken,
    removeToken
} from "./storageService";


// =====================================================
// REDUX STORE REFERENCE
// =====================================================

let reduxStore = null;


// =====================================================
// CONNECT REDUX STORE
// =====================================================

export const setReduxStore = (
    store
) => {

    reduxStore = store;

};


// =====================================================
// API BASE URL
// =====================================================
// - Development: http://localhost:5000/api/v1
// - Production:  VITE_API_URL if set, otherwise "/api/v1"
//                (same domain, proxied to the backend)

const API_URL =
    import.meta.env.VITE_API_URL ||
    (import.meta.env.DEV
        ? "http://localhost:5000/api/v1"
        : "/api/v1");


// =====================================================
// AXIOS CLIENT
// =====================================================

const axiosClient = axios.create({

    baseURL: API_URL,

    headers: {
        "Content-Type":
            "application/json"
    }

});


// =====================================================
// REQUEST INTERCEPTOR
// =====================================================

axiosClient.interceptors.request.use(

    (config) => {

        // =============================================
        // AUTH TOKEN
        // =============================================

        const token =
            getToken();


        if (token) {

            config.headers.Authorization =
                `Bearer ${token}`;

        }


        // =============================================
        // SUPER ADMIN ORGANIZATION CONTEXT
        // =============================================

        if (reduxStore) {

            const state =
                reduxStore.getState();


            const user =
                state.auth?.user;


            const isSuperAdmin =
                user?.role === "superadmin" ||
                user?.role === "super_admin" ||
                user?.isSuperAdmin === true ||
                user?.userType === "superadmin";


            if (isSuperAdmin) {

                const organizationId =
                    state.organizationContext
                        ?.selectedOrganizationId;


                if (organizationId) {

                    config.headers[
                        "x-organization-id"
                    ] = organizationId;

                }

            }

        }


        return config;

    },

    (error) => {

        return Promise.reject(
            error
        );

    }

);


// =====================================================
// RESPONSE INTERCEPTOR
// =====================================================
//
// 401 (not a login attempt): the session ended, e.g. the
// password was changed or reset, or the token expired.
// Clear it and go to the login page with the reason.
//
// 403 PASSWORD_CHANGE_REQUIRED: the user signed in with
// a temporary password and must change it first.
//
// =====================================================

axiosClient.interceptors.response.use(
    (response) => response,
    (error) => {

        const status =
            error?.response?.status;

        const code =
            error?.response?.data?.code;

        const url =
            String(error?.config?.url || "");

        const path =
            window.location.pathname;

        if (
            status === 403 &&
            code === "PASSWORD_CHANGE_REQUIRED" &&
            path !== "/account/password"
        ) {

            window.location.assign("/account/password");

        }
        else if (
            status === 401 &&
            !url.includes("/auth/login") &&
            getToken()
        ) {

            removeToken();

            if (!path.startsWith("/login")) {

                const reason =
                    code === "PASSWORD_CHANGED"
                        ? "password-changed"
                        : "session-ended";

                window.location.assign(`/login?reason=${reason}`);

            }

        }

        return Promise.reject(error);

    }
);


// Base URL for calls that must not carry the staff
// session (e.g. public donor share pages).

export { API_URL };


export default axiosClient;