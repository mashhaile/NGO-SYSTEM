import axios from "axios";

import {
    getToken
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


export default axiosClient;