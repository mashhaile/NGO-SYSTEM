import { useEffect } from "react";

import { useDispatch } from "react-redux";

import {
    loadCurrentUserThunk,
    refreshCurrentUserThunk,
    authInitialized
} from "../features/auth/store";

import {
    getToken
} from "../services/storageService";


const AuthInitializer = ({ children }) => {

    const dispatch = useDispatch();


    useEffect(() => {

        const initialize = async () => {

            const token = getToken();


            // ==========================================
            // NO TOKEN
            // ==========================================

            if (!token) {

                dispatch(
                    authInitialized()
                );

                return;

            }


            // ==========================================
            // TOKEN EXISTS
            // VERIFY SESSION
            // ==========================================

            await dispatch(
                loadCurrentUserThunk()
            );

        };


        initialize();

    }, [dispatch]);


    // ==========================================
    // KEEP PERMISSIONS AND MODULES CURRENT
    // ==========================================
    //
    // When the window comes back into focus (at most once a
    // minute), the user's permissions and the organization's
    // modules are loaded again: a role or module changed by
    // an administrator applies without signing out.
    //
    // ==========================================

    useEffect(() => {

        let last = Date.now();

        const refresh = () => {
            if (!getToken() || Date.now() - last < 60000) return;
            last = Date.now();
            dispatch(refreshCurrentUserThunk());
        };

        window.addEventListener("focus", refresh);
        return () => window.removeEventListener("focus", refresh);

    }, [dispatch]);


    return children;

};


export default AuthInitializer;