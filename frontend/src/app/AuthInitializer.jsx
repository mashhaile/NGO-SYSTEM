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
    // When the window or the tab comes back (at most every 15
    // seconds), and every 2 minutes while the page is visible,
    // the user's permissions and the organization's modules
    // are loaded again (quietly): a role or module changed by
    // an administrator applies without signing out or
    // reloading.
    //
    // ==========================================

    useEffect(() => {

        let last = Date.now();

        const refresh = (minimum = 15000) => {
            if (!getToken() || document.visibilityState === "hidden" || Date.now() - last < minimum) return;
            last = Date.now();
            dispatch(refreshCurrentUserThunk());
        };

        const onFocus = () => refresh();
        const onVisible = () => refresh();
        const timer = setInterval(() => refresh(120000), 30000);

        window.addEventListener("focus", onFocus);
        document.addEventListener("visibilitychange", onVisible);

        return () => {
            window.removeEventListener("focus", onFocus);
            document.removeEventListener("visibilitychange", onVisible);
            clearInterval(timer);
        };

    }, [dispatch]);


    return children;

};


export default AuthInitializer;