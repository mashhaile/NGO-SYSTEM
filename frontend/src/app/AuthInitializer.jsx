import { useEffect } from "react";

import { useDispatch } from "react-redux";

import {
    loadCurrentUserThunk,
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


    return children;

};


export default AuthInitializer;