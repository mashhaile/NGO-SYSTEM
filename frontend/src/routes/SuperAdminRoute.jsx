import { Navigate } from "react-router-dom";

import {
    CircularProgress,
    Box
} from "@mui/material";

import useAuth
    from "../features/auth/hooks/useAuth";


const SuperAdminRoute = ({ children }) => {

    const {
        user,
        initialized,
        isAuthenticated
    } = useAuth();


    // ==========================================
    // AUTH INITIALIZATION
    // ==========================================

    if (!initialized) {

        return (

            <Box
                sx={{
                    display: "flex",
                    justifyContent: "center",
                    alignItems: "center",
                    height: "100vh"
                }}
            >

                <CircularProgress />

            </Box>

        );

    }


    // ==========================================
    // NOT AUTHENTICATED
    // ==========================================

    if (!isAuthenticated) {

        return (

            <Navigate
                to="/login"
                replace
            />

        );

    }


    // ==========================================
    // SUPER ADMIN ONLY
    // ==========================================

    if (
        user?.role !== "super_admin"
    ) {

        return (

            <Navigate
                to="/dashboard"
                replace
            />

        );

    }


    return children;

};


export default SuperAdminRoute;