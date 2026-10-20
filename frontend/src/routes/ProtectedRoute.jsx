import {
    Navigate,
    useLocation
} from "react-router-dom";

import {
    CircularProgress,
    Box
} from "@mui/material";


import {
    useAuth
} from "../features/auth";



const ProtectedRoute = ({ children }) => {


    const {

        user,

        isAuthenticated,

        initialized

    } = useAuth();


    const location =
        useLocation();



    if (!initialized) {

        return (

            <Box
                sx={{
                    display:"flex",
                    justifyContent:"center",
                    alignItems:"center",
                    height:"100vh"
                }}
            >

                <CircularProgress />

            </Box>

        );

    }



    if (!isAuthenticated) {

        return (

            <Navigate

                to="/login"

                replace

            />

        );

    }



    // Temporary password from an admin reset:
    // nothing else until it is changed

    if (
        user?.mustChangePassword &&
        location.pathname !== "/account/password"
    ) {

        return (

            <Navigate
                to="/account/password"
                replace
            />

        );

    }



    return children;


};


export default ProtectedRoute;