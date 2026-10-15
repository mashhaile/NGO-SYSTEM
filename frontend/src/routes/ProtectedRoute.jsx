import { Navigate } from "react-router-dom";

import {
    CircularProgress,
    Box
} from "@mui/material";


import {
    useAuth
} from "../features/auth";



const ProtectedRoute = ({ children }) => {


    const {

        isAuthenticated,

        initialized

    } = useAuth();



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



    return children;


};


export default ProtectedRoute;