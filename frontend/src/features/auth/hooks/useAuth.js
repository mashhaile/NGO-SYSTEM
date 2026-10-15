import { useSelector } from "react-redux";

import {
    selectUser,
    selectIsAuthenticated,
    selectAuthLoading,
    selectAuthInitialized
} from "../store";


const useAuth = () => {

    const user = useSelector(selectUser);

    const isAuthenticated =
        useSelector(selectIsAuthenticated);

    const loading =
        useSelector(selectAuthLoading);

    const initialized =
        useSelector(selectAuthInitialized);


    return {

        user,

        isAuthenticated,

        loading,

        initialized

    };

};


export default useAuth;