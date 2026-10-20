import {
    Navigate
} from "react-router-dom";

import useAuth
    from "../features/auth/hooks/useAuth";


const PermissionRoute = ({
    children,
    permission
}) => {

    const {
        user,
        isAuthenticated,
        loading,
        initialized
    } = useAuth();

    // ==========================================================
    // WAIT FOR AUTH INITIALIZATION
    // ==========================================================

    if (
        loading ||
        !initialized
    ) {

        return null;

    }


    // ==========================================================
    // NOT AUTHENTICATED
    // ==========================================================

    if (
        !isAuthenticated ||
        !user
    ) {

        return (
            <Navigate
                to="/login"
                replace
            />
        );

    }


    // ==========================================================
    // USER PERMISSIONS
    // ==========================================================

    const permissions =
        Array.isArray(user.permissions)
            ? user.permissions
            : [];




    // ==========================================================
    // PERMISSION CHECK
    // ==========================================================

    // "*" = super admin (all permissions)

    if (
        permission &&
        !permissions.includes("*") &&
        !permissions.includes(permission)
    ) {

        console.warn(
            "Permission denied:",
            permission
        );

        return (
            <Navigate
                to="/dashboard"
                replace
            />
        );

    }


    // ==========================================================
    // ALLOWED
    // ==========================================================



    return children;

};


// ==========================================================
// DEFAULT EXPORT
// ==========================================================

export default PermissionRoute;