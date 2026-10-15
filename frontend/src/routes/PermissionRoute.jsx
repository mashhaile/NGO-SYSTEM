import {
    Navigate,
    useLocation
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

    const location = useLocation();


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


    console.log(
        "========== PermissionRoute ==========",
        {
            path: location.pathname,
            requiredPermission: permission,
            permissions: permissions,
            allowed:
                permissions.includes(permission)
        }
    );


    // ==========================================================
    // PERMISSION CHECK
    // ==========================================================

    if (
        permission &&
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

    console.log(
        "Permission allowed:",
        permission
    );


    return children;

};


// ==========================================================
// DEFAULT EXPORT
// ==========================================================

export default PermissionRoute;