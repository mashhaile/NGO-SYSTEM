import {
    Navigate,
    useNavigate
} from "react-router-dom";

import useAuth
    from "../features/auth/hooks/useAuth";

import {
    PageContainer,
    ErrorState
} from "../components/ui";

import {
    moduleOfPermission
} from "../utils/modules";


// ==========================================================
// PERMISSION ROUTE
// ==========================================================
//
// Shows the page only when the user's role has the
// permission (the API checks it again). Otherwise a clear
// "no access" message instead of a broken page or a silent
// jump to the dashboard.
//
// ==========================================================

const NoAccess = ({ moduleOff = false }) => {

    const navigate = useNavigate();

    return (
        <PageContainer>
            <ErrorState
                title={moduleOff ? "This module is not switched on" : "You don't have access to this page"}
                message={
                    moduleOff
                        ? "This part of the system is not switched on for your organization. Ask the platform administrator if you need it."
                        : "Your role does not include this part of the system. Ask your organization administrator if you need it."
                }
                action={() => navigate("/dashboard")}
                actionLabel="Go to Dashboard"
            />
        </PageContainer>
    );

};


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


    // Wait for the session to load
    if (loading || !initialized) {
        return null;
    }

    if (!isAuthenticated || !user) {
        return <Navigate to="/login" replace />;
    }

    const permissions =
        Array.isArray(user.permissions)
            ? user.permissions
            : [];

    // "*" = super admin (all permissions)
    if (
        permission &&
        !permissions.includes("*") &&
        !permissions.includes(permission)
    ) {
        // the module is off for the organization, or the role lacks it
        const module = moduleOfPermission(permission);
        const moduleOff = Boolean(module) && Array.isArray(user.modules) && !user.modules.includes(module);
        return <NoAccess moduleOff={moduleOff} />;
    }

    return children;

};


export default PermissionRoute;
