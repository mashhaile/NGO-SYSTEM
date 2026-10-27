import { useSelector } from "react-redux";

import { selectUser } from "../features/auth/store";


// =====================================================
// THE ORGANIZATION'S MODULES
// =====================================================
//
// The platform super admin switches optional modules on or
// off per organization (backend/config/modules.js). Menus,
// pages and actions follow the user's permissions, which
// already leave out the modules that are off. This tells a
// screen to hide a field that belongs to another module,
// e.g. the donor on a project when "funding" is off.
//
// Keys: enrollments, enterprises, activities, tor,
// serviceDelivery, funding, finance.
//
// =====================================================

// permission prefix -> module (same as backend/config/modules.js)
const MODULE_OF_PREFIX = {
    enrollment: "enrollments",
    enterprise: "enterprises",
    activity: "activities",
    activity_run: "activities",
    attendance: "activities",
    attendance_record: "activities",
    tor: "tor",
    service: "serviceDelivery",
    donor: "funding",
    donation: "funding",
    budget: "finance",
    expense: "finance",
    indicator: "me",
    supplier: "procurement",
    purchase_request: "procurement"
};

export const moduleOfPermission = (permission) =>
    MODULE_OF_PREFIX[String(permission || "").split(".")[0]] || null;

// true when the module is on. A session without the module
// list (signed in before modules existed): a module is taken
// as on when the user has any of its permissions, so a module
// switched off is hidden, not shown locked.
const isOn = (user, key) => {
    if (!key) return true;
    if (Array.isArray(user?.modules)) return user.modules.includes(key);
    const permissions = Array.isArray(user?.permissions) ? user.permissions : [];
    if (!permissions.length || permissions.includes("*")) return true;
    return permissions.some(permission => moduleOfPermission(permission) === key);
};

export const useModuleOn = (key) => {
    const user = useSelector(selectUser);
    return isOn(user, key);
};

// for a list: (permission) => is its module on?
export const useModuleOfPermissionOn = () => {
    const user = useSelector(selectUser);
    return (permission) => isOn(user, moduleOfPermission(permission));
};
