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
    expense: "finance"
};

export const moduleOfPermission = (permission) =>
    MODULE_OF_PREFIX[String(permission || "").split(".")[0]] || null;

// true when the module is on (or not known yet: older sign-in)
const isOn = (modules, key) =>
    !key || !Array.isArray(modules) || modules.includes(key);

export const useModuleOn = (key) => {
    const user = useSelector(selectUser);
    return isOn(user?.modules, key);
};

// for a list: (permission) => is its module on?
export const useModuleOfPermissionOn = () => {
    const user = useSelector(selectUser);
    return (permission) => isOn(user?.modules, moduleOfPermission(permission));
};
