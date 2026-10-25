import { useEffect, useState } from "react";

import axiosClient from "../../services/axiosClient";


// =====================================================
// ROLES (built-in + the organization's custom roles)
// =====================================================

export const getRolesApi = async () =>
    (await axiosClient.get("/roles")).data.data;

export const createRoleApi = async (data) =>
    (await axiosClient.post("/roles", data)).data.data;

export const updateRoleApi = async (id, data) =>
    (await axiosClient.put(`/roles/${id}`, data)).data.data;

export const deleteRoleApi = async (id) =>
    (await axiosClient.delete(`/roles/${id}`)).data.data;


// A custom role travels in the user form as "custom:<id>"
export const CUSTOM_PREFIX = "custom:";

export const roleValueOf = (user) =>
    user?.customRole
        ? `${CUSTOM_PREFIX}${user.customRole?._id || user.customRole}`
        : user?.role || "";

// { role } for a built-in role, { role: "viewer", customRole } for a custom one
export const rolePayload = (value) =>
    String(value || "").startsWith(CUSTOM_PREFIX)
        ? { role: "viewer", customRole: String(value).slice(CUSTOM_PREFIX.length) }
        : { role: value };


// The roles to choose from in a user form
export const useRoleOptions = () => {

    const [options, setOptions] = useState([
        { value: "data_entry", label: "Data Entry" },
        { value: "finance_officer", label: "Finance Officer" },
        { value: "viewer", label: "Viewer" },
        { value: "organization_admin", label: "Organization Admin" }
    ]);

    useEffect(() => {
        let alive = true;
        getRolesApi()
            .then(roles => {
                if (!alive) return;
                setOptions([
                    ...roles.builtIn.map(role => ({ value: role.key, label: role.name })),
                    ...roles.custom.map(role => ({ value: `${CUSTOM_PREFIX}${role._id}`, label: `${role.name} (custom)` }))
                ]);
            })
            .catch(() => {});
        return () => { alive = false; };
    }, []);

    return options;

};
