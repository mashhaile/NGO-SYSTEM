import { useEffect, useState } from "react";

import {
    Alert,
    Box,
    Chip,
    CircularProgress,
    Divider,
    Paper,
    Stack,
    Switch,
    Typography
} from "@mui/material";

import { Extension } from "@mui/icons-material";

import axiosClient from "../../../services/axiosClient";


// =====================================================
// MODULES OF AN ORGANIZATION (super admin)
// =====================================================
//
// Switch optional modules on or off for this organization.
// Off is hidden, never deleted: the organization no longer
// sees the module, and gets all its data back when it is
// switched on again. A module that needs another one (TOR
// needs activities) is off while that one is.
//
// =====================================================

const recordsText = (records = []) =>
    records
        .filter(item => item.count !== null && item.count !== undefined)
        .map(item => `${item.count} ${item.label}`)
        .join(" · ");


const OrganizationModulesCard = ({ organizationId }) => {

    const [data, setData] = useState(null);
    const [error, setError] = useState("");
    const [saving, setSaving] = useState("");
    const [saved, setSaved] = useState("");

    useEffect(() => {
        if (!organizationId) return undefined;
        let alive = true;
        axiosClient.get(`/admin/organizations/${organizationId}/modules`)
            .then(response => { if (alive) setData(response.data?.data || null); })
            .catch(loadError => { if (alive) setError(loadError?.response?.data?.message || "The modules could not be loaded."); });
        return () => { alive = false; };
    }, [organizationId]);

    const toggle = async (module, on) => {
        const counts = recordsText(module.records);
        if (!on && counts && !window.confirm(`Switch off "${module.name}"?\n\nThis organization has ${counts}. They will be hidden, not deleted, and come back when the module is switched on again.`)) {
            return;
        }
        setSaving(module.key);
        setError("");
        setSaved("");
        try {
            const response = await axiosClient.put(`/admin/organizations/${organizationId}/modules`, { modules: { [module.key]: on } });
            setData(response.data?.data || null);
            setSaved(`${module.name} switched ${on ? "on" : "off"}. The organization's users see the change at their next page load.`);
        }
        catch (saveError) {
            setError(saveError?.response?.data?.message || "The module could not be changed.");
        }
        finally {
            setSaving("");
        }
    };

    const nameOf = (key) => data?.modules.find(module => module.key === key)?.name || key;

    return (
        <Paper variant="outlined" sx={{ p: 3, borderRadius: 3, mt: 3 }}>

            <Stack direction="row" spacing={1.5} sx={{ alignItems: "center", mb: 0.5 }}>
                <Extension color="primary" />
                <Typography variant="h6" sx={{ fontWeight: 700 }}>Modules</Typography>
            </Stack>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Switch modules on or off for this organization. Beneficiaries, programs, projects, reports and settings are always on.
                A module that is off is hidden from the organization, never deleted.
            </Typography>

            {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
            {saved && <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSaved("")}>{saved}</Alert>}

            {!data && !error && <Box sx={{ py: 3, textAlign: "center" }}><CircularProgress size={24} /></Box>}

            {data && (
                <Stack divider={<Divider flexItem />}>
                    {data.modules.map(module => {
                        const blockedBy = module.switchedOn && !module.enabled
                            ? module.requires.filter(key => !data.modules.find(item => item.key === key)?.enabled)
                            : [];
                        return (
                            <Stack
                                key={module.key}
                                direction={{ xs: "column", sm: "row" }}
                                spacing={1.5}
                                sx={{ py: 1.5, alignItems: { sm: "center" } }}
                            >
                                <Box sx={{ flex: 1, minWidth: 0 }}>
                                    <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap" }}>
                                        <Typography sx={{ fontWeight: 600 }}>{module.name}</Typography>
                                        <Chip size="small" label={module.group} variant="outlined" />
                                        {module.enabled
                                            ? <Chip size="small" color="success" label="On" />
                                            : <Chip size="small" label="Off" />}
                                    </Stack>
                                    <Typography variant="body2" color="text.secondary">{module.description}</Typography>
                                    <Typography variant="caption" color="text.secondary">
                                        {recordsText(module.records) || "No records yet"}
                                        {module.requires.length ? ` · Needs: ${module.requires.map(nameOf).join(", ")}` : ""}
                                    </Typography>
                                    {blockedBy.length > 0 && (
                                        <Typography variant="caption" color="warning.main" sx={{ display: "block" }}>
                                            Off because {blockedBy.map(nameOf).join(", ")} {blockedBy.length === 1 ? "is" : "are"} off.
                                        </Typography>
                                    )}
                                </Box>
                                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                    {saving === module.key && <CircularProgress size={18} />}
                                    <Switch
                                        checked={Boolean(module.switchedOn)}
                                        disabled={Boolean(saving)}
                                        onChange={(event) => toggle(module, event.target.checked)}
                                        inputProps={{ "aria-label": `${module.name} on or off` }}
                                    />
                                </Box>
                            </Stack>
                        );
                    })}
                </Stack>
            )}

        </Paper>
    );

};

export default OrganizationModulesCard;
