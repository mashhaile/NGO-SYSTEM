import {
    useEffect,
    useState
} from "react";

import {
    Alert,
    Box,
    Checkbox,
    Chip,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    FormControlLabel,
    Stack,
    Typography
} from "@mui/material";

import {
    Add,
    Delete,
    Edit
} from "@mui/icons-material";

import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    AppButton,
    AppTextField,
    LoadingState,
    ErrorState
} from "../../components/ui";

import TraceTable
    from "../donations/components/TraceTable";

import {
    getRolesApi,
    createRoleApi,
    updateRoleApi,
    deleteRoleApi
} from "./rolesApi";

import {
    getApiErrorMessage
} from "../../utils/apiError";


// =====================================================
// ROLES
// =====================================================
//
// The built-in roles (the same for every organization)
// and the organization's own roles: a name and what its
// users may do, ticked per module. A user with a custom
// role gets exactly its permissions.
//
// =====================================================

const emptyRole = { _id: null, name: "", description: "", permissions: [] };


const RoleDialog = ({ open, role, catalog, onClose, onSaved }) => {

    const [form, setForm] = useState(emptyRole);
    const [error, setError] = useState("");
    const [saving, setSaving] = useState(false);
    const [opened, setOpened] = useState(null);

    // a new role opened: start from it
    if (open && opened !== (role?._id || "new")) {
        setOpened(role?._id || "new");
        setForm(role ? { ...emptyRole, ...role } : emptyRole);
        setError("");
    }
    if (!open && opened !== null) setOpened(null);

    const has = (code) => form.permissions.includes(code);
    const toggle = (code) =>
        setForm(previous => ({
            ...previous,
            permissions: previous.permissions.includes(code)
                ? previous.permissions.filter(item => item !== code)
                : [...previous.permissions, code]
        }));
    const toggleGroup = (group, on) =>
        setForm(previous => {
            const codes = group.permissions.map(item => item.code);
            const rest = previous.permissions.filter(item => !codes.includes(item));
            return { ...previous, permissions: on ? [...rest, ...codes] : rest };
        });

    const save = async () => {
        setSaving(true);
        setError("");
        try {
            const body = { name: form.name, description: form.description, permissions: form.permissions };
            if (form._id) await updateRoleApi(form._id, body);
            else await createRoleApi(body);
            onSaved();
        }
        catch (saveError) {
            setError(getApiErrorMessage(saveError, "The role could not be saved."));
        }
        finally {
            setSaving(false);
        }
    };

    return (
        <Dialog open={open} onClose={onClose} fullWidth maxWidth="md">
            <DialogTitle>{form._id ? `Edit role: ${role?.name}` : "New role"}</DialogTitle>
            <DialogContent dividers>
                {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
                <Stack spacing={2} sx={{ mb: 3 }}>
                    <AppTextField label="Role name" required value={form.name} onChange={event => setForm({ ...form, name: event.target.value })} helperText="For example Program Manager, M&E Officer, Administrator" />
                    <AppTextField label="Description" value={form.description} onChange={event => setForm({ ...form, description: event.target.value })} />
                </Stack>
                <Typography variant="subtitle2" sx={{ mb: 1 }}>
                    What users with this role may do ({form.permissions.length} chosen)
                </Typography>
                <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "1fr 1fr" }, gap: 2 }}>
                    {catalog.map(group => {
                        const chosen = group.permissions.filter(item => has(item.code)).length;
                        return (
                            <Box key={group.module} sx={{ border: "1px solid", borderColor: "divider", borderRadius: 2, p: 1.5 }}>
                                <FormControlLabel
                                    label={<Typography sx={{ fontWeight: 600 }}>{group.label}</Typography>}
                                    control={
                                        <Checkbox
                                            checked={chosen === group.permissions.length}
                                            indeterminate={chosen > 0 && chosen < group.permissions.length}
                                            onChange={event => toggleGroup(group, event.target.checked)}
                                        />
                                    }
                                />
                                <Box sx={{ display: "flex", flexWrap: "wrap", pl: 3 }}>
                                    {group.permissions.map(item => (
                                        <FormControlLabel
                                            key={item.code}
                                            label={item.label}
                                            control={<Checkbox size="small" checked={has(item.code)} onChange={() => toggle(item.code)} />}
                                            sx={{ mr: 2 }}
                                        />
                                    ))}
                                </Box>
                            </Box>
                        );
                    })}
                </Box>
            </DialogContent>
            <DialogActions>
                <AppButton variant="outlined" onClick={onClose} disabled={saving}>Cancel</AppButton>
                <AppButton variant="contained" onClick={save} loading={saving}>Save Role</AppButton>
            </DialogActions>
        </Dialog>
    );

};


const RolesPage = () => {

    const [roles, setRoles] = useState(null);
    const [error, setError] = useState("");
    const [editing, setEditing] = useState(undefined);
    const [reload, setReload] = useState(0);

    useEffect(() => {
        let alive = true;
        getRolesApi()
            .then(data => { if (alive) setRoles(data); })
            .catch(loadError => { if (alive) setError(getApiErrorMessage(loadError, "Roles could not be loaded.")); });
        return () => { alive = false; };
    }, [reload]);

    const remove = async (role) => {
        if (!window.confirm(`Delete the role "${role.name}"?`)) return;
        try {
            await deleteRoleApi(role._id);
            setReload(value => value + 1);
        }
        catch (deleteError) {
            setError(getApiErrorMessage(deleteError, "The role could not be deleted."));
        }
    };

    const header = (
        <PageHeader
            title="Roles"
            subtitle="Who can do what. Make your own roles (Program Manager, M&E Officer ...) and give them to users."
            action={() => setEditing(null)}
            actionLabel="New Role"
            actionIcon={<Add />}
        />
    );

    if (!roles) {
        return (
            <PageContainer>
                {header}
                {error ? <ErrorState message={error} /> : <LoadingState message="Loading roles..." />}
            </PageContainer>
        );
    }

    return (
        <PageContainer>

            {header}

            {error && <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError("")}>{error}</Alert>}

            <PageCard>
                <FormSection title="Your roles" subtitle="Made by your organization. A user with one of these roles can do exactly what is ticked.">
                    <TraceTable
                        rows={roles.custom}
                        getRowKey={row => row._id}
                        empty="No roles of your own yet. Choose New Role."
                        columns={[
                            { key: "name", label: "Role", render: row => <Typography sx={{ fontWeight: 600 }}>{row.name}</Typography> },
                            { key: "description", label: "Description", render: row => row.description || "-" },
                            { key: "permissions", label: "Permissions", align: "right", render: row => row.permissions.length },
                            { key: "users", label: "Users", align: "right", render: row => row.users },
                            {
                                key: "actions",
                                label: "",
                                render: row => (
                                    <Stack direction="row" spacing={1}>
                                        <AppButton size="small" variant="outlined" startIcon={<Edit />} onClick={() => setEditing(row)}>Edit</AppButton>
                                        <AppButton size="small" variant="outlined" color="error" startIcon={<Delete />} onClick={() => remove(row)} disabled={row.users > 0}>Delete</AppButton>
                                    </Stack>
                                )
                            }
                        ]}
                    />
                </FormSection>
            </PageCard>

            <PageCard>
                <FormSection title="Built-in roles" subtitle="The same for every organization; they cannot be changed. Make your own role to give a different set of permissions.">
                    <TraceTable
                        rows={roles.builtIn}
                        getRowKey={row => row.key}
                        columns={[
                            { key: "name", label: "Role", render: row => <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}><Typography sx={{ fontWeight: 600 }}>{row.name}</Typography><Chip size="small" label="Built-in" /></Stack> },
                            { key: "description", label: "Description" },
                            { key: "permissions", label: "Permissions", align: "right", render: row => row.permissions.length },
                            { key: "users", label: "Users", align: "right", render: row => row.users },
                            { key: "copy", label: "", render: row => <AppButton size="small" variant="outlined" sx={{ whiteSpace: "nowrap" }} onClick={() => setEditing({ ...emptyRole, name: `${row.name} (copy)`, permissions: row.permissions })}>Copy as new role</AppButton> }
                        ]}
                    />
                </FormSection>
            </PageCard>

            <RoleDialog
                open={editing !== undefined}
                role={editing}
                catalog={roles.catalog}
                onClose={() => setEditing(undefined)}
                onSaved={() => { setEditing(undefined); setReload(value => value + 1); }}
            />

        </PageContainer>
    );

};


export default RolesPage;
