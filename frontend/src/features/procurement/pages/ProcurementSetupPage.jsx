import {
    useCallback,
    useEffect,
    useState
} from "react";

import {
    Alert,
    Box,
    Checkbox,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    FormControlLabel,
    IconButton,
    Stack,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Tooltip,
    Typography
} from "@mui/material";

import {
    Add,
    DeleteOutlined,
    Edit,
    Gavel,
    RestartAlt,
    Save
} from "@mui/icons-material";

import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    FormGrid,
    AppButton,
    AppIconButton,
    AppSelect,
    AppTextField,
    StatusChip,
    ConfirmDeleteDialog,
    LoadingState
} from "../../../components/ui";

import useAuth
    from "../../auth/hooks/useAuth";

import {
    getProcurementSettingsApi,
    updateProcurementSettingsApi,
    getCommitteesApi,
    getCommitteeMemberOptionsApi,
    createCommitteeApi,
    updateCommitteeApi,
    deleteCommitteeApi
} from "../api/procurementApi";

import {
    getApiErrorMessage
} from "../../budgets/api/budgetApi";

import {
    hasPermission
} from "../../budgets/utils/budgetUtils";

import {
    METHOD_KEYS,
    COMMITTEE_ROLES,
    idOf
} from "../utils/procurementUtils";


const amount = (value) => Number(value || 0).toLocaleString("en-US");


// =====================================================
// METHODS BY AMOUNT (organization admin)
// =====================================================

const MethodsCard = ({ canEdit }) => {

    const [settings, setSettings] = useState(null);
    const [draft, setDraft] = useState(null);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState("");
    const [saved, setSaved] = useState("");

    useEffect(() => {
        getProcurementSettingsApi().then(setSettings).catch(err => setError(getApiErrorMessage(err, "Failed to load the settings.")));
    }, []);

    if (!settings) return <PageCard>{error ? <Alert severity="error">{error}</Alert> : <LoadingState message="Loading..." />}</PageCard>;

    const shown = draft || settings.methods;
    const change = (key, patch) => setDraft({ ...shown, [key]: { ...shown[key], ...patch } });

    const isDefault = METHOD_KEYS.every(key =>
        ["upTo", "minQuotes", "committee"].every(field => settings.methods[key][field] === settings.defaults[key][field]));

    const send = async (body, message) => {
        setBusy(true);
        setError("");
        setSaved("");
        try {
            setSettings(await updateProcurementSettingsApi(body));
            setDraft(null);
            setSaved(message);
        }
        catch (err) {
            setError(getApiErrorMessage(err, "The settings could not be saved."));
        }
        finally {
            setBusy(false);
        }
    };

    const save = () => send({
        methods: Object.fromEntries(METHOD_KEYS.map(key => [key, {
            ...(key === "tender" ? {} : { upTo: Number(shown[key].upTo) }),
            minQuotes: Number(shown[key].minQuotes),
            committee: Boolean(shown[key].committee)
        }]))
    }, "Saved. Quotations started from now on use these limits.");

    const { direct, rfq } = shown;

    return (
        <PageCard>
            <FormSection
                title="Procurement Methods by Amount"
                subtitle={`The request's value in ${settings.currency} decides the method: how many quotations are needed and who approves the choice. A bid analysis already started keeps its method.`}
            >
                {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
                {saved && <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSaved("")}>{saved}</Alert>}

                <TableContainer sx={{ border: "1px solid", borderColor: "divider", borderRadius: 2 }}>
                    <Table size="small">
                        <TableHead>
                            <TableRow>
                                <TableCell>Method</TableCell>
                                <TableCell>Amount ({settings.currency})</TableCell>
                                <TableCell>Quotations needed</TableCell>
                                <TableCell>Approved by</TableCell>
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {METHOD_KEYS.map(key => {
                                const method = shown[key];
                                const from = key === "direct" ? 0 : key === "rfq" ? Number(direct.upTo) : Number(rfq.upTo);
                                return (
                                    <TableRow key={key}>
                                        <TableCell sx={{ fontWeight: 600 }}>{settings.methods[key].name}</TableCell>
                                        <TableCell>
                                            {key === "tender"
                                                ? <Typography variant="body2">Above {amount(from)}</Typography>
                                                : (
                                                    <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                                                        <Typography variant="body2" sx={{ whiteSpace: "nowrap" }}>{key === "direct" ? "Up to" : `Above ${amount(from)}, up to`}</Typography>
                                                        <AppTextField
                                                            type="number"
                                                            value={method.upTo ?? ""}
                                                            disabled={!canEdit}
                                                            onChange={(e) => change(key, { upTo: e.target.value })}
                                                            inputProps={{ min: 1, step: 1000, "aria-label": `${settings.methods[key].name} up to` }}
                                                            sx={{ width: 150 }}
                                                            fullWidth={false}
                                                        />
                                                    </Stack>
                                                )}
                                        </TableCell>
                                        <TableCell>
                                            <AppTextField
                                                type="number"
                                                value={method.minQuotes}
                                                disabled={!canEdit}
                                                onChange={(e) => change(key, { minQuotes: e.target.value })}
                                                inputProps={{ min: 1, max: 10, step: 1, "aria-label": `${settings.methods[key].name} quotations` }}
                                                sx={{ width: 90 }}
                                                fullWidth={false}
                                            />
                                        </TableCell>
                                        <TableCell>
                                            <FormControlLabel
                                                control={<Checkbox checked={Boolean(method.committee)} disabled={!canEdit} onChange={(e) => change(key, { committee: e.target.checked })} />}
                                                label={method.committee ? "A committee" : "An approver"}
                                            />
                                        </TableCell>
                                    </TableRow>
                                );
                            })}
                        </TableBody>
                    </Table>
                </TableContainer>

                {canEdit
                    ? (
                        <Stack direction="row" spacing={1} sx={{ mt: 2, justifyContent: "flex-end", alignItems: "center" }}>
                            <Tooltip title={`Set to default (direct up to ${amount(settings.defaults.direct.upTo)}, RFQ up to ${amount(settings.defaults.rfq.upTo)}, tender above; 1 / 3 / 3 quotations; committee for tenders)`}>
                                <span>
                                    <IconButton
                                        aria-label="Set the procurement methods to default"
                                        disabled={(isDefault && !draft) || busy}
                                        onClick={() => send({ reset: true }, "Back to the defaults.")}
                                    >
                                        <RestartAlt />
                                    </IconButton>
                                </span>
                            </Tooltip>
                            <AppButton variant="contained" startIcon={<Save />} loading={busy} disabled={!draft} onClick={save}>
                                Save
                            </AppButton>
                        </Stack>
                    )
                    : (
                        <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
                            Only the organization admin changes these.
                        </Typography>
                    )}
            </FormSection>
        </PageCard>
    );

};


// =====================================================
// A COMMITTEE (add / edit)
// =====================================================

const CommitteeDialog = ({ open, committee, people, loading, error, onClose, onSave }) => {

    const [form, setForm] = useState(() => ({
        name: committee?.name || "",
        description: committee?.description || "",
        members: (committee?.members || []).map(member => ({ user: idOf(member.user), role: member.role })),
        approvalsNeeded: committee ? String(committee.approvalsNeeded) : "",
        status: committee?.status || "Active"
    }));

    const change = (patch) => setForm(prev => ({ ...prev, ...patch }));
    const changeMember = (index, patch) => change({ members: form.members.map((member, i) => (i === index ? { ...member, ...patch } : member)) });

    const chosen = new Set(form.members.map(member => member.user));
    const count = form.members.filter(member => member.user).length;
    const majority = Math.floor(count / 2) + 1;

    return (
        <Dialog open={open} onClose={loading ? undefined : onClose} fullWidth maxWidth="sm">
            <DialogTitle sx={{ fontWeight: 700 }}>{committee ? "Edit Committee" : "Add Committee"}</DialogTitle>
            <DialogContent>
                {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
                <Box sx={{ mt: 1 }}>
                    <AppTextField label="Name" required placeholder="e.g. Tender Committee, Bid Evaluation Committee" value={form.name} onChange={(e) => change({ name: e.target.value })} />
                </Box>
                <Box sx={{ mt: 2 }}>
                    <AppTextField label="What it decides" value={form.description} onChange={(e) => change({ description: e.target.value })} placeholder="e.g. tenders above 300,000 ETB for the Adama office" />
                </Box>

                <Typography variant="subtitle2" sx={{ mt: 3, mb: 1 }}>Members</Typography>
                <Stack spacing={1.5}>
                    {form.members.map((member, index) => (
                        <Stack key={index} direction="row" spacing={1} sx={{ alignItems: "center" }}>
                            <Box sx={{ flex: 1 }}>
                                <AppSelect
                                    label={`Member ${index + 1}`}
                                    value={member.user}
                                    onChange={(e) => changeMember(index, { user: e.target.value })}
                                    options={people.filter(person => person._id === member.user || !chosen.has(person._id)).map(person => ({ value: person._id, label: `${person.name} (${person.email})` }))}
                                />
                            </Box>
                            <Box sx={{ width: 140 }}>
                                <AppSelect
                                    label="Role"
                                    value={member.role}
                                    onChange={(e) => changeMember(index, { role: e.target.value })}
                                    options={COMMITTEE_ROLES.map(value => ({ value, label: value }))}
                                />
                            </Box>
                            <AppIconButton icon={<DeleteOutlined fontSize="small" />} tooltip="Remove member" color="error" onClick={() => change({ members: form.members.filter((_, i) => i !== index) })} />
                        </Stack>
                    ))}
                </Stack>
                <AppButton variant="outlined" startIcon={<Add />} sx={{ mt: 1.5 }} onClick={() => change({ members: [...form.members, { user: "", role: form.members.length ? "Member" : "Chair" }] })}>
                    Add Member
                </AppButton>

                <Box sx={{ mt: 3 }}>
                    <FormGrid columns={2}>
                        <AppTextField
                            label="Approvals needed"
                            type="number"
                            value={form.approvalsNeeded}
                            onChange={(e) => change({ approvalsNeeded: e.target.value })}
                            inputProps={{ min: 1, max: Math.max(1, count), step: 1 }}
                            helperText={count ? `1 to ${count}. Empty: a majority (${majority} of ${count}).` : "Add the members first"}
                        />
                        {committee
                            ? (
                                <AppSelect
                                    label="Status"
                                    value={form.status}
                                    onChange={(e) => change({ status: e.target.value })}
                                    options={["Active", "Inactive"].map(value => ({ value, label: value }))}
                                    helperText="Inactive committees are not offered for new bid analyses"
                                />
                            )
                            : <Box />}
                    </FormGrid>
                </Box>
            </DialogContent>
            <DialogActions sx={{ px: 3, pb: 2 }}>
                <AppButton variant="outlined" onClick={onClose} disabled={loading}>Cancel</AppButton>
                <AppButton
                    variant="contained"
                    loading={loading}
                    disabled={form.name.trim().length < 3 || !count}
                    onClick={() => onSave({
                        name: form.name.trim(),
                        description: form.description.trim(),
                        members: form.members.filter(member => member.user),
                        approvalsNeeded: form.approvalsNeeded === "" ? null : Number(form.approvalsNeeded),
                        ...(committee ? { status: form.status } : {})
                    })}
                >
                    {committee ? "Save Committee" : "Add Committee"}
                </AppButton>
            </DialogActions>
        </Dialog>
    );

};


// =====================================================
// COMMITTEES
// =====================================================

const CommitteesCard = ({ user }) => {

    const [committees, setCommittees] = useState(null);
    const [people, setPeople] = useState([]);
    const [error, setError] = useState("");
    const [dialog, setDialog] = useState(null);
    const [dialogKey, setDialogKey] = useState(0);
    const [dialogError, setDialogError] = useState("");
    const [busy, setBusy] = useState(false);

    const canCreate = hasPermission(user, "committee.create");
    const canUpdate = hasPermission(user, "committee.update");
    const canDelete = hasPermission(user, "committee.delete");

    const load = useCallback(() =>
        getCommitteesApi()
            .then(setCommittees)
            .catch(err => setError(getApiErrorMessage(err, "Failed to load the committees."))),
    []);

    useEffect(() => {
        load();
        getCommitteeMemberOptionsApi().then(setPeople).catch(() => setPeople([]));
    }, [load]);

    const open = (kind, committee = null) => {
        setDialogError("");
        setDialogKey(key => key + 1);
        setDialog({ kind, committee });
    };

    const run = async (action) => {
        setBusy(true);
        setDialogError("");
        try {
            await action();
            setDialog(null);
            await load();
        }
        catch (err) {
            setDialogError(getApiErrorMessage(err, "The action failed."));
            if (dialog?.kind === "delete") {
                setError(getApiErrorMessage(err, "The committee could not be deleted."));
                setDialog(null);
            }
        }
        finally {
            setBusy(false);
        }
    };

    return (
        <PageCard>
            <FormSection
                title="Procurement Committees"
                subtitle="Committees approve the bid analyses of the methods that need one. Each has its members and how many of them must approve."
            >
                {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError("")}>{error}</Alert>}

                {committees === null
                    ? <LoadingState message="Loading..." />
                    : committees.length === 0
                        ? <Typography variant="body2" color="text.secondary">No committees yet.</Typography>
                        : (
                            <Stack spacing={1.5}>
                                {committees.map(committee => (
                                    <Box key={committee._id} sx={{ p: 2, border: "1px solid", borderColor: "divider", borderRadius: 2 }}>
                                        <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                                            <Gavel color="primary" fontSize="small" />
                                            <Typography sx={{ fontWeight: 700, flex: 1 }}>{committee.name}</Typography>
                                            <StatusChip status={committee.status} />
                                            {canUpdate && <AppIconButton icon={<Edit fontSize="small" />} tooltip="Edit committee" onClick={() => open("edit", committee)} />}
                                            {canDelete && <AppIconButton icon={<DeleteOutlined fontSize="small" />} tooltip="Delete committee" color="error" onClick={() => open("delete", committee)} />}
                                        </Stack>
                                        {committee.description && <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>{committee.description}</Typography>}
                                        <Typography variant="body2" sx={{ mt: 1 }}>
                                            {committee.members.map(member => `${member.user?.name || "?"}${member.role !== "Member" ? ` (${member.role})` : ""}`).join(", ")}
                                        </Typography>
                                        <Typography variant="caption" color="text.secondary">
                                            {committee.approvalsNeeded} of {committee.members.length} must approve
                                        </Typography>
                                    </Box>
                                ))}
                            </Stack>
                        )}

                {canCreate && (
                    <AppButton variant="outlined" startIcon={<Add />} sx={{ mt: 2 }} onClick={() => open("add")}>
                        Add Committee
                    </AppButton>
                )}
            </FormSection>

            {dialog && dialog.kind !== "delete" && (
                <CommitteeDialog
                    key={dialogKey}
                    open
                    committee={dialog.committee}
                    people={people}
                    loading={busy}
                    error={dialogError}
                    onClose={() => !busy && setDialog(null)}
                    onSave={(body) => run(() => (dialog.committee ? updateCommitteeApi(dialog.committee._id, body) : createCommitteeApi(body)))}
                />
            )}

            <ConfirmDeleteDialog
                open={dialog?.kind === "delete"}
                title="Delete Committee"
                message={dialog?.committee ? `Delete "${dialog.committee.name}"? Bid analyses it already decided keep its decision.` : ""}
                loading={busy}
                onClose={() => !busy && setDialog(null)}
                onConfirm={() => run(() => deleteCommitteeApi(dialog.committee._id))}
            />
        </PageCard>
    );

};


// =====================================================
// PROCUREMENT SETUP PAGE
// =====================================================

const ProcurementSetupPage = () => {

    const { user } = useAuth();

    return (
        <PageContainer>
            <PageHeader
                title="Procurement Setup"
                subtitle="How much each method allows, how many quotations it needs, and the committees that approve."
            />
            <MethodsCard canEdit={hasPermission(user, "organization.update")} />
            <CommitteesCard user={user} />
        </PageContainer>
    );

};


export default ProcurementSetupPage;
