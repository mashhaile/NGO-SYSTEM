import {
    useCallback,
    useEffect,
    useState
} from "react";


import {
    Alert,
    Box,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    InputAdornment,
    Stack,
    TextField,
    Typography
} from "@mui/material";


import {
    AddLink,
    ContentCopy,
    LinkOff
} from "@mui/icons-material";


import {
    PageCard,
    FormSection,
    AppButton,
    AppIconButton,
    AppSelect,
    AppTextField,
    StatusChip,
    ConfirmDialog
} from "../../../components/ui";


import useAuth
    from "../../auth/hooks/useAuth";


import TraceTable
    from "./TraceTable";


import {
    getShareLinksApi,
    createShareLinkApi,
    revokeShareLinkApi,
    buildShareUrl
} from "../api/donorShareApi";


import {
    getDonorTraceApi,
    formatDate
} from "../api/donationTraceApi";



const EXPIRY_OPTIONS = [
    { value: 30, label: "30 days" },
    { value: 90, label: "90 days (recommended)" },
    { value: 180, label: "180 days" },
    { value: 365, label: "1 year" }
];


const canShare = (user) => {

    const permissions =
        Array.isArray(user?.permissions)
            ? user.permissions
            : [];

    return (
        permissions.includes("*") ||
        permissions.includes("donor.share")
    );

};


const errorMessage = (error, fallback) =>
    error?.response?.data?.message ||
    fallback;



// =====================================================
// DONOR SHARE LINKS
// =====================================================

const DonorShareLinksSection = ({
    donorId,
    shareBeneficiaryNames = false
}) => {

    const {
        user
    } = useAuth();

    const allowed =
        canShare(user);

    const [links, setLinks] =
        useState(null);

    const [donations, setDonations] =
        useState([]);

    const [error, setError] =
        useState("");

    const [reloadKey, setReloadKey] =
        useState(0);

    // create dialog

    const [creating, setCreating] =
        useState(false);

    const [form, setForm] =
        useState({
            donation: "",
            expiresInDays: 90,
            label: ""
        });

    const [saving, setSaving] =
        useState(false);

    const [createError, setCreateError] =
        useState("");

    const [newUrl, setNewUrl] =
        useState("");

    const [copied, setCopied] =
        useState(false);

    // revoke

    const [revokeTarget, setRevokeTarget] =
        useState(null);

    const [revoking, setRevoking] =
        useState(false);


    useEffect(() => {

        let cancelled = false;

        getShareLinksApi(donorId)

            .then(data => {
                if (!cancelled) {
                    setLinks(data);
                }
            })

            .catch(loadError => {
                if (!cancelled) {
                    setError(errorMessage(loadError, "Could not load share links."));
                }
            });

        return () => {
            cancelled = true;
        };

    }, [donorId, reloadKey]);


    useEffect(() => {

        if (!allowed) {
            return undefined;
        }

        let cancelled = false;

        getDonorTraceApi(donorId)

            .then(data => {
                if (!cancelled) {
                    setDonations(data?.donations || []);
                }
            })

            .catch(() => {});

        return () => {
            cancelled = true;
        };

    }, [donorId, allowed]);


    const openCreate = () => {

        setForm({
            donation: "",
            expiresInDays: 90,
            label: ""
        });

        setCreateError("");

        setNewUrl("");

        setCopied(false);

        setCreating(true);

    };


    const handleCreate = async () => {

        setSaving(true);

        setCreateError("");

        try {

            const result =
                await createShareLinkApi({
                    donor: donorId,
                    donation: form.donation || null,
                    expiresInDays: Number(form.expiresInDays),
                    label: form.label
                });

            setNewUrl(
                buildShareUrl(result.token)
            );

            setReloadKey(key => key + 1);

        }
        catch (saveError) {

            setCreateError(errorMessage(saveError, "Could not create the link."));

        }
        finally {

            setSaving(false);

        }

    };


    const handleCopy = useCallback(async () => {

        try {

            await navigator.clipboard.writeText(newUrl);

            setCopied(true);

        }
        catch {

            setCopied(false);

        }

    }, [newUrl]);


    const handleRevoke = async () => {

        setRevoking(true);

        try {

            await revokeShareLinkApi(revokeTarget.id);

            setRevokeTarget(null);

            setReloadKey(key => key + 1);

        }
        catch (revokeError) {

            setRevokeTarget(null);

            setError(errorMessage(revokeError, "Could not revoke the link."));

        }
        finally {

            setRevoking(false);

        }

    };


    const donationOptions = [
        {
            value: "",
            label: "All donations of this donor"
        },
        ...donations.map(donation => ({
            value: donation.id,
            label: [donation.code, donation.title].filter(Boolean).join(" - ")
        }))
    ];


    return (
        <PageCard>

            <FormSection
                title="Share with Donor"
                subtitle="Private links that let the donor see where their donations went, without an account."
            >

                <Stack
                    direction={{
                        xs: "column",
                        sm: "row"
                    }}
                    spacing={2}
                    sx={{ alignItems: {
                        xs: "flex-start",
                        sm: "center"
                    }, justifyContent: "space-between", mb: 2 }}
                >

                    <Typography variant="body2" sx={{
                        color: "text.secondary"
                    }}>
                        {shareBeneficiaryNames
                            ? "Links include beneficiary names (donor setting)."
                            : "Links show numbers only; beneficiary names are not shared."}
                    </Typography>

                    {allowed && (
                        <AppButton
                            variant="contained"
                            startIcon={<AddLink />}
                            onClick={openCreate}
                        >
                            Create Share Link
                        </AppButton>
                    )}

                </Stack>

                {error && (
                    <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError("")}>
                        {error}
                    </Alert>
                )}

                <TraceTable
                    rows={links || []}
                    empty={links ? "No share links yet." : "Loading..."}
                    columns={[
                        { key: "label", label: "Label", render: row => row.label || `…${row.tokenHint}` },
                        { key: "scope", label: "Covers", render: row => row.donation ? row.donation.code : row.scope },
                        { key: "status", label: "Status", render: row => <StatusChip status={row.status} /> },
                        { key: "expiresAt", label: "Expires", render: row => formatDate(row.expiresAt) },
                        { key: "viewCount", label: "Views", align: "right" },
                        { key: "lastViewedAt", label: "Last viewed", render: row => row.lastViewedAt ? formatDate(row.lastViewedAt) : "Never" },
                        { key: "createdBy", label: "Created by", render: row => `${row.createdBy || "-"} · ${formatDate(row.createdAt)}` },
                        {
                            key: "actions",
                            label: "",
                            align: "right",
                            render: row =>
                                allowed && row.status === "Active"
                                    ? (
                                        <AppIconButton
                                            icon={<LinkOff fontSize="small" />}
                                            tooltip="Revoke link"
                                            color="error"
                                            onClick={() => setRevokeTarget(row)}
                                        />
                                    )
                                    : null
                        }
                    ]}
                />

            </FormSection>

            {/* CREATE */}

            <Dialog
                open={creating}
                onClose={saving ? undefined : () => setCreating(false)}
                fullWidth
                maxWidth="sm"
            >

                <DialogTitle sx={{ fontWeight: 700 }}>
                    {newUrl ? "Share Link Created" : "Create Share Link"}
                </DialogTitle>

                <DialogContent>

                    {newUrl
                        ? (

                            <Box>

                                <Alert severity="warning" sx={{ mb: 2 }}>
                                    Copy this link now. For security it is shown only once; if it is lost, create a new one.
                                </Alert>

                                <TextField
                                    fullWidth
                                    size="small"
                                    value={newUrl}
                                    onFocus={(e) => e.target.select()}
                                    slotProps={{
                                        input: {
                                            readOnly: true,
                                            endAdornment: (
                                                <InputAdornment position="end">
                                                    <AppIconButton
                                                        icon={<ContentCopy fontSize="small" />}
                                                        tooltip={copied ? "Copied" : "Copy link"}
                                                        onClick={handleCopy}
                                                    />
                                                </InputAdornment>
                                            )
                                        }
                                    }}
                                />

                                {copied && (
                                    <Typography
                                        variant="body2"
                                        sx={{
                                            color: "success.main",
                                            mt: 1
                                        }}>
                                        Link copied to the clipboard.
                                    </Typography>
                                )}

                            </Box>

                        )
                        : (

                            <Box sx={{ display: "grid", gap: 2, pt: 1 }}>

                                <AppSelect
                                    label="Covers"
                                    required
                                    value={form.donation}
                                    options={donationOptions}
                                    onChange={(e) =>
                                        setForm(prev => ({ ...prev, donation: e.target.value }))
                                    }
                                />

                                <AppSelect
                                    label="Valid for"
                                    required
                                    value={form.expiresInDays}
                                    options={EXPIRY_OPTIONS}
                                    onChange={(e) =>
                                        setForm(prev => ({ ...prev, expiresInDays: e.target.value }))
                                    }
                                />

                                <AppTextField
                                    label="Label (for your reference)"
                                    placeholder="e.g. Q3 report to UNDP"
                                    value={form.label}
                                    onChange={(e) =>
                                        setForm(prev => ({ ...prev, label: e.target.value }))
                                    }
                                />

                                {createError && (
                                    <Alert severity="error">
                                        {createError}
                                    </Alert>
                                )}

                            </Box>

                        )}

                </DialogContent>

                <DialogActions sx={{ px: 3, pb: 2 }}>

                    {newUrl
                        ? (
                            <AppButton
                                variant="contained"
                                onClick={() => setCreating(false)}
                            >
                                Done
                            </AppButton>
                        )
                        : (
                            <>
                                <AppButton
                                    variant="outlined"
                                    color="inherit"
                                    onClick={() => setCreating(false)}
                                    disabled={saving}
                                >
                                    Cancel
                                </AppButton>

                                <AppButton
                                    variant="contained"
                                    loading={saving}
                                    loadingText="Creating..."
                                    onClick={handleCreate}
                                >
                                    Create Link
                                </AppButton>
                            </>
                        )}

                </DialogActions>

            </Dialog>

            {/* REVOKE */}

            <ConfirmDialog
                open={Boolean(revokeTarget)}
                title="Revoke Share Link"
                message="The donor will no longer be able to open this link. This cannot be undone."
                confirmLabel="Revoke"
                confirmColor="error"
                loading={revoking}
                onClose={() => !revoking && setRevokeTarget(null)}
                onConfirm={handleRevoke}
            />

        </PageCard>
    );

};


export default DonorShareLinksSection;
