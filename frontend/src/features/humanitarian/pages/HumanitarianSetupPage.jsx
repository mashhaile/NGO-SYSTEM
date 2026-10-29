import {
    useEffect,
    useState
} from "react";

import {
    Alert,
    Checkbox,
    FormControlLabel,
    IconButton,
    Stack,
    Tooltip,
    Typography
} from "@mui/material";

import {
    RestartAlt,
    Save
} from "@mui/icons-material";

import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    FormGrid,
    AppSelect,
    AppTextField,
    AppButton,
    LoadingState
} from "../../../components/ui";

import axiosClient
    from "../../../services/axiosClient";

import { getApiErrorMessage } from "../../../utils/apiError";
import { hasPermission } from "../../../utils/permissions";
import useAuth from "../../auth/hooks/useAuth";


const PERIODS = [
    { value: "day", label: "The same day" },
    { value: "week", label: "The same week (Monday - Sunday)" },
    { value: "month", label: "The same month" },
    { value: "days", label: "Within a number of days" },
    { value: "project", label: "Once per project" }
];


// =====================================================
// HUMANITARIAN SETUP: THE DUPLICATE CHECK
// =====================================================

const HumanitarianSetupPage = () => {

    const { user } = useAuth();
    const canEdit = hasPermission(user, "organization.update");

    const [settings, setSettings] = useState(null);
    const [draft, setDraft] = useState(null);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState("");
    const [saved, setSaved] = useState("");

    useEffect(() => {
        axiosClient.get("/humanitarian/settings")
            .then(response => setSettings(response.data?.data))
            .catch(err => setError(getApiErrorMessage(err, "The settings could not be loaded.")));
    }, []);

    const send = async (body, message) => {
        setBusy(true);
        setError("");
        setSaved("");
        try {
            const response = await axiosClient.put("/humanitarian/settings", body);
            setSettings(response.data?.data);
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

    const header = (
        <PageHeader
            title="Humanitarian Setup"
            subtitle="How distributions are checked so the same person does not receive the same service twice."
        />
    );

    if (!settings) {
        return <PageContainer>{header}<PageCard>{error ? <Alert severity="error">{error}</Alert> : <LoadingState message="Loading..." />}</PageCard></PageContainer>;
    }

    const rule = draft || settings.duplicateCheck;
    const change = (patch) => setDraft({ ...rule, ...patch });
    const isDefault = ["enabled", "period", "days", "sameProject"].every(key => settings.duplicateCheck[key] === settings.defaults[key]);

    return (

        <PageContainer>

            {header}

            <PageCard>
                <FormSection
                    title="Duplicate check on distributions"
                    subtitle="When a delivery gives a person a service (e.g. a food basket) they already received in the period, it is stopped with the list of earlier deliveries. Staff can still save it with a reason; it is then listed in the 3W report."
                >
                    {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
                    {saved && <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSaved("")}>{saved}</Alert>}

                    <FormControlLabel
                        control={<Checkbox checked={Boolean(rule.enabled)} disabled={!canEdit} onChange={(e) => change({ enabled: e.target.checked })} />}
                        label={<Typography sx={{ fontWeight: 700 }}>Check for duplicates</Typography>}
                    />

                    {rule.enabled && (
                        <FormGrid columns={3}>
                            <AppSelect
                                label="The same service only once in"
                                value={rule.period}
                                disabled={!canEdit}
                                onChange={(e) => change({ period: e.target.value })}
                                options={PERIODS}
                            />
                            {rule.period === "days"
                                ? (
                                    <AppTextField
                                        label="Days"
                                        type="number"
                                        value={rule.days}
                                        disabled={!canEdit}
                                        onChange={(e) => change({ days: e.target.value })}
                                        inputProps={{ min: 1, max: 365, step: 1 }}
                                    />
                                )
                                : <span />}
                            <FormControlLabel
                                control={<Checkbox checked={Boolean(rule.sameProject) || rule.period === "project"} disabled={!canEdit || rule.period === "project"} onChange={(e) => change({ sameProject: e.target.checked })} />}
                                label="Only deliveries of the same project count"
                            />
                        </FormGrid>
                    )}

                    {canEdit
                        ? (
                            <Stack direction="row" spacing={1} sx={{ mt: 2, justifyContent: "flex-end", alignItems: "center" }}>
                                <Tooltip title="Set to default (the same month, any project)">
                                    <span>
                                        <IconButton aria-label="Set the duplicate check to default" disabled={(isDefault && !draft) || busy} onClick={() => send({ reset: true }, "Back to the defaults.")}>
                                            <RestartAlt />
                                        </IconButton>
                                    </span>
                                </Tooltip>
                                <AppButton
                                    variant="contained"
                                    startIcon={<Save />}
                                    loading={busy}
                                    disabled={!draft}
                                    onClick={() => send({ duplicateCheck: { ...rule, days: Number(rule.days) } }, "Saved. New and edited deliveries are checked this way.")}
                                >
                                    Save
                                </AppButton>
                            </Stack>
                        )
                        : (
                            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
                                Only the organization admin changes this.
                            </Typography>
                        )}
                </FormSection>
            </PageCard>

        </PageContainer>

    );

};


export default HumanitarianSetupPage;
