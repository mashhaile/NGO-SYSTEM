import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

import {
    Alert,
    Box,
    IconButton,
    Stack,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    TextField,
    Tooltip,
    Typography
} from "@mui/material";
import { Delete, Edit, Save } from "@mui/icons-material";

import {
    AppButton,
    ConfirmDeleteDialog,
    FormSection,
    InfoRow,
    LoadingState,
    PageCard,
    PageContainer,
    PageHeader,
    StatusChip
} from "../../../components/ui";

import useAuth from "../../auth/hooks/useAuth";
import { getApiErrorMessage } from "../../../utils/apiError";
import { formatDate } from "../../../utils/date";

import {
    deleteIndicatorApi,
    deleteIndicatorValueApi,
    getIndicatorApi,
    setIndicatorValueApi
} from "../api/indicatorApi";

import { nameOf, percentText, periodLabel, periodsOf, statusHelp, valueText } from "../utils/indicatorUtils";
import { useMeLimits } from "../indicatorHooks";


// =====================================================
// ONE INDICATOR: ITS PROGRESS PER PERIOD
// =====================================================
//
// A row per period: target, actual, % achieved, status.
// Automatic indicators are counted by the system; entered
// ones get their value typed here (with female / male and a
// note) by those allowed to report.
//
// =====================================================

const can = (user, permission) =>
    (user?.permissions || []).includes("*") || (user?.permissions || []).includes(permission);

const cellSx = { whiteSpace: "nowrap" };


const IndicatorDetailsPage = () => {

    const { id } = useParams();
    const navigate = useNavigate();
    const { user } = useAuth();

    const [indicator, setIndicator] = useState(null);
    const [error, setError] = useState("");
    const [saved, setSaved] = useState("");
    const [drafts, setDrafts] = useState({});
    const [saving, setSaving] = useState("");
    const [confirmDelete, setConfirmDelete] = useState(false);
    const [limits] = useMeLimits();

    const load = useCallback(async () => {
        try {
            setIndicator(await getIndicatorApi(id));
        }
        catch (loadError) {
            setError(getApiErrorMessage(loadError, "The indicator could not be loaded."));
        }
    }, [id]);

    useEffect(() => {
        const timer = setTimeout(load, 0);
        return () => clearTimeout(timer);
    }, [load]);

    const manual = indicator?.source === "manual";
    const mayReport = manual && can(user, "indicator.report");

    // rows: every period with a target or a value, and (to
    // enter values) every period of those years that has started
    const rows = useMemo(() => {
        if (!indicator) return [];
        const byPeriod = new Map((indicator.progress?.rows || []).map(row => [row.period, row]));
        if (mayReport) {
            const years = [...byPeriod.keys()].map(period => Number(String(period).slice(0, 4)));
            const from = years.length ? Math.min(...years) : new Date().getFullYear();
            const to = years.length ? Math.max(...years) : from;
            const today = new Date();
            for (const period of periodsOf(indicator.frequency, from, to)) {
                if (byPeriod.has(period)) continue;
                const start = period.length === 4 ? new Date(`${period}-01-01`)
                    : period.includes("Q") ? new Date(`${period.slice(0, 4)}-${String((Number(period.slice(-1)) - 1) * 3 + 1).padStart(2, "0")}-01`)
                        : new Date(`${period}-01`);
                if (start <= today) byPeriod.set(period, { period, target: null, actual: null, percent: null, status: "No data", started: true });
            }
        }
        return [...byPeriod.values()].sort((a, b) => a.period.localeCompare(b.period));
    }, [indicator, mayReport]);

    const draftOf = (row) => drafts[row.period] || {
        value: row.actual ?? "",
        female: row.female ?? "",
        male: row.male ?? "",
        notes: row.notes || ""
    };

    const setDraft = (period, patch, row) =>
        setDrafts(previous => ({ ...previous, [period]: { ...draftOf(row), ...previous[period], ...patch } }));

    const saveValue = async (row) => {
        setError("");
        setSaved("");
        setSaving(row.period);
        try {
            const updated = await setIndicatorValueApi(id, row.period, draftOf(row));
            setIndicator(updated);
            setDrafts(previous => { const next = { ...previous }; delete next[row.period]; return next; });
            setSaved(`${periodLabel(row.period)} saved.`);
        }
        catch (saveError) {
            setError(getApiErrorMessage(saveError, "The value could not be saved."));
        }
        finally {
            setSaving("");
        }
    };

    const removeValue = async (row) => {
        setError("");
        setSaving(row.period);
        try {
            setIndicator(await deleteIndicatorValueApi(id, row.period));
            setDrafts(previous => { const next = { ...previous }; delete next[row.period]; return next; });
        }
        catch (removeError) {
            setError(getApiErrorMessage(removeError, "The value could not be removed."));
        }
        finally {
            setSaving("");
        }
    };

    const removeIndicator = async () => {
        try {
            await deleteIndicatorApi(id);
            navigate("/indicators");
        }
        catch (removeError) {
            setError(getApiErrorMessage(removeError, "The indicator could not be deleted."));
            setConfirmDelete(false);
        }
    };

    if (!indicator) {
        return (
            <PageContainer>
                {error ? <Alert severity="error">{error}</Alert> : <LoadingState message="Loading indicator..." />}
            </PageContainer>
        );
    }

    const unit = indicator.unit;
    const current = indicator.progress?.current;

    return (
        <PageContainer>

            <PageHeader
                title={indicator.name}
                subtitle={`${indicator.code} · ${indicator.level}${indicator.result ? ` · ${indicator.result}` : ""}`}
                action={can(user, "indicator.update") ? () => navigate(`/indicators/${id}/edit`) : undefined}
                actionLabel="Edit"
                actionIcon={<Edit />}
                secondaryAction={can(user, "indicator.delete") ? () => setConfirmDelete(true) : undefined}
                secondaryActionLabel="Delete"
                secondaryActionIcon={<Delete />}
            />

            {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
            {saved && <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSaved("")}>{saved}</Alert>}

            <PageCard>
                <Stack direction={{ xs: "column", md: "row" }} spacing={3}>
                    <Box sx={{ flex: 1 }}>
                        <FormSection title="Indicator">
                            <InfoRow label="Program" value={nameOf(indicator.program)} />
                            <InfoRow label="Project" value={indicator.project ? nameOf(indicator.project) : "Whole program"} />
                            <InfoRow label="Definition" value={indicator.definition || "-"} />
                            <InfoRow label="Actual values" value={indicator.source === "auto" ? `Automatic: ${indicator.measureName || indicator.measure}` : "Entered per period"} />
                            <InfoRow label="Better when" value={indicator.direction === "decrease" ? "Lower" : "Higher"} />
                            <InfoRow label="Baseline" value={indicator.baseline?.value !== null && indicator.baseline?.value !== undefined ? `${valueText(indicator.baseline.value, unit)}${indicator.baseline.date ? ` (${formatDate(indicator.baseline.date)})` : ""}` : "-"} />
                            <InfoRow label="Frequency" value={indicator.frequency} />
                            <InfoRow label="Means of verification" value={indicator.dataSource || "-"} />
                            <InfoRow label="Status" value={<StatusChip status={indicator.status} />} />
                        </FormSection>
                    </Box>
                    <Box sx={{ width: { md: 280 } }}>
                        <FormSection title="Latest period">
                            {current
                                ? (
                                    <>
                                        <Typography variant="body2" color="text.secondary">{periodLabel(current.period)}</Typography>
                                        <Typography variant="h4" sx={{ fontWeight: 800, my: 0.5 }}>{percentText(current.percent)}</Typography>
                                        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                            {valueText(current.actual, unit)} of {valueText(current.target, unit)}
                                        </Typography>
                                        <StatusChip status={current.status} />
                                    </>
                                )
                                : <Typography color="text.secondary">No period with a target has started yet.</Typography>}
                            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1.5 }}>{statusHelp(limits)}</Typography>
                        </FormSection>
                    </Box>
                </Stack>
            </PageCard>

            <PageCard>
                <FormSection
                    title="Progress by period"
                    subtitle={indicator.source === "auto"
                        ? "Counted automatically from this program's / project's records for each period."
                        : mayReport ? "Type the actual value of a period and save it. Female / male are optional." : "Values are entered by the people responsible."}
                >
                    <TableContainer>
                        <Table size="small">
                            <TableHead>
                                <TableRow>
                                    <TableCell>Period</TableCell>
                                    <TableCell align="right">Target</TableCell>
                                    <TableCell align="right">Actual</TableCell>
                                    {mayReport && <TableCell align="right">Female</TableCell>}
                                    {mayReport && <TableCell align="right">Male</TableCell>}
                                    {mayReport && <TableCell>Note</TableCell>}
                                    <TableCell align="right">Achieved</TableCell>
                                    <TableCell>Status</TableCell>
                                    {mayReport && <TableCell />}
                                </TableRow>
                            </TableHead>
                            <TableBody>
                                {rows.length === 0 && (
                                    <TableRow><TableCell colSpan={9}><Typography color="text.secondary">No targets yet. Edit the indicator to add them.</Typography></TableCell></TableRow>
                                )}
                                {rows.map(row => {
                                    const draft = draftOf(row);
                                    const changed = Boolean(drafts[row.period]);
                                    return (
                                        <TableRow key={row.period}>
                                            <TableCell sx={cellSx}>{periodLabel(row.period)}</TableCell>
                                            <TableCell align="right" sx={cellSx}>{valueText(row.target, unit)}</TableCell>
                                            <TableCell align="right" sx={cellSx}>
                                                {mayReport && row.started
                                                    ? <TextField size="small" type="number" value={draft.value} onChange={(event) => setDraft(row.period, { value: event.target.value }, row)} inputProps={{ min: 0, step: "any", style: { textAlign: "right", width: 80 } }} />
                                                    : valueText(row.actual, unit)}
                                            </TableCell>
                                            {mayReport && (
                                                <TableCell align="right">
                                                    {row.started && <TextField size="small" type="number" value={draft.female} onChange={(event) => setDraft(row.period, { female: event.target.value }, row)} inputProps={{ min: 0, style: { textAlign: "right", width: 60 } }} />}
                                                </TableCell>
                                            )}
                                            {mayReport && (
                                                <TableCell align="right">
                                                    {row.started && <TextField size="small" type="number" value={draft.male} onChange={(event) => setDraft(row.period, { male: event.target.value }, row)} inputProps={{ min: 0, style: { textAlign: "right", width: 60 } }} />}
                                                </TableCell>
                                            )}
                                            {mayReport && (
                                                <TableCell>
                                                    {row.started && <TextField size="small" value={draft.notes} placeholder="Source, remarks" onChange={(event) => setDraft(row.period, { notes: event.target.value }, row)} sx={{ minWidth: 160 }} />}
                                                </TableCell>
                                            )}
                                            <TableCell align="right" sx={cellSx}>{percentText(row.percent)}</TableCell>
                                            <TableCell sx={cellSx}><StatusChip status={row.status} /></TableCell>
                                            {mayReport && (
                                                <TableCell sx={cellSx}>
                                                    {row.started && (
                                                        <>
                                                            <Tooltip title="Save this period">
                                                                <span>
                                                                    <IconButton size="small" color="primary" disabled={!changed || saving === row.period || draft.value === ""} onClick={() => saveValue(row)}>
                                                                        <Save fontSize="small" />
                                                                    </IconButton>
                                                                </span>
                                                            </Tooltip>
                                                            <Tooltip title="Remove the value">
                                                                <span>
                                                                    <IconButton size="small" disabled={row.actual === null || saving === row.period} onClick={() => removeValue(row)}>
                                                                        <Delete fontSize="small" />
                                                                    </IconButton>
                                                                </span>
                                                            </Tooltip>
                                                        </>
                                                    )}
                                                </TableCell>
                                            )}
                                        </TableRow>
                                    );
                                })}
                            </TableBody>
                        </Table>
                    </TableContainer>
                </FormSection>

                <Stack direction="row" sx={{ justifyContent: "flex-start", mt: 2 }}>
                    <AppButton variant="outlined" onClick={() => navigate("/indicators")}>Back to indicators</AppButton>
                </Stack>
            </PageCard>

            <ConfirmDeleteDialog
                open={confirmDelete}
                title="Delete indicator"
                message={`Delete "${indicator.name}"? Its targets and entered values are removed from reports.`}
                onClose={() => setConfirmDelete(false)}
                onConfirm={removeIndicator}
            />

        </PageContainer>
    );

};

export default IndicatorDetailsPage;
