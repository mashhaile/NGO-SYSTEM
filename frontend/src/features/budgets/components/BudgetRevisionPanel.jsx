import {
    useState
} from "react";

import {
    Alert,
    Chip,
    Stack,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Typography
} from "@mui/material";

import {
    CheckCircle,
    Close,
    Edit,
    History,
    Send,
    Undo
} from "@mui/icons-material";

import {
    PageCard,
    FormSection,
    AppButton,
    ConfirmDialog
} from "../../../components/ui";

import TorReviewDialog
    from "../../tor/components/TorReviewDialog";

import {
    startRevisionApi,
    cancelRevisionApi,
    submitRevisionApi,
    approveRevisionApi,
    returnRevisionApi,
    getApiErrorMessage
} from "../api/budgetApi";

import {
    formatMoney,
    hasPermission
} from "../utils/budgetUtils";

import {
    fiscalYearLabel,
    fiscalYearRange
} from "../../../utils/fiscalYear";
import { formatDateTime } from "../../../utils/date";


const tableSx = { border: "1px solid", borderColor: "divider", borderRadius: 2, overflowX: "auto" };
const nowrap = { whiteSpace: "nowrap" };

const sum = (amounts = []) => amounts.reduce((total, item) => total + Number(item.amount || 0), 0);

const amountIn = (amounts = [], year) =>
    Number(amounts.find(item => item.fiscalYear === year)?.amount || 0);

const dateTime = (value) =>
    value ? formatDateTime(value) : "-";

// figures of one year, for a budget or a revision
const yearTotal = (source, isProgram, year) =>
    isProgram
        ? amountIn(source.yearlyAmounts, year)
        : (source.lines || []).reduce((total, line) => total + amountIn(line.amounts, year), 0);

const totalOf = (source, isProgram) =>
    isProgram ? sum(source.yearlyAmounts) : (source.lines || []).reduce((total, line) => total + sum(line.amounts), 0);

// current lines vs proposed lines, matched by line id
const compareLines = (budget, revision) => {

    const proposed = revision.lines || [];

    const rows = (budget.lines || []).map(line => {
        const next = proposed.find(item => item._id && String(item._id) === String(line._id));
        return {
            key: String(line._id),
            category: line.category,
            description: next ? next.description : line.description,
            current: sum(line.amounts),
            proposed: next ? sum(next.amounts) : 0,
            removed: !next
        };
    });

    proposed
        .filter(item => !item._id || !rows.some(row => row.key === String(item._id)))
        .forEach((item, index) => rows.push({
            key: `new-${index}`,
            category: item.category,
            description: item.description,
            current: 0,
            proposed: sum(item.amounts),
            added: true
        }));

    return rows;

};


const Change = ({ value, currency }) => {
    if (!value) return <Typography variant="body2" sx={{ color: "text.secondary" }}>-</Typography>;
    return (
        <Typography variant="body2" sx={{ ...nowrap, fontWeight: 600, color: value > 0 ? "success.main" : "error.main" }}>
            {value > 0 ? "+" : "−"}{formatMoney(Math.abs(value), currency)}
        </Typography>
    );
};


// =====================================================
// REVISIONS OF AN APPROVED BUDGET
// =====================================================
// Approved budgets are locked. A change goes through a
// revision: proposed figures + reason -> submit -> approve.
// On approval the old figures are kept as a version.

const BudgetRevisionPanel = ({ budget, user, navigate, onChanged }) => {

    const [busy, setBusy] = useState(false);
    const [error, setError] = useState("");

    // "submit" | "cancel" | "approve" | "return" | null
    const [dialog, setDialog] = useState(null);
    const [dialogKey, setDialogKey] = useState(0);

    const { revision } = budget;
    const currency = budget.currency;
    const isProgram = budget.level === "program";
    const versions = budget.versions || [];

    const canEdit = hasPermission(user, "budget.update");
    const canApprove = hasPermission(user, "budget.approve");
    const editable = revision && ["Draft", "Returned"].includes(revision.status);
    const submitted = revision?.status === "Submitted";

    const reviseUrl = `/budgets/${budget._id}/revise`;


    const openDialog = (name) => {
        setError("");
        setDialogKey(key => key + 1);
        setDialog(name);
    };

    const closeDialog = () => !busy && setDialog(null);

    const run = async (action, after) => {
        setBusy(true);
        setError("");
        try {
            await action();
            setDialog(null);
            if (after) after();
            else await onChanged();
        }
        catch (err) {
            setError(getApiErrorMessage(err, "The action failed."));
        }
        finally {
            setBusy(false);
        }
    };


    if (!revision && versions.length === 0 && !canEdit) return null;


    // figures to compare
    const years = revision
        ? [...new Set([
            ...fiscalYearRange(budget.startYear, budget.endYear),
            ...fiscalYearRange(revision.startYear, revision.endYear)
        ])].sort((a, b) => a - b)
        : [];

    const lineRows = revision && !isProgram ? compareLines(budget, revision) : [];
    const currentTotal = Number(budget.totalAmount ?? totalOf(budget, isProgram));
    const proposedTotal = revision ? totalOf(revision, isProgram) : 0;


    return (

        <PageCard>

            <FormSection
                title="Revisions"
                subtitle="An approved budget is locked. To change its figures, propose a revision with a reason; once approved, the old figures are kept as a version and expenses stay attached."
            >

                {error && !dialog && (
                    <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError("")}>
                        {error}
                    </Alert>
                )}


                {/* NO REVISION */}

                {!revision && canEdit && (
                    <AppButton
                        variant="outlined"
                        startIcon={<Edit />}
                        loading={busy}
                        onClick={() => run(() => startRevisionApi(budget._id), () => navigate(reviseUrl))}
                    >
                        Revise Budget
                    </AppButton>
                )}


                {/* REVISION IN PROGRESS */}

                {revision && (
                    <>
                        <Alert
                            severity={revision.status === "Returned" ? "warning" : submitted ? "info" : "success"}
                            icon={<History />}
                            sx={{ mb: 2 }}
                        >
                            <Stack spacing={0.5}>
                                <span>
                                    <strong>Revision v{(budget.version || 1) + 1}</strong>{" "}
                                    <Chip size="small" label={revision.status} sx={{ ml: 0.5 }} />
                                </span>
                                <span>
                                    Requested by {revision.requestedBy?.name || "-"} on {dateTime(revision.requestedAt)}
                                    {submitted && revision.submittedBy?.name ? ` · submitted by ${revision.submittedBy.name}` : ""}
                                </span>
                                <span>
                                    <strong>Reason:</strong> {revision.reason || <em>not given yet</em>}
                                </span>
                                {revision.status === "Returned" && revision.reviewComment && (
                                    <span><strong>Returned:</strong> {revision.reviewComment}</span>
                                )}
                            </Stack>
                        </Alert>

                        <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} sx={{ mb: 3 }}>
                            {editable && canEdit && (
                                <AppButton variant="outlined" startIcon={<Edit />} onClick={() => navigate(reviseUrl)}>
                                    Edit Revision
                                </AppButton>
                            )}
                            {editable && canEdit && (
                                <AppButton
                                    variant="contained"
                                    startIcon={<Send />}
                                    onClick={() => openDialog("submit")}
                                    // the reason is given when the revision is edited
                                    disabled={String(revision.reason || "").trim().length < 3}
                                    title={String(revision.reason || "").trim().length < 3 ? "Edit the revision and give its reason first" : undefined}
                                >
                                    Submit Revision
                                </AppButton>
                            )}
                            {submitted && canApprove && (
                                <AppButton variant="contained" color="success" startIcon={<CheckCircle />} onClick={() => openDialog("approve")}>
                                    Approve Revision
                                </AppButton>
                            )}
                            {submitted && canApprove && (
                                <AppButton variant="outlined" color="warning" startIcon={<Undo />} onClick={() => openDialog("return")}>
                                    Return Revision
                                </AppButton>
                            )}
                            {canEdit && (
                                <AppButton variant="outlined" color="error" startIcon={<Close />} onClick={() => openDialog("cancel")}>
                                    Cancel Revision
                                </AppButton>
                            )}
                        </Stack>


                        {/* line comparison (project budgets) */}

                        {!isProgram && (
                            <TableContainer sx={{ ...tableSx, mb: 2 }}>
                                <Table size="small">
                                    <TableHead>
                                        <TableRow>
                                            <TableCell sx={{ minWidth: 220 }}>Line</TableCell>
                                            <TableCell align="right">Current</TableCell>
                                            <TableCell align="right">Proposed</TableCell>
                                            <TableCell align="right">Change</TableCell>
                                        </TableRow>
                                    </TableHead>
                                    <TableBody>
                                        {lineRows.map(row => (
                                            <TableRow key={row.key}>
                                                <TableCell>
                                                    <Typography variant="body2" sx={{ fontWeight: 600 }}>
                                                        {row.category}
                                                        {row.added && <Chip size="small" color="success" label="New" sx={{ ml: 1 }} />}
                                                        {row.removed && <Chip size="small" color="error" label="Removed" sx={{ ml: 1 }} />}
                                                    </Typography>
                                                    {row.description && (
                                                        <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                                                            {row.description}
                                                        </Typography>
                                                    )}
                                                </TableCell>
                                                <TableCell align="right" sx={nowrap}>{formatMoney(row.current, currency)}</TableCell>
                                                <TableCell align="right" sx={{ ...nowrap, fontWeight: 600 }}>{formatMoney(row.proposed, currency)}</TableCell>
                                                <TableCell align="right"><Change value={row.proposed - row.current} currency={currency} /></TableCell>
                                            </TableRow>
                                        ))}
                                    </TableBody>
                                </Table>
                            </TableContainer>
                        )}


                        {/* per-year comparison */}

                        <TableContainer sx={tableSx}>
                            <Table size="small">
                                <TableHead>
                                    <TableRow>
                                        <TableCell>Fiscal year</TableCell>
                                        <TableCell align="right">Current</TableCell>
                                        <TableCell align="right">Proposed</TableCell>
                                        <TableCell align="right">Change</TableCell>
                                    </TableRow>
                                </TableHead>
                                <TableBody>
                                    {years.map(year => {
                                        const current = yearTotal(budget, isProgram, year);
                                        const proposed = yearTotal(revision, isProgram, year);
                                        return (
                                            <TableRow key={year}>
                                                <TableCell>{fiscalYearLabel(year)}</TableCell>
                                                <TableCell align="right" sx={nowrap}>{formatMoney(current, currency)}</TableCell>
                                                <TableCell align="right" sx={{ ...nowrap, fontWeight: 600 }}>{formatMoney(proposed, currency)}</TableCell>
                                                <TableCell align="right"><Change value={proposed - current} currency={currency} /></TableCell>
                                            </TableRow>
                                        );
                                    })}
                                    <TableRow>
                                        <TableCell sx={{ fontWeight: 700 }}>Total</TableCell>
                                        <TableCell align="right" sx={{ ...nowrap, fontWeight: 700 }}>{formatMoney(currentTotal, currency)}</TableCell>
                                        <TableCell align="right" sx={{ ...nowrap, fontWeight: 800 }}>{formatMoney(proposedTotal, currency)}</TableCell>
                                        <TableCell align="right"><Change value={proposedTotal - currentTotal} currency={currency} /></TableCell>
                                    </TableRow>
                                </TableBody>
                            </Table>
                        </TableContainer>
                    </>
                )}


                {/* VERSION HISTORY */}

                {versions.length > 0 && (
                    <>
                        <Typography sx={{ fontWeight: 700, mt: 3, mb: 1 }}>
                            Version history
                        </Typography>
                        <TableContainer sx={tableSx}>
                            <Table size="small">
                                <TableHead>
                                    <TableRow>
                                        <TableCell>Version</TableCell>
                                        <TableCell>Period</TableCell>
                                        <TableCell align="right">Total</TableCell>
                                        <TableCell>Approved</TableCell>
                                        <TableCell>Replaced</TableCell>
                                        <TableCell sx={{ minWidth: 220 }}>Reason for change</TableCell>
                                    </TableRow>
                                </TableHead>
                                <TableBody>
                                    <TableRow>
                                        <TableCell sx={{ ...nowrap, fontWeight: 700 }}>
                                            v{budget.version || 1} <Chip size="small" color="primary" label="Current" sx={{ ml: 0.5 }} />
                                        </TableCell>
                                        <TableCell sx={nowrap}>{fiscalYearLabel(budget.startYear)} – {fiscalYearLabel(budget.endYear)}</TableCell>
                                        <TableCell align="right" sx={{ ...nowrap, fontWeight: 700 }}>{formatMoney(currentTotal, currency)}</TableCell>
                                        <TableCell sx={nowrap}>{dateTime(budget.approvedAt)}</TableCell>
                                        <TableCell>-</TableCell>
                                        <TableCell>-</TableCell>
                                    </TableRow>
                                    {versions.slice().reverse().map(item => (
                                        <TableRow key={item.version}>
                                            <TableCell>v{item.version}</TableCell>
                                            <TableCell sx={nowrap}>{fiscalYearLabel(item.startYear)} – {fiscalYearLabel(item.endYear)}</TableCell>
                                            <TableCell align="right" sx={nowrap}>{formatMoney(item.totalAmount, currency)}</TableCell>
                                            <TableCell sx={nowrap}>
                                                {dateTime(item.approvedAt)}
                                                {item.approvedBy?.name && (
                                                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                                                        by {item.approvedBy.name}
                                                    </Typography>
                                                )}
                                            </TableCell>
                                            <TableCell sx={nowrap}>{dateTime(item.replacedAt)}</TableCell>
                                            <TableCell>{item.replacedBecause || "-"}</TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                        </TableContainer>
                    </>
                )}

            </FormSection>


            {/* DIALOGS */}

            <ConfirmDialog
                open={dialog === "submit"}
                title="Submit Revision"
                message={
                    error ||
                    "The revision will be locked while it is reviewed. The new figures are checked against the program budget and against what is already spent."
                }
                confirmLabel="Submit"
                loading={busy}
                onClose={closeDialog}
                onConfirm={() => run(() => submitRevisionApi(budget._id))}
            />

            <ConfirmDialog
                open={dialog === "cancel"}
                title="Cancel Revision"
                message={error || "Discard the proposed figures? The approved budget stays as it is."}
                confirmLabel="Cancel Revision"
                loading={busy}
                onClose={closeDialog}
                onConfirm={() => run(() => cancelRevisionApi(budget._id))}
            />

            <TorReviewDialog
                key={`revision-${dialogKey}`}
                entityLabel="revision"
                open={dialog === "approve" || dialog === "return"}
                mode={dialog === "return" ? "return" : "approve"}
                loading={busy}
                error={error}
                onClose={closeDialog}
                onConfirm={(comment) =>
                    run(() => (dialog === "return"
                        ? returnRevisionApi(budget._id, comment)
                        : approveRevisionApi(budget._id, comment)))
                }
            />

        </PageCard>

    );

};


export default BudgetRevisionPanel;

