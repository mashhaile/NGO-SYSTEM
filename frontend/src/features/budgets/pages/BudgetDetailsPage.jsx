import {
    useCallback,
    useEffect,
    useState
} from "react";

import {
    useNavigate,
    useParams
} from "react-router-dom";

import {
    Alert,
    Box,
    Link,
    Stack,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableFooter,
    TableHead,
    TableRow,
    Typography
} from "@mui/material";

import {
    ArrowBack,
    CheckCircle,
    Delete,
    Edit,
    Send,
    Undo
} from "@mui/icons-material";

import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    InfoRow,
    AppButton,
    StatusChip,
    StatsCards,
    LoadingState,
    ConfirmDeleteDialog,
    ConfirmDialog
} from "../../../components/ui";

import TorReviewDialog
    from "../../tor/components/TorReviewDialog";

import useAuth
    from "../../auth/hooks/useAuth";

import {
    getBudgetByIdApi,
    deleteBudgetApi,
    submitBudgetApi,
    approveBudgetApi,
    returnBudgetApi,
    getApiErrorMessage
} from "../api/budgetApi";

import {
    BUDGET_STATUS,
    EDITABLE_STATUSES,
    formatMoney,
    levelLabel,
    hasPermission
} from "../utils/budgetUtils";

import {
    fiscalYearLabel
} from "../../../utils/fiscalYear";


const tableSx = {
    border: "1px solid",
    borderColor: "divider",
    borderRadius: 2,
    overflowX: "auto"
};

const nowrap = { whiteSpace: "nowrap" };

const dateTime = (value) =>
    value ? new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "-";


// =====================================================
// BUDGET DETAILS
// =====================================================

const BudgetDetailsPage = () => {

    const { id } = useParams();

    const navigate = useNavigate();

    const { user } = useAuth();

    const [budget, setBudget] = useState(null);
    const [error, setError] = useState("");
    const [actionError, setActionError] = useState("");
    const [busy, setBusy] = useState(false);

    // "submit" | "approve" | "return" | "delete" | null
    const [dialog, setDialog] = useState(null);
    const [dialogKey, setDialogKey] = useState(0);


    const load = useCallback(() =>
        getBudgetByIdApi(id)
            .then(data => {
                setBudget(data);
                setError("");
            })
            .catch(err => setError(getApiErrorMessage(err, "Failed to load the budget."))),
    [id]);

    useEffect(() => {
        load();
    }, [load]);


    const openDialog = (name) => {
        setActionError("");
        setDialogKey(key => key + 1);
        setDialog(name);
    };

    const closeDialog = () => !busy && setDialog(null);

    const run = async (action) => {
        setBusy(true);
        setActionError("");
        try {
            const updated = await action();
            if (updated) setBudget(updated);
            setDialog(null);
        }
        catch (err) {
            setActionError(getApiErrorMessage(err, "The action failed."));
        }
        finally {
            setBusy(false);
        }
    };

    const handleDelete = () =>
        run(async () => {
            await deleteBudgetApi(id);
            navigate("/budgets");
            return null;
        });


    const header = (
        <PageHeader
            title="Budget Details"
            subtitle={budget ? `${budget.budgetCode} · ${budget.name}` : ""}
            action={() => navigate("/budgets")}
            actionLabel="Back"
            actionIcon={<ArrowBack />}
        />
    );

    if (!budget) {
        return (
            <PageContainer>
                {header}
                {error
                    ? <Alert severity="error">{error}</Alert>
                    : <PageCard><LoadingState message="Loading budget..." /></PageCard>}
            </PageContainer>
        );
    }


    const { summary } = budget;
    const currency = budget.currency;
    const years = summary.years.map(item => item.fiscalYear);
    const isProgram = budget.level === "program";
    const editable = EDITABLE_STATUSES.includes(budget.status);

    const can = {
        edit: editable && hasPermission(user, "budget.update"),
        delete: editable && hasPermission(user, "budget.delete"),
        submit: editable && hasPermission(user, "budget.update"),
        review: budget.status === BUDGET_STATUS.SUBMITTED && hasPermission(user, "budget.approve")
    };


    return (

        <PageContainer>

            {header}

            {actionError && !dialog && (
                <Alert severity="error" sx={{ mb: 3 }} onClose={() => setActionError("")}>
                    {actionError}
                </Alert>
            )}

            {budget.status === BUDGET_STATUS.RETURNED && budget.reviewComment && (
                <Alert severity="warning" sx={{ mb: 3 }}>
                    <strong>Returned for changes:</strong> {budget.reviewComment}
                </Alert>
            )}


            {/* ACTIONS */}

            {(can.edit || can.delete || can.submit || can.review) && (
                <PageCard>
                    <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
                        {can.edit && (
                            <AppButton variant="outlined" startIcon={<Edit />} onClick={() => navigate(`/budgets/${id}/edit`)}>
                                Edit
                            </AppButton>
                        )}
                        {can.submit && (
                            <AppButton variant="contained" startIcon={<Send />} onClick={() => openDialog("submit")}>
                                Submit for Approval
                            </AppButton>
                        )}
                        {can.review && (
                            <AppButton variant="contained" color="success" startIcon={<CheckCircle />} onClick={() => openDialog("approve")}>
                                Approve
                            </AppButton>
                        )}
                        {can.review && (
                            <AppButton variant="outlined" color="warning" startIcon={<Undo />} onClick={() => openDialog("return")}>
                                Return for Changes
                            </AppButton>
                        )}
                        {can.delete && (
                            <AppButton variant="outlined" color="error" startIcon={<Delete />} onClick={() => openDialog("delete")}>
                                Delete
                            </AppButton>
                        )}
                    </Stack>
                </PageCard>
            )}


            {/* TOTALS */}

            <StatsCards
                valueSize="small"
                items={[
                    { label: "Budget", value: formatMoney(summary.totalAmount, currency) },
                    { label: "Committed", value: formatMoney(summary.totalCommitted, currency) },
                    { label: "Spent", value: formatMoney(summary.totalSpent, currency) },
                    { label: "Remaining", value: formatMoney(summary.totalRemaining, currency) }
                ]}
            />


            {/* INFORMATION */}

            <PageCard>
                <FormSection title="Budget Information">
                    <InfoRow label="Budget Code" value={budget.budgetCode} />
                    <InfoRow label="Name" value={budget.name} />
                    <InfoRow label="Level" value={levelLabel(budget.level)} />
                    <InfoRow label="Program" value={budget.program?.name} />
                    {!isProgram && <InfoRow label="Project" value={budget.project?.name} />}
                    <InfoRow
                        label="Period"
                        value={`${fiscalYearLabel(budget.startYear)} – ${fiscalYearLabel(budget.endYear)} (${years.length} year${years.length === 1 ? "" : "s"})`}
                    />
                    <InfoRow label="Currency" value={currency} />
                    <InfoRow label="Status" value={<StatusChip status={budget.status} />} />
                    {budget.description && <InfoRow label="Description" value={budget.description} />}
                </FormSection>
            </PageCard>


            {/* PROGRAM: allocation */}

            {isProgram && (
                <PageCard>
                    <FormSection
                        title="Allocation to Projects"
                        subtitle="How much of each year is already given to project budgets (drafts included) and what is left."
                    >
                        <TableContainer sx={tableSx}>
                            <Table size="small">
                                <TableHead>
                                    <TableRow>
                                        <TableCell>Fiscal year</TableCell>
                                        <TableCell align="right">Program budget</TableCell>
                                        <TableCell align="right">Allocated to projects</TableCell>
                                        <TableCell align="right">Unallocated</TableCell>
                                    </TableRow>
                                </TableHead>
                                <TableBody>
                                    {summary.allocation.years.map(item => (
                                        <TableRow key={item.fiscalYear}>
                                            <TableCell>{fiscalYearLabel(item.fiscalYear)}</TableCell>
                                            <TableCell align="right" sx={nowrap}>{formatMoney(item.amount, currency)}</TableCell>
                                            <TableCell align="right" sx={nowrap}>{formatMoney(item.allocated, currency)}</TableCell>
                                            <TableCell
                                                align="right"
                                                sx={{ ...nowrap, fontWeight: 700, color: item.unallocated < 0 ? "error.main" : "text.primary" }}
                                            >
                                                {formatMoney(item.unallocated, currency)}
                                            </TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                                <TableFooter>
                                    <TableRow>
                                        <TableCell sx={{ fontWeight: 700 }}>Total</TableCell>
                                        <TableCell align="right" sx={{ ...nowrap, fontWeight: 700 }}>{formatMoney(summary.totalAmount, currency)}</TableCell>
                                        <TableCell align="right" sx={{ ...nowrap, fontWeight: 700 }}>{formatMoney(summary.allocation.totalAllocated, currency)}</TableCell>
                                        <TableCell align="right" sx={{ ...nowrap, fontWeight: 800 }}>{formatMoney(summary.allocation.totalUnallocated, currency)}</TableCell>
                                    </TableRow>
                                </TableFooter>
                            </Table>
                        </TableContainer>

                        <Typography sx={{ fontWeight: 700, mt: 3, mb: 1 }}>
                            Project budgets in this program
                        </Typography>

                        {summary.allocation.projects.length === 0
                            ? (
                                <Typography variant="body2" sx={{ color: "text.secondary" }}>
                                    No project budgets yet.
                                </Typography>
                            )
                            : (
                                <TableContainer sx={tableSx}>
                                    <Table size="small">
                                        <TableHead>
                                            <TableRow>
                                                <TableCell sx={{ minWidth: 200 }}>Project</TableCell>
                                                <TableCell>Status</TableCell>
                                                {years.map(year => (
                                                    <TableCell key={year} align="right">{fiscalYearLabel(year)}</TableCell>
                                                ))}
                                                <TableCell align="right">Total</TableCell>
                                            </TableRow>
                                        </TableHead>
                                        <TableBody>
                                            {summary.allocation.projects.map(item => (
                                                <TableRow key={item._id} hover>
                                                    <TableCell>
                                                        <Link component="button" underline="hover" sx={{ textAlign: "left", fontWeight: 600 }} onClick={() => navigate(`/budgets/${item._id}`)}>
                                                            {item.project?.name || item.budgetCode}
                                                        </Link>
                                                        <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                                                            {item.budgetCode}
                                                        </Typography>
                                                    </TableCell>
                                                    <TableCell><StatusChip status={item.status} /></TableCell>
                                                    {years.map(year => (
                                                        <TableCell key={year} align="right" sx={nowrap}>
                                                            {formatMoney(item.years.find(y => y.fiscalYear === year)?.amount || 0, item.currency)}
                                                        </TableCell>
                                                    ))}
                                                    <TableCell align="right" sx={{ ...nowrap, fontWeight: 600 }}>
                                                        {formatMoney(item.totalAmount, item.currency)}
                                                    </TableCell>
                                                </TableRow>
                                            ))}
                                        </TableBody>
                                    </Table>
                                </TableContainer>
                            )}
                    </FormSection>
                </PageCard>
            )}


            {/* PROJECT: lines */}

            {!isProgram && (
                <PageCard>
                    <FormSection
                        title="Budget Lines"
                        subtitle="Spent and Remaining will follow expenses recorded against each line."
                    >
                        <TableContainer sx={tableSx}>
                            <Table size="small">
                                <TableHead>
                                    <TableRow>
                                        <TableCell sx={{ minWidth: 220 }}>Line</TableCell>
                                        {years.map(year => (
                                            <TableCell key={year} align="right">{fiscalYearLabel(year)}</TableCell>
                                        ))}
                                        <TableCell align="right">Budget</TableCell>
                                        <TableCell align="right">Spent</TableCell>
                                        <TableCell align="right">Remaining</TableCell>
                                    </TableRow>
                                </TableHead>
                                <TableBody>
                                    {summary.lines.map(line => (
                                        <TableRow key={line._id}>
                                            <TableCell>
                                                <Typography variant="body2" sx={{ fontWeight: 600 }}>{line.category}</Typography>
                                                {line.description && (
                                                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                                                        {line.description}
                                                    </Typography>
                                                )}
                                            </TableCell>
                                            {years.map(year => (
                                                <TableCell key={year} align="right" sx={nowrap}>
                                                    {formatMoney(line.amounts.find(item => item.fiscalYear === year)?.amount || 0, currency)}
                                                </TableCell>
                                            ))}
                                            <TableCell align="right" sx={{ ...nowrap, fontWeight: 600 }}>{formatMoney(line.total, currency)}</TableCell>
                                            <TableCell align="right" sx={nowrap}>{formatMoney(line.spent, currency)}</TableCell>
                                            <TableCell align="right" sx={{ ...nowrap, fontWeight: 600 }}>{formatMoney(line.remaining, currency)}</TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                                <TableFooter>
                                    <TableRow>
                                        <TableCell sx={{ fontWeight: 700 }}>Total</TableCell>
                                        {summary.years.map(item => (
                                            <TableCell key={item.fiscalYear} align="right" sx={{ ...nowrap, fontWeight: 700 }}>
                                                {formatMoney(item.amount, currency)}
                                            </TableCell>
                                        ))}
                                        <TableCell align="right" sx={{ ...nowrap, fontWeight: 800 }}>{formatMoney(summary.totalAmount, currency)}</TableCell>
                                        <TableCell align="right" sx={{ ...nowrap, fontWeight: 700 }}>{formatMoney(summary.totalSpent, currency)}</TableCell>
                                        <TableCell align="right" sx={{ ...nowrap, fontWeight: 800 }}>{formatMoney(summary.totalRemaining, currency)}</TableCell>
                                    </TableRow>
                                </TableFooter>
                            </Table>
                        </TableContainer>

                        {summary.programBudget
                            ? (
                                <Box sx={{ mt: 3 }}>
                                    <Typography sx={{ fontWeight: 700, mb: 1 }}>
                                        In the program budget{" "}
                                        <Link component="button" underline="hover" onClick={() => navigate(`/budgets/${summary.programBudget._id}`)}>
                                            {summary.programBudget.budgetCode}
                                        </Link>
                                    </Typography>
                                    <TableContainer sx={tableSx}>
                                        <Table size="small">
                                            <TableHead>
                                                <TableRow>
                                                    <TableCell>Fiscal year</TableCell>
                                                    <TableCell align="right">Program budget</TableCell>
                                                    <TableCell align="right">Other projects</TableCell>
                                                    <TableCell align="right">Available for this project</TableCell>
                                                    <TableCell align="right">This budget</TableCell>
                                                </TableRow>
                                            </TableHead>
                                            <TableBody>
                                                {summary.programBudget.years.map(item => {
                                                    const mine = summary.years.find(y => y.fiscalYear === item.fiscalYear)?.amount || 0;
                                                    return (
                                                        <TableRow key={item.fiscalYear}>
                                                            <TableCell>{fiscalYearLabel(item.fiscalYear)}</TableCell>
                                                            <TableCell align="right" sx={nowrap}>{formatMoney(item.amount, currency)}</TableCell>
                                                            <TableCell align="right" sx={nowrap}>{formatMoney(item.usedByOtherProjects, currency)}</TableCell>
                                                            <TableCell align="right" sx={nowrap}>{formatMoney(item.availableForThisProject, currency)}</TableCell>
                                                            <TableCell
                                                                align="right"
                                                                sx={{ ...nowrap, fontWeight: 700, color: mine > item.availableForThisProject ? "error.main" : "text.primary" }}
                                                            >
                                                                {formatMoney(mine, currency)}
                                                            </TableCell>
                                                        </TableRow>
                                                    );
                                                })}
                                            </TableBody>
                                        </Table>
                                    </TableContainer>
                                </Box>
                            )
                            : (
                                <Alert severity="info" sx={{ mt: 3 }}>
                                    This program has no program budget, so nothing limits this project budget.
                                    Create a program budget to set a ceiling per year.
                                </Alert>
                            )}
                    </FormSection>
                </PageCard>
            )}


            {/* HISTORY */}

            <PageCard>
                <FormSection title="History">
                    {(budget.history || []).slice().reverse().map((entry, index) => (
                        <InfoRow
                            key={index}
                            label={dateTime(entry.at)}
                            value={
                                <span>
                                    <strong>{entry.action}</strong>
                                    {entry.by?.name ? ` by ${entry.by.name}` : ""}
                                    {entry.comment ? ` — "${entry.comment}"` : ""}
                                </span>
                            }
                        />
                    ))}
                </FormSection>
            </PageCard>


            {/* DIALOGS */}

            <ConfirmDialog
                open={dialog === "submit"}
                title="Submit for Approval"
                message={
                    actionError ||
                    "The budget will be locked while it is reviewed. A project budget is checked against what is left in its program budget."
                }
                confirmLabel="Submit"
                loading={busy}
                onClose={closeDialog}
                onConfirm={() => run(() => submitBudgetApi(id))}
            />

            <TorReviewDialog
                key={`review-${dialogKey}`}
                entityLabel="budget"
                open={dialog === "approve" || dialog === "return"}
                mode={dialog === "return" ? "return" : "approve"}
                loading={busy}
                error={actionError}
                onClose={closeDialog}
                onConfirm={(comment) =>
                    run(() => (dialog === "return" ? returnBudgetApi(id, comment) : approveBudgetApi(id, comment)))
                }
            />

            <ConfirmDeleteDialog
                open={dialog === "delete"}
                title="Delete Budget"
                message={`Delete ${budget.budgetCode} "${budget.name}"? This cannot be undone.`}
                loading={busy}
                onClose={closeDialog}
                onConfirm={handleDelete}
            />

        </PageContainer>

    );

};


export default BudgetDetailsPage;
