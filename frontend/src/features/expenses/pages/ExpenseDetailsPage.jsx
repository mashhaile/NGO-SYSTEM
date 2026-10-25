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
    Link,
    Stack
} from "@mui/material";

import {
    ArrowBack,
    Block,
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

import ExpenseActionDialog
    from "../components/ExpenseActionDialog";

import useAuth
    from "../../auth/hooks/useAuth";

import {
    getExpenseByIdApi,
    deleteExpenseApi,
    submitExpenseApi,
    approveExpenseApi,
    returnExpenseApi,
    voidExpenseApi
} from "../api/expenseApi";

import {
    getApiErrorMessage
} from "../../budgets/api/budgetApi";

import {
    formatMoney,
    hasPermission
} from "../../budgets/utils/budgetUtils";

import {
    EXPENSE_STATUS,
    EDITABLE_STATUSES,
    formatDate
} from "../utils/expenseUtils";

import {
    fiscalYearLabel
} from "../../../utils/fiscalYear";
import { formatDateTime } from "../../../utils/date";


const dateTime = (value) =>
    value ? formatDateTime(value) : "-";


// =====================================================
// EXPENSE DETAILS
// =====================================================

const ExpenseDetailsPage = () => {

    const { id } = useParams();

    const navigate = useNavigate();

    const { user } = useAuth();

    const [expense, setExpense] = useState(null);
    const [error, setError] = useState("");
    const [actionError, setActionError] = useState("");
    const [busy, setBusy] = useState(false);

    // "submit" | "approve" | "return" | "void" | "delete" | null
    const [dialog, setDialog] = useState(null);
    const [dialogKey, setDialogKey] = useState(0);


    const load = useCallback(() =>
        getExpenseByIdApi(id)
            .then(data => { setExpense(data); setError(""); })
            .catch(err => setError(getApiErrorMessage(err, "Failed to load the expense."))),
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
            if (updated) setExpense(updated);
            setDialog(null);
        }
        catch (err) {
            setActionError(getApiErrorMessage(err, "The action failed."));
        }
        finally {
            setBusy(false);
        }
    };


    const header = (
        <PageHeader
            title="Expense Details"
            subtitle={expense ? `${expense.expenseCode} · ${expense.description}` : ""}
            action={() => navigate("/expenses")}
            actionLabel="Back"
            actionIcon={<ArrowBack />}
        />
    );

    if (!expense) {
        return (
            <PageContainer>
                {header}
                {error ? <Alert severity="error">{error}</Alert> : <PageCard><LoadingState message="Loading expense..." /></PageCard>}
            </PageContainer>
        );
    }


    const { line } = expense;
    const currency = expense.budgetCurrency;
    const editable = EDITABLE_STATUSES.includes(expense.status);

    const can = {
        edit: editable && hasPermission(user, "expense.update"),
        delete: editable && hasPermission(user, "expense.delete"),
        submit: editable && hasPermission(user, "expense.update"),
        review: expense.status === EXPENSE_STATUS.SUBMITTED && hasPermission(user, "expense.approve"),
        void: expense.status === EXPENSE_STATUS.APPROVED && hasPermission(user, "expense.approve")
    };

    const overBudgetText =
        line.overBudget
            ? `${line.category} has ${formatMoney(Math.max(0, line.remainingBefore), currency)} left in ${fiscalYearLabel(line.fiscalYear)}; this expense is ${formatMoney(expense.budgetAmount, currency)}.`
            : null;


    return (

        <PageContainer>

            {header}

            {actionError && !dialog && (
                <Alert severity="error" sx={{ mb: 3 }} onClose={() => setActionError("")}>{actionError}</Alert>
            )}

            {expense.status === EXPENSE_STATUS.RETURNED && expense.reviewComment && (
                <Alert severity="warning" sx={{ mb: 3 }}><strong>Returned for changes:</strong> {expense.reviewComment}</Alert>
            )}

            {expense.status === EXPENSE_STATUS.VOIDED && (
                <Alert severity="info" sx={{ mb: 3 }}>
                    <strong>Voided</strong> {expense.voidedBy?.name ? `by ${expense.voidedBy.name} ` : ""}on {formatDate(expense.voidedAt)}: {expense.voidReason}. It no longer counts as spent.
                </Alert>
            )}

            {editable && line.overBudget && (
                <Alert severity="warning" sx={{ mb: 3 }}>
                    {overBudgetText} The approver will have to confirm approving over budget.
                </Alert>
            )}


            {(can.edit || can.delete || can.submit || can.review || can.void) && (
                <PageCard>
                    <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
                        {can.edit && <AppButton variant="outlined" startIcon={<Edit />} onClick={() => navigate(`/expenses/${id}/edit`)}>Edit</AppButton>}
                        {can.submit && <AppButton variant="contained" startIcon={<Send />} onClick={() => openDialog("submit")}>Submit for Approval</AppButton>}
                        {can.review && <AppButton variant="contained" color="success" startIcon={<CheckCircle />} onClick={() => openDialog("approve")}>Approve</AppButton>}
                        {can.review && <AppButton variant="outlined" color="warning" startIcon={<Undo />} onClick={() => openDialog("return")}>Return for Changes</AppButton>}
                        {can.void && <AppButton variant="outlined" color="error" startIcon={<Block />} onClick={() => openDialog("void")}>Void</AppButton>}
                        {can.delete && <AppButton variant="outlined" color="error" startIcon={<Delete />} onClick={() => openDialog("delete")}>Delete</AppButton>}
                    </Stack>
                </PageCard>
            )}


            <StatsCards
                valueSize="small"
                items={[
                    { label: "This expense", value: formatMoney(expense.budgetAmount, currency) },
                    { label: `Line budget ${fiscalYearLabel(line.fiscalYear)}`, value: formatMoney(line.budget, currency) },
                    { label: "Spent by other expenses", value: formatMoney(line.spentByOthers, currency) },
                    { label: "Remaining after this", value: formatMoney(line.remainingAfter, currency) }
                ]}
            />


            <PageCard>
                <FormSection title="Expense">
                    <InfoRow label="Expense Code" value={expense.expenseCode} />
                    <InfoRow label="Status" value={<StatusChip status={expense.status} />} />
                    <InfoRow label="Date" value={formatDate(expense.expenseDate)} />
                    <InfoRow label="Description" value={expense.description} />
                    <InfoRow label="Paid to" value={expense.payee} />
                    <InfoRow label="Receipt / invoice no." value={expense.referenceNumber} />
                    <InfoRow label="Payment method" value={expense.paymentMethod} />
                    <InfoRow
                        label="Amount"
                        value={
                            expense.currency === currency
                                ? formatMoney(expense.amount, currency)
                                : `${formatMoney(expense.amount, expense.currency)} × ${expense.exchangeRate} = ${formatMoney(expense.budgetAmount, currency)}`
                        }
                    />
                    {expense.approvedOverBudget && (
                        <InfoRow
                            label="Approval"
                            value={
                                line.remainingAfter >= 0
                                    ? "Approved over budget at the time; the line has since been covered (budget revised). See history for the reason."
                                    : "Approved over budget; the line is still over budget. See history for the reason."
                            }
                        />
                    )}
                </FormSection>
            </PageCard>


            <PageCard>
                <FormSection title="Charged To">
                    <InfoRow
                        label="Budget"
                        value={
                            <Link component="button" underline="hover" onClick={() => navigate(`/budgets/${expense.budget?._id}`)}>
                                {expense.budget?.budgetCode} · {expense.budget?.name}
                            </Link>
                        }
                    />
                    <InfoRow label="Budget line" value={`${line.category}${line.description ? ` — ${line.description}` : ""}`} />
                    <InfoRow label="Fiscal year" value={fiscalYearLabel(line.fiscalYear)} />
                    <InfoRow label="Program" value={expense.program?.name} />
                    <InfoRow label="Project" value={expense.project?.name} />
                    <InfoRow label="Paid from donation" value={expense.donation ? `${expense.donation.donationCode} · ${expense.donation.title}` : "-"} />
                    <InfoRow label="Activity" value={expense.activity ? `${expense.activity.activityCode} · ${expense.activity.name}` : "-"} />
                </FormSection>
            </PageCard>


            <PageCard>
                <FormSection title="History">
                    {(expense.history || []).slice().reverse().map((entry, index) => (
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


            <ConfirmDialog
                open={dialog === "submit"}
                title="Submit for Approval"
                message={actionError || "The expense will be locked while it is reviewed."}
                confirmLabel="Submit"
                loading={busy}
                onClose={closeDialog}
                onConfirm={() => run(() => submitExpenseApi(id))}
            />

            <ExpenseActionDialog
                key={`approve-${dialogKey}`}
                open={dialog === "approve"}
                title="Approve Expense"
                message="Approved expenses count as spent on the budget line and are locked."
                confirmLabel="Approve"
                confirmColor="success"
                overBudget={overBudgetText}
                loading={busy}
                error={actionError}
                onClose={closeDialog}
                onConfirm={(body) => run(() => approveExpenseApi(id, body))}
            />

            <ExpenseActionDialog
                key={`return-${dialogKey}`}
                open={dialog === "return"}
                title="Return for Changes"
                message="The person who recorded it will see your comment and can correct and resubmit it."
                commentLabel="What needs to change"
                requireComment
                confirmLabel="Return"
                confirmColor="warning"
                loading={busy}
                error={actionError}
                onClose={closeDialog}
                onConfirm={({ comment }) => run(() => returnExpenseApi(id, comment))}
            />

            <ExpenseActionDialog
                key={`void-${dialogKey}`}
                open={dialog === "void"}
                title="Void Expense"
                message="The expense stays on record but no longer counts as spent. Use this to correct a mistake."
                commentLabel="Reason"
                requireComment
                confirmLabel="Void"
                confirmColor="error"
                loading={busy}
                error={actionError}
                onClose={closeDialog}
                onConfirm={({ comment }) => run(() => voidExpenseApi(id, comment))}
            />

            <ConfirmDeleteDialog
                open={dialog === "delete"}
                title="Delete Expense"
                message={`Delete ${expense.expenseCode} "${expense.description}"?`}
                loading={busy}
                onClose={closeDialog}
                onConfirm={() => run(async () => { await deleteExpenseApi(id); navigate("/expenses"); return null; })}
            />

        </PageContainer>

    );

};


export default ExpenseDetailsPage;
