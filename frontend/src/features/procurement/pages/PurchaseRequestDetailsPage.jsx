import {
    useCallback,
    useEffect,
    useState
} from "react";

import {
    useLocation,
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
    TableHead,
    TableRow,
    Typography
} from "@mui/material";

import {
    ArrowBack,
    Block,
    CheckCircle,
    Delete,
    DoNotDisturb,
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
    from "../../expenses/components/ExpenseActionDialog";

import SourcingCard
    from "../components/SourcingCard";

import useAuth
    from "../../auth/hooks/useAuth";

import {
    getPurchaseRequestByIdApi,
    deletePurchaseRequestApi,
    submitPurchaseRequestApi,
    approvePurchaseRequestApi,
    returnPurchaseRequestApi,
    rejectPurchaseRequestApi,
    cancelPurchaseRequestApi
} from "../api/procurementApi";

import {
    getApiErrorMessage
} from "../../budgets/api/budgetApi";

import {
    formatMoney,
    hasPermission
} from "../../budgets/utils/budgetUtils";

import {
    PURCHASE_REQUEST_STATUS,
    EDITABLE_STATUSES,
    formatDate
} from "../utils/procurementUtils";

import {
    fiscalYearLabel
} from "../../../utils/fiscalYear";

import { formatDateTime } from "../../../utils/date";


const dateTime = (value) =>
    value ? formatDateTime(value) : "-";


// =====================================================
// PURCHASE REQUEST DETAILS
// =====================================================

const PurchaseRequestDetailsPage = () => {

    const { id } = useParams();

    const navigate = useNavigate();

    const { user } = useAuth();

    // from the form: saved as a draft but not submitted
    const location = useLocation();

    const [request, setRequest] = useState(null);
    const [error, setError] = useState("");
    const [actionError, setActionError] = useState(location.state?.error || "");
    const [busy, setBusy] = useState(false);

    // "submit" | "approve" | "return" | "reject" | "cancel" | "delete" | null
    const [dialog, setDialog] = useState(null);
    const [dialogKey, setDialogKey] = useState(0);


    const load = useCallback(() =>
        getPurchaseRequestByIdApi(id)
            .then(data => { setRequest(data); setError(""); })
            .catch(err => setError(getApiErrorMessage(err, "Failed to load the purchase request."))),
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
            if (updated) setRequest(updated);
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
            title="Purchase Request"
            subtitle={request ? `${request.requestCode} · ${request.title}` : ""}
            action={() => navigate("/purchase-requests")}
            actionLabel="Back"
            actionIcon={<ArrowBack />}
        />
    );

    if (!request) {
        return (
            <PageContainer>
                {header}
                {error ? <Alert severity="error">{error}</Alert> : <PageCard><LoadingState message="Loading purchase request..." /></PageCard>}
            </PageContainer>
        );
    }


    const { line } = request;
    const budgetCurrency = request.budgetCurrency;
    const editable = EDITABLE_STATUSES.includes(request.status);
    const submitted = request.status === PURCHASE_REQUEST_STATUS.SUBMITTED;
    const approved = request.status === PURCHASE_REQUEST_STATUS.APPROVED;
    const canApprove = hasPermission(user, "purchase_request.approve");

    const can = {
        edit: editable && hasPermission(user, "purchase_request.update"),
        delete: editable && hasPermission(user, "purchase_request.delete"),
        submit: editable && hasPermission(user, "purchase_request.update"),
        review: submitted && canApprove,
        cancel: approved && canApprove
    };

    const overText =
        line.overBudget
            ? `${line.category} has ${formatMoney(Math.max(0, line.available), budgetCurrency)} left in ${fiscalYearLabel(line.fiscalYear)}; this request is ${formatMoney(request.budgetAmount, budgetCurrency)}.`
            : null;

    const foreign = request.currency !== budgetCurrency;


    return (

        <PageContainer>

            {header}

            {actionError && !dialog && (
                <Alert severity="error" sx={{ mb: 3 }} onClose={() => setActionError("")}>{actionError}</Alert>
            )}

            {request.status === PURCHASE_REQUEST_STATUS.RETURNED && request.reviewComment && (
                <Alert severity="warning" sx={{ mb: 3 }}><strong>Returned for changes:</strong> {request.reviewComment}</Alert>
            )}

            {request.status === PURCHASE_REQUEST_STATUS.REJECTED && (
                <Alert severity="error" sx={{ mb: 3 }}>
                    <strong>Rejected</strong> {request.rejectedBy?.name ? `by ${request.rejectedBy.name} ` : ""}on {formatDate(request.rejectedAt)}{request.reviewComment ? `: ${request.reviewComment}` : "."}
                </Alert>
            )}

            {request.status === PURCHASE_REQUEST_STATUS.CANCELLED && (
                <Alert severity="info" sx={{ mb: 3 }}>
                    <strong>Cancelled</strong> {request.cancelledBy?.name ? `by ${request.cancelledBy.name} ` : ""}on {formatDate(request.cancelledAt)}: {request.cancelReason}. Its money is released on the budget line.
                </Alert>
            )}

            {approved && (
                <Alert severity="success" sx={{ mb: 3 }}>
                    Approved {request.approvedBy?.name ? `by ${request.approvedBy.name} ` : ""}on {formatDate(request.approvedAt)}. {formatMoney(request.budgetAmount, budgetCurrency)} is committed on the budget line.
                    {request.reviewComment ? ` Comment: ${request.reviewComment}` : ""}
                </Alert>
            )}

            {request.status === PURCHASE_REQUEST_STATUS.ORDERED && request.purchaseOrder && (
                <Alert severity="success" sx={{ mb: 3 }}>
                    Ordered:{" "}
                    <Link component="button" underline="hover" onClick={() => navigate(`/purchase-orders/${request.purchaseOrder._id}`)}>
                        {request.purchaseOrder.poCode}
                    </Link>{" "}
                    for {formatMoney(request.purchaseOrder.total, request.currency)}; this amount is now committed on the budget line instead of the estimate.
                </Alert>
            )}

            {(editable || submitted) && overText && (
                <Alert severity="warning" sx={{ mb: 3 }}>
                    {overText} It cannot be {submitted ? "approved" : "submitted"} until it is reduced or the budget is revised.
                </Alert>
            )}


            {(can.edit || can.delete || can.submit || can.review || can.cancel) && (
                <PageCard>
                    <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
                        {can.edit && <AppButton variant="outlined" startIcon={<Edit />} onClick={() => navigate(`/purchase-requests/${id}/edit`)}>Edit</AppButton>}
                        {can.submit && <AppButton variant="contained" startIcon={<Send />} disabled={line.overBudget} onClick={() => openDialog("submit")}>Submit for Approval</AppButton>}
                        {can.review && <AppButton variant="contained" color="success" startIcon={<CheckCircle />} disabled={line.overBudget} onClick={() => openDialog("approve")}>Approve</AppButton>}
                        {can.review && <AppButton variant="outlined" color="warning" startIcon={<Undo />} onClick={() => openDialog("return")}>Return for Changes</AppButton>}
                        {can.review && <AppButton variant="outlined" color="error" startIcon={<DoNotDisturb />} onClick={() => openDialog("reject")}>Reject</AppButton>}
                        {can.cancel && <AppButton variant="outlined" color="error" startIcon={<Block />} onClick={() => openDialog("cancel")}>Cancel Request</AppButton>}
                        {can.delete && <AppButton variant="outlined" color="error" startIcon={<Delete />} onClick={() => openDialog("delete")}>Delete</AppButton>}
                    </Stack>
                </PageCard>
            )}


            <StatsCards
                valueSize="small"
                items={[
                    { label: request.status === PURCHASE_REQUEST_STATUS.ORDERED ? "Ordered" : "This request", value: formatMoney(line.takes ?? request.budgetAmount, budgetCurrency) },
                    { label: `Line budget ${fiscalYearLabel(line.fiscalYear)}`, value: formatMoney(line.budget, budgetCurrency) },
                    { label: "Spent + committed by others", value: formatMoney(line.spent + line.committedByOthers, budgetCurrency) },
                    { label: "Left after this", value: formatMoney(line.remainingAfter, budgetCurrency) }
                ]}
            />


            <PageCard>
                <FormSection title="Items">
                    <TableContainer>
                        <Table size="small">
                            <TableHead>
                                <TableRow>
                                    <TableCell>#</TableCell>
                                    <TableCell>Item</TableCell>
                                    <TableCell>Unit</TableCell>
                                    <TableCell align="right">Quantity</TableCell>
                                    <TableCell align="right">Est. unit price</TableCell>
                                    <TableCell align="right">Total</TableCell>
                                </TableRow>
                            </TableHead>
                            <TableBody>
                                {(request.items || []).map((item, index) => (
                                    <TableRow key={item._id || index}>
                                        <TableCell>{index + 1}</TableCell>
                                        <TableCell>
                                            <Typography variant="body2" sx={{ fontWeight: 600 }}>{item.description}</Typography>
                                            {item.specification && <Typography variant="caption" color="text.secondary">{item.specification}</Typography>}
                                        </TableCell>
                                        <TableCell>{item.unit}</TableCell>
                                        <TableCell align="right">{Number(item.quantity).toLocaleString("en-US")}</TableCell>
                                        <TableCell align="right" sx={{ whiteSpace: "nowrap" }}>{formatMoney(item.unitPrice, request.currency)}</TableCell>
                                        <TableCell align="right" sx={{ whiteSpace: "nowrap", fontWeight: 600 }}>{formatMoney(item.total, request.currency)}</TableCell>
                                    </TableRow>
                                ))}
                                <TableRow>
                                    <TableCell colSpan={5} align="right" sx={{ fontWeight: 700 }}>Estimated total</TableCell>
                                    <TableCell align="right" sx={{ whiteSpace: "nowrap", fontWeight: 700 }}>{formatMoney(request.estimatedTotal, request.currency)}</TableCell>
                                </TableRow>
                                {foreign && (
                                    <TableRow>
                                        <TableCell colSpan={5} align="right" sx={{ color: "text.secondary" }}>In the budget's currency (× {request.exchangeRate})</TableCell>
                                        <TableCell align="right" sx={{ whiteSpace: "nowrap", fontWeight: 700 }}>{formatMoney(request.budgetAmount, budgetCurrency)}</TableCell>
                                    </TableRow>
                                )}
                            </TableBody>
                        </Table>
                    </TableContainer>
                </FormSection>
            </PageCard>


            <SourcingCard request={request} user={user} onChange={setRequest} navigate={navigate} />


            <PageCard>
                <FormSection title="Request">
                    <InfoRow label="Request Code" value={request.requestCode} />
                    <InfoRow label="Status" value={<StatusChip status={request.status} />} />
                    <InfoRow label="Title" value={request.title} />
                    <InfoRow label="Why it is needed" value={request.justification || "-"} />
                    <InfoRow label="Request date" value={formatDate(request.requestDate)} />
                    <InfoRow label="Needed by" value={request.neededBy ? formatDate(request.neededBy) : "-"} />
                    <InfoRow label="Deliver to" value={request.deliveryLocation || "-"} />
                    <InfoRow
                        label="Suggested supplier"
                        value={
                            request.suggestedSupplier
                                ? (
                                    <Link component="button" underline="hover" onClick={() => navigate(`/suppliers/${request.suggestedSupplier._id}`)}>
                                        {request.suggestedSupplier.supplierCode} · {request.suggestedSupplier.name}
                                    </Link>
                                )
                                : "-"
                        }
                    />
                    <InfoRow label="Requested by" value={request.createdBy?.name || "-"} />
                </FormSection>
            </PageCard>


            <PageCard>
                <FormSection title="Charged To">
                    <InfoRow
                        label="Budget"
                        value={
                            <Link component="button" underline="hover" onClick={() => navigate(`/budgets/${request.budget?._id}`)}>
                                {request.budget?.budgetCode} · {request.budget?.name}
                            </Link>
                        }
                    />
                    <InfoRow label="Budget line" value={`${line.category}${line.description ? ` — ${line.description}` : ""}`} />
                    <InfoRow label="Fiscal year" value={fiscalYearLabel(line.fiscalYear)} />
                    <InfoRow label="Program" value={request.program?.name} />
                    <InfoRow label="Project" value={request.project?.name} />
                    <InfoRow label="Activity" value={request.activity ? `${request.activity.activityCode} · ${request.activity.name}` : "-"} />
                    <Box sx={{ mt: 1 }}>
                        <Typography variant="body2" color="text.secondary">
                            Line {fiscalYearLabel(line.fiscalYear)}: budget {formatMoney(line.budget, budgetCurrency)} · spent {formatMoney(line.spent, budgetCurrency)} · committed by other requests {formatMoney(line.committedByOthers, budgetCurrency)} · left before this request {formatMoney(line.available, budgetCurrency)}
                        </Typography>
                    </Box>
                </FormSection>
            </PageCard>


            <PageCard>
                <FormSection title="History">
                    {(request.history || []).slice().reverse().map((entry, index) => (
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
                message={actionError || "The request will be locked while it is reviewed. The approvers are notified."}
                confirmLabel="Submit"
                loading={busy}
                onClose={closeDialog}
                onConfirm={() => run(() => submitPurchaseRequestApi(id))}
            />

            <ExpenseActionDialog
                key={`approve-${dialogKey}`}
                open={dialog === "approve"}
                title="Approve Purchase Request"
                message={`${formatMoney(request.budgetAmount, budgetCurrency)} will be committed on ${line.category} (${fiscalYearLabel(line.fiscalYear)}), and the request locked.`}
                confirmLabel="Approve"
                confirmColor="success"
                loading={busy}
                error={actionError}
                onClose={closeDialog}
                onConfirm={({ comment }) => run(() => approvePurchaseRequestApi(id, { comment }))}
            />

            <ExpenseActionDialog
                key={`return-${dialogKey}`}
                open={dialog === "return"}
                title="Return for Changes"
                message="The requester will see your comment and can correct and resubmit it."
                commentLabel="What needs to change"
                requireComment
                confirmLabel="Return"
                confirmColor="warning"
                loading={busy}
                error={actionError}
                onClose={closeDialog}
                onConfirm={({ comment }) => run(() => returnPurchaseRequestApi(id, comment))}
            />

            <ExpenseActionDialog
                key={`reject-${dialogKey}`}
                open={dialog === "reject"}
                title="Reject Purchase Request"
                message="Rejection is final: the request cannot be resubmitted. To ask for changes, return it instead."
                commentLabel="Reason"
                requireComment
                confirmLabel="Reject"
                confirmColor="error"
                loading={busy}
                error={actionError}
                onClose={closeDialog}
                onConfirm={({ comment }) => run(() => rejectPurchaseRequestApi(id, comment))}
            />

            <ExpenseActionDialog
                key={`cancel-${dialogKey}`}
                open={dialog === "cancel"}
                title="Cancel Purchase Request"
                message="The request stays on record; its committed money is released on the budget line."
                commentLabel="Reason"
                requireComment
                confirmLabel="Cancel Request"
                confirmColor="error"
                loading={busy}
                error={actionError}
                onClose={closeDialog}
                onConfirm={({ comment }) => run(() => cancelPurchaseRequestApi(id, comment))}
            />

            <ConfirmDeleteDialog
                open={dialog === "delete"}
                title="Delete Purchase Request"
                message={`Delete ${request.requestCode} "${request.title}"?`}
                loading={busy}
                onClose={closeDialog}
                onConfirm={() => run(async () => { await deletePurchaseRequestApi(id); navigate("/purchase-requests"); return null; })}
            />

        </PageContainer>

    );

};


export default PurchaseRequestDetailsPage;
