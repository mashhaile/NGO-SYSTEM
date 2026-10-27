import {
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
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
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
    Edit,
    PictureAsPdf
} from "@mui/icons-material";

import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    FormGrid,
    InfoRow,
    AppButton,
    AppDatePicker,
    AppTextField,
    StatusChip,
    StatsCards,
    LoadingState
} from "../../../components/ui";

import ExpenseActionDialog
    from "../../expenses/components/ExpenseActionDialog";

import FulfilmentCard
    from "../components/FulfilmentCard";

import useAuth
    from "../../auth/hooks/useAuth";

import {
    getPurchaseOrderByIdApi,
    updatePurchaseOrderApi,
    cancelPurchaseOrderApi,
    downloadPurchaseOrderPdfApi
} from "../api/procurementApi";

import {
    getApiErrorMessage
} from "../../budgets/api/budgetApi";

import {
    formatMoney,
    hasPermission
} from "../../budgets/utils/budgetUtils";

import {
    PURCHASE_ORDER_STATUS,
    formatDate
} from "../utils/procurementUtils";

import {
    fiscalYearLabel
} from "../../../utils/fiscalYear";

import { formatDateTime } from "../../../utils/date";


// =====================================================
// PURCHASE ORDER DETAILS
// =====================================================

const PurchaseOrderDetailsPage = () => {

    const { id } = useParams();

    const navigate = useNavigate();

    const { user } = useAuth();

    const [order, setOrder] = useState(null);
    const [error, setError] = useState("");
    const [actionError, setActionError] = useState("");
    const [busy, setBusy] = useState("");

    // "edit" | "cancel" | null
    const [dialog, setDialog] = useState(null);
    const [dialogKey, setDialogKey] = useState(0);
    const [edit, setEdit] = useState(null);


    useEffect(() => {
        getPurchaseOrderByIdApi(id)
            .then(setOrder)
            .catch(err => setError(getApiErrorMessage(err, "Failed to load the purchase order.")));
    }, [id]);


    const run = async (name, action) => {
        setBusy(name);
        setActionError("");
        try {
            const updated = await action();
            if (updated) setOrder(updated);
            setDialog(null);
        }
        catch (err) {
            setActionError(getApiErrorMessage(err, "The action failed."));
        }
        finally {
            setBusy("");
        }
    };

    const openDialog = (name) => {
        setActionError("");
        setDialogKey(key => key + 1);
        if (name === "edit") {
            setEdit({
                deliveryDate: order.deliveryDate ? String(order.deliveryDate).slice(0, 10) : "",
                deliveryLocation: order.deliveryLocation || "",
                paymentTerms: order.paymentTerms || "",
                notes: order.notes || ""
            });
        }
        setDialog(name);
    };


    const header = (
        <PageHeader
            title="Purchase Order"
            subtitle={order ? `${order.poCode} · ${order.supplier?.name}` : ""}
            action={() => navigate("/purchase-orders")}
            actionLabel="Back"
            actionIcon={<ArrowBack />}
        />
    );

    if (!order) {
        return (
            <PageContainer>
                {header}
                {error ? <Alert severity="error">{error}</Alert> : <PageCard><LoadingState message="Loading purchase order..." /></PageCard>}
            </PageContainer>
        );
    }

    const issued = order.status === PURCHASE_ORDER_STATUS.ISSUED;
    const canUpdate = hasPermission(user, "purchase_order.update");
    const canEdit = canUpdate && [PURCHASE_ORDER_STATUS.ISSUED, PURCHASE_ORDER_STATUS.PARTIALLY_RECEIVED].includes(order.status);
    const canCancel = canUpdate && issued;
    const received = order.fulfilment?.received || {};
    const supplier = order.supplier || {};

    return (

        <PageContainer>

            {header}

            {actionError && !dialog && (
                <Alert severity="error" sx={{ mb: 3 }} onClose={() => setActionError("")}>{actionError}</Alert>
            )}

            {order.status === PURCHASE_ORDER_STATUS.CANCELLED && (
                <Alert severity="info" sx={{ mb: 3 }}>
                    <strong>Cancelled</strong> {order.cancelledBy?.name ? `by ${order.cancelledBy.name} ` : ""}on {formatDate(order.cancelledAt)}: {order.cancelReason}. Its money is no longer committed; the request went back to choosing a supplier.
                </Alert>
            )}

            <PageCard>
                <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
                    <AppButton
                        variant="contained"
                        startIcon={<PictureAsPdf />}
                        loading={busy === "pdf"}
                        onClick={() => run("pdf", async () => { await downloadPurchaseOrderPdfApi(order._id, `${order.poCode}.pdf`); return null; })}
                    >
                        Download PDF
                    </AppButton>
                    {canEdit && <AppButton variant="outlined" startIcon={<Edit />} onClick={() => openDialog("edit")}>Edit Delivery / Terms</AppButton>}
                    {canCancel && <AppButton variant="outlined" color="error" startIcon={<Block />} onClick={() => openDialog("cancel")}>Cancel Order</AppButton>}
                </Stack>
            </PageCard>

            <StatsCards
                valueSize="small"
                items={[
                    { label: "Order total", value: formatMoney(order.total, order.currency) },
                    ...(order.currency !== order.budgetCurrency ? [{ label: "In the budget's currency", value: formatMoney(order.budgetAmount, order.budgetCurrency) }] : []),
                    { label: "Ordered", value: formatDate(order.orderDate) },
                    { label: "Deliver by", value: order.deliveryDate ? formatDate(order.deliveryDate) : "-" }
                ]}
            />

            <PageCard>
                <FormSection title="Items (quoted prices)">
                    <TableContainer>
                        <Table size="small">
                            <TableHead>
                                <TableRow>
                                    <TableCell>#</TableCell>
                                    <TableCell>Item</TableCell>
                                    <TableCell>Unit</TableCell>
                                    <TableCell align="right">Quantity</TableCell>
                                    <TableCell align="right">Received</TableCell>
                                    <TableCell align="right">Unit price</TableCell>
                                    <TableCell align="right">Total</TableCell>
                                </TableRow>
                            </TableHead>
                            <TableBody>
                                {order.items.map((item, index) => (
                                    <TableRow key={item._id || index}>
                                        <TableCell>{index + 1}</TableCell>
                                        <TableCell>
                                            <Typography variant="body2" sx={{ fontWeight: 600 }}>{item.description}</Typography>
                                            {item.specification && <Typography variant="caption" color="text.secondary">{item.specification}</Typography>}
                                        </TableCell>
                                        <TableCell>{item.unit}</TableCell>
                                        <TableCell align="right">{Number(item.quantity).toLocaleString("en-US")}</TableCell>
                                        <TableCell align="right" sx={{ color: (received[item._id]?.accepted || 0) >= item.quantity ? "success.dark" : "text.secondary" }}>
                                            {received[item._id]?.accepted || 0}{received[item._id]?.rejected ? ` (+${received[item._id].rejected} rejected)` : ""}
                                        </TableCell>
                                        <TableCell align="right" sx={{ whiteSpace: "nowrap" }}>{formatMoney(item.unitPrice, order.currency)}</TableCell>
                                        <TableCell align="right" sx={{ whiteSpace: "nowrap", fontWeight: 600 }}>{formatMoney(item.total, order.currency)}</TableCell>
                                    </TableRow>
                                ))}
                                <TableRow>
                                    <TableCell colSpan={6} align="right" sx={{ fontWeight: 700 }}>Total</TableCell>
                                    <TableCell align="right" sx={{ whiteSpace: "nowrap", fontWeight: 700 }}>{formatMoney(order.total, order.currency)}</TableCell>
                                </TableRow>
                            </TableBody>
                        </Table>
                    </TableContainer>
                </FormSection>
            </PageCard>

            <FulfilmentCard order={order} user={user} onChange={setOrder} navigate={navigate} />

            <PageCard>
                <FormSection title="Order">
                    <InfoRow label="PO number" value={order.poCode} />
                    <InfoRow label="Status" value={<StatusChip status={order.status} />} />
                    <InfoRow
                        label="Purchase request"
                        value={
                            <Link component="button" underline="hover" onClick={() => navigate(`/purchase-requests/${order.purchaseRequest?._id}`)}>
                                {order.purchaseRequest?.requestCode} · {order.purchaseRequest?.title}
                            </Link>
                        }
                    />
                    <InfoRow
                        label="Method"
                        value={`${order.purchaseRequest?.sourcing?.methodName || "-"}${order.purchaseRequest?.sourcing?.quoteCount ? ` · ${order.purchaseRequest.sourcing.quoteCount} quotation(s)` : ""}${order.purchaseRequest?.sourcing?.committeeName ? ` · ${order.purchaseRequest.sourcing.committeeName}` : ""}`}
                    />
                    <InfoRow label="Quotation no." value={order.quoteReference || "-"} />
                    <InfoRow label="Deliver to" value={order.deliveryLocation || "-"} />
                    <InfoRow label="Payment terms" value={order.paymentTerms || "-"} />
                    {order.notes && <InfoRow label="Notes" value={order.notes} />}
                    <InfoRow label="Issued by" value={order.issuedBy?.name || "-"} />
                </FormSection>
            </PageCard>

            <PageCard>
                <FormSection title="Supplier">
                    <InfoRow
                        label="Supplier"
                        value={
                            <Link component="button" underline="hover" onClick={() => navigate(`/suppliers/${supplier._id}`)}>
                                {supplier.supplierCode} · {supplier.name}
                            </Link>
                        }
                    />
                    <InfoRow label="TIN" value={`${supplier.tin || "-"}${supplier.vatRegistered ? " (VAT registered)" : ""}`} />
                    <InfoRow label="Contact" value={[supplier.contactPerson, supplier.phone, supplier.email].filter(Boolean).join(" · ") || "-"} />
                    <InfoRow label="Bank" value={[supplier.bankName, supplier.bankAccountName, supplier.bankAccountNumber].filter(Boolean).join(" · ") || "-"} />
                </FormSection>
            </PageCard>

            <PageCard>
                <FormSection title="Charged To">
                    <InfoRow
                        label="Budget"
                        value={
                            <Link component="button" underline="hover" onClick={() => navigate(`/budgets/${order.budget?._id}`)}>
                                {order.budget?.budgetCode} · {order.budget?.name}
                            </Link>
                        }
                    />
                    <InfoRow label="Budget line" value={order.category} />
                    <InfoRow label="Fiscal year" value={fiscalYearLabel(order.fiscalYear)} />
                    <InfoRow label="Program" value={order.program?.name} />
                    <InfoRow label="Project" value={order.project?.name} />
                </FormSection>
            </PageCard>

            <PageCard>
                <FormSection title="History">
                    {(order.history || []).slice().reverse().map((entry, index) => (
                        <InfoRow
                            key={index}
                            label={formatDateTime(entry.at)}
                            value={<span><strong>{entry.action}</strong>{entry.by?.name ? ` by ${entry.by.name}` : ""}{entry.comment ? ` — "${entry.comment}"` : ""}</span>}
                        />
                    ))}
                </FormSection>
            </PageCard>


            <Dialog open={dialog === "edit"} onClose={busy ? undefined : () => setDialog(null)} fullWidth maxWidth="sm">
                <DialogTitle sx={{ fontWeight: 700 }}>Edit Delivery and Terms</DialogTitle>
                <DialogContent>
                    {actionError && <Alert severity="error" sx={{ mb: 2 }}>{actionError}</Alert>}
                    {edit && (
                        <Box sx={{ mt: 1 }}>
                            <FormGrid columns={2}>
                                <AppDatePicker
                                    label="Deliver by"
                                    value={edit.deliveryDate || null}
                                    minDate={String(order.orderDate).slice(0, 10)}
                                    onChange={(date) => setEdit(prev => ({ ...prev, deliveryDate: date ? date.format("YYYY-MM-DD") : "" }))}
                                />
                                <AppTextField label="Deliver to" value={edit.deliveryLocation} onChange={(e) => setEdit(prev => ({ ...prev, deliveryLocation: e.target.value }))} />
                            </FormGrid>
                            <Box sx={{ mt: 2 }}>
                                <AppTextField label="Payment terms" value={edit.paymentTerms} onChange={(e) => setEdit(prev => ({ ...prev, paymentTerms: e.target.value }))} />
                            </Box>
                            <Box sx={{ mt: 2 }}>
                                <AppTextField label="Notes for the supplier" multiline rows={2} value={edit.notes} onChange={(e) => setEdit(prev => ({ ...prev, notes: e.target.value }))} />
                            </Box>
                            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
                                Items and prices come from the approved quotation and cannot be changed.
                            </Typography>
                        </Box>
                    )}
                </DialogContent>
                <DialogActions sx={{ px: 3, pb: 2 }}>
                    <AppButton variant="outlined" onClick={() => setDialog(null)} disabled={Boolean(busy)}>Cancel</AppButton>
                    <AppButton variant="contained" loading={busy === "edit"} onClick={() => run("edit", () => updatePurchaseOrderApi(order._id, { ...edit, deliveryDate: edit.deliveryDate || null }))}>
                        Save
                    </AppButton>
                </DialogActions>
            </Dialog>

            <ExpenseActionDialog
                key={`cancel-${dialogKey}`}
                open={dialog === "cancel"}
                title="Cancel Purchase Order"
                message="The order stays on record. The request goes back to choosing a supplier (or can be cancelled), and the request's estimate is committed again."
                commentLabel="Reason"
                requireComment
                confirmLabel="Cancel Order"
                confirmColor="error"
                loading={busy === "cancel"}
                error={actionError}
                onClose={() => !busy && setDialog(null)}
                onConfirm={({ comment }) => run("cancel", () => cancelPurchaseOrderApi(order._id, comment))}
            />

        </PageContainer>

    );

};


export default PurchaseOrderDetailsPage;
