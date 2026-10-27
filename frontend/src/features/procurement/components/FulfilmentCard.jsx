import {
    useState
} from "react";

import {
    Alert,
    Box,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Link,
    Stack,
    Typography
} from "@mui/material";

import {
    DoneAll,
    Inventory,
    Payments
} from "@mui/icons-material";

import {
    AppButton,
    AppDatePicker,
    AppSelect,
    AppTextField,
    FormGrid,
    FormSection,
    InfoRow,
    PageCard,
    StatusChip,
    StatsCards
} from "../../../components/ui";

import ExpenseActionDialog
    from "../../expenses/components/ExpenseActionDialog";

import {
    recordReceiptApi,
    cancelReceiptApi,
    createPaymentApi,
    closeOrderApi
} from "../api/procurementApi";

import {
    getApiErrorMessage
} from "../../budgets/api/budgetApi";

import {
    formatMoney,
    hasPermission
} from "../../budgets/utils/budgetUtils";

import {
    PAYMENT_METHODS
} from "../../expenses/utils/expenseUtils";

import {
    PURCHASE_ORDER_STATUS,
    formatDate,
    idOf
} from "../utils/procurementUtils";


const today = () => new Date().toISOString().slice(0, 10);

const OPEN = [PURCHASE_ORDER_STATUS.ISSUED, PURCHASE_ORDER_STATUS.PARTIALLY_RECEIVED, PURCHASE_ORDER_STATUS.RECEIVED];


// =====================================================
// RECORD GOODS RECEIVED (dialog)
// =====================================================

const ReceiptDialog = ({ order, loading, error, onClose, onSave }) => {

    const received = order.fulfilment?.received || {};

    const [form, setForm] = useState(() => ({
        receivedDate: today(),
        deliveryNote: "",
        notes: "",
        lines: Object.fromEntries(order.items.map(item => {
            const left = Math.max(0, item.quantity - (received[idOf(item._id)]?.accepted || 0));
            return [idOf(item._id), { accepted: left ? String(left) : "", rejected: "", remark: "" }];
        }))
    }));

    const changeLine = (key, patch) =>
        setForm(prev => ({ ...prev, lines: { ...prev.lines, [key]: { ...prev.lines[key], ...patch } } }));

    return (
        <Dialog open onClose={loading ? undefined : onClose} fullWidth maxWidth="md">
            <DialogTitle sx={{ fontWeight: 700 }}>Record Goods Received</DialogTitle>
            <DialogContent>
                {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
                <Box sx={{ mt: 1 }}>
                    <FormGrid columns={2}>
                        <AppDatePicker
                            label="Received on"
                            required
                            value={form.receivedDate || null}
                            minDate={String(order.orderDate).slice(0, 10)}
                            maxDate={today()}
                            onChange={(date) => setForm(prev => ({ ...prev, receivedDate: date ? date.format("YYYY-MM-DD") : "" }))}
                        />
                        <AppTextField label="Supplier's delivery note no." value={form.deliveryNote} onChange={(e) => setForm(prev => ({ ...prev, deliveryNote: e.target.value }))} />
                    </FormGrid>
                </Box>

                <Typography variant="subtitle2" sx={{ mt: 3, mb: 1 }}>
                    What arrived: accepted goods count as received and can be paid; rejected goods go back to the supplier.
                </Typography>

                <Stack spacing={1.5}>
                    {order.items.map((item, index) => {
                        const key = idOf(item._id);
                        const done = received[key]?.accepted || 0;
                        const left = Math.max(0, item.quantity - done);
                        const line = form.lines[key];
                        return (
                            <Box key={key} sx={{ p: 1.5, border: "1px solid", borderColor: "divider", borderRadius: 2, opacity: left ? 1 : 0.6 }}>
                                <Typography variant="body2" sx={{ fontWeight: 600 }}>{index + 1}. {item.description}</Typography>
                                <Typography variant="caption" color="text.secondary">
                                    Ordered {item.quantity} {item.unit} · received so far {done} · left {left}
                                </Typography>
                                {left > 0 && (
                                    <Box sx={{ mt: 1 }}>
                                        <FormGrid columns={3}>
                                            <AppTextField
                                                label="Accepted"
                                                type="number"
                                                value={line.accepted}
                                                onChange={(e) => changeLine(key, { accepted: e.target.value })}
                                                inputProps={{ min: 0, max: left, step: "any" }}
                                                error={Number(line.accepted) > left}
                                                helperText={Number(line.accepted) > left ? `At most ${left}` : ""}
                                            />
                                            <AppTextField
                                                label="Rejected"
                                                type="number"
                                                value={line.rejected}
                                                onChange={(e) => changeLine(key, { rejected: e.target.value })}
                                                inputProps={{ min: 0, step: "any" }}
                                            />
                                            <AppTextField
                                                label={Number(line.rejected) > 0 ? "Why rejected (required)" : "Remark"}
                                                value={line.remark}
                                                onChange={(e) => changeLine(key, { remark: e.target.value })}
                                            />
                                        </FormGrid>
                                    </Box>
                                )}
                            </Box>
                        );
                    })}
                </Stack>

                <Box sx={{ mt: 2 }}>
                    <AppTextField label="Notes" multiline rows={2} value={form.notes} onChange={(e) => setForm(prev => ({ ...prev, notes: e.target.value }))} />
                </Box>
            </DialogContent>
            <DialogActions sx={{ px: 3, pb: 2 }}>
                <AppButton variant="outlined" onClick={onClose} disabled={loading}>Cancel</AppButton>
                <AppButton
                    variant="contained"
                    loading={loading}
                    disabled={!form.receivedDate}
                    onClick={() => onSave({
                        receivedDate: form.receivedDate,
                        deliveryNote: form.deliveryNote.trim(),
                        notes: form.notes.trim(),
                        lines: Object.entries(form.lines)
                            .map(([item, line]) => ({ item, accepted: Number(line.accepted || 0), rejected: Number(line.rejected || 0), remark: line.remark.trim() }))
                            .filter(line => line.accepted > 0 || line.rejected > 0)
                    })}
                >
                    Record
                </AppButton>
            </DialogActions>
        </Dialog>
    );

};


// =====================================================
// RECORD PAYMENT (dialog): a Draft expense linked to the order
// =====================================================

const PaymentDialog = ({ order, loading, error, onClose, onSave }) => {

    const payable = order.fulfilment?.payable || 0;
    const foreign = order.currency !== order.budgetCurrency;

    const [form, setForm] = useState(() => ({
        amount: String(payable),
        expenseDate: today(),
        referenceNumber: "",
        paymentMethod: "Bank Transfer",
        exchangeRate: foreign ? String(order.exchangeRate) : ""
    }));

    const change = (patch) => setForm(prev => ({ ...prev, ...patch }));
    const amount = Number(form.amount || 0);

    return (
        <Dialog open onClose={loading ? undefined : onClose} fullWidth maxWidth="sm">
            <DialogTitle sx={{ fontWeight: 700 }}>Record Payment</DialogTitle>
            <DialogContent>
                {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    To <strong>{order.supplier?.name}</strong>. Up to {formatMoney(payable, order.currency)} can be paid: the goods received and not yet paid.
                    It is saved as an expense on {order.budget?.budgetCode} · {order.category}; once approved, it moves from Committed to Spent.
                </Typography>
                <FormGrid columns={2}>
                    <AppTextField
                        label={`Amount (${order.currency})`}
                        required
                        type="number"
                        value={form.amount}
                        onChange={(e) => change({ amount: e.target.value })}
                        inputProps={{ min: 0, max: payable, step: "any" }}
                        error={amount > payable + 0.005}
                        helperText={amount > payable + 0.005 ? `At most ${formatMoney(payable, order.currency)}` : ""}
                    />
                    <AppDatePicker
                        label="Paid on"
                        required
                        value={form.expenseDate || null}
                        maxDate={today()}
                        onChange={(date) => change({ expenseDate: date ? date.format("YYYY-MM-DD") : "" })}
                    />
                    <AppTextField label="Supplier's invoice no." value={form.referenceNumber} onChange={(e) => change({ referenceNumber: e.target.value })} />
                    <AppSelect
                        label="Payment method"
                        value={form.paymentMethod}
                        onChange={(e) => change({ paymentMethod: e.target.value })}
                        options={PAYMENT_METHODS.map(value => ({ value, label: value }))}
                    />
                    {foreign && (
                        <AppTextField
                            label={`Exchange rate (1 ${order.currency} = ? ${order.budgetCurrency})`}
                            type="number"
                            value={form.exchangeRate}
                            onChange={(e) => change({ exchangeRate: e.target.value })}
                            helperText={`Order rate: ${order.exchangeRate}`}
                        />
                    )}
                </FormGrid>
            </DialogContent>
            <DialogActions sx={{ px: 3, pb: 2 }}>
                <AppButton variant="outlined" onClick={onClose} disabled={loading}>Cancel</AppButton>
                <AppButton
                    variant="contained"
                    loading={loading}
                    disabled={!(amount > 0) || amount > payable + 0.005 || !form.expenseDate}
                    onClick={() => onSave({
                        amount,
                        expenseDate: form.expenseDate,
                        referenceNumber: form.referenceNumber.trim(),
                        paymentMethod: form.paymentMethod,
                        ...(foreign ? { exchangeRate: Number(form.exchangeRate) } : {})
                    })}
                >
                    Save Payment
                </AppButton>
            </DialogActions>
        </Dialog>
    );

};


// =====================================================
// RECEIVING AND PAYMENT (purchase order page)
// =====================================================

const FulfilmentCard = ({ order, user, onChange, navigate }) => {

    const fulfilment = order.fulfilment || {};
    const open = OPEN.includes(order.status);

    const [dialog, setDialog] = useState(null);
    const [dialogKey, setDialogKey] = useState(0);
    const [target, setTarget] = useState(null);
    const [busy, setBusy] = useState("");
    const [error, setError] = useState("");

    const can = {
        receive: [PURCHASE_ORDER_STATUS.ISSUED, PURCHASE_ORDER_STATUS.PARTIALLY_RECEIVED].includes(order.status) && hasPermission(user, "goods_receipt.create"),
        // not once the goods are being paid
        cancelReceipt: open && !(fulfilment.payments || []).some(payment => payment.status !== "Voided") && hasPermission(user, "goods_receipt.update"),
        pay: [PURCHASE_ORDER_STATUS.PARTIALLY_RECEIVED, PURCHASE_ORDER_STATUS.RECEIVED].includes(order.status) && fulfilment.payable > 0.005 && hasPermission(user, "expense.create"),
        close: [PURCHASE_ORDER_STATUS.PARTIALLY_RECEIVED, PURCHASE_ORDER_STATUS.RECEIVED].includes(order.status)
            && !fulfilment.pendingPayments && fulfilment.paid >= fulfilment.receivedValue - 0.005
            && hasPermission(user, "purchase_order.update")
    };

    const openDialog = (name, item = null) => {
        setError("");
        setTarget(item);
        setDialogKey(key => key + 1);
        setDialog(name);
    };

    const run = async (name, action) => {
        setBusy(name);
        setError("");
        try {
            const updated = await action();
            if (updated) onChange(updated);
            setDialog(null);
        }
        catch (err) {
            setError(getApiErrorMessage(err, "The action failed."));
        }
        finally {
            setBusy("");
        }
    };

    if (order.status === PURCHASE_ORDER_STATUS.CANCELLED) return null;

    const unpaid = Math.max(0, order.total - (order.paidTotal || 0));

    return (
        <PageCard>
            <FormSection
                title="Receiving and Payment"
                subtitle="Record what arrives (partial deliveries are fine), then pay what was received. Payments are expenses linked to this order."
            >
                {error && !dialog && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError("")}>{error}</Alert>}

                {order.status === PURCHASE_ORDER_STATUS.CLOSED && (
                    <Alert severity="success" sx={{ mb: 2 }}>
                        Closed{order.closedAt ? ` on ${formatDate(order.closedAt)}` : ""}{order.closeReason ? ` short: ${order.closeReason}` : ": everything received and paid"}. Nothing is committed for it any more.
                    </Alert>
                )}

                <StatsCards
                    valueSize="small"
                    items={[
                        { label: "Received (value)", value: formatMoney(fulfilment.receivedValue || 0, order.currency) },
                        { label: "Paid (approved)", value: formatMoney(fulfilment.paid || 0, order.currency) },
                        { label: "Payment waiting approval", value: formatMoney(fulfilment.pendingPayments || 0, order.currency) },
                        { label: open ? "Still to pay on the order" : "Not paid", value: formatMoney(unpaid, order.currency) }
                    ]}
                />

                {(can.receive || can.pay || can.close) && (
                    <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} sx={{ my: 2 }}>
                        {can.receive && <AppButton variant="contained" startIcon={<Inventory />} onClick={() => openDialog("receive")}>Record Goods Received</AppButton>}
                        {can.pay && <AppButton variant="contained" color="success" startIcon={<Payments />} onClick={() => openDialog("pay")}>Record Payment ({formatMoney(fulfilment.payable, order.currency)})</AppButton>}
                        {can.close && order.status === PURCHASE_ORDER_STATUS.PARTIALLY_RECEIVED && (
                            <AppButton variant="outlined" startIcon={<DoneAll />} onClick={() => openDialog("close")}>Close Short</AppButton>
                        )}
                    </Stack>
                )}

                <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>Goods received notes</Typography>
                {(fulfilment.receipts || []).length === 0
                    ? <Typography variant="body2" color="text.secondary">Nothing received yet.</Typography>
                    : fulfilment.receipts.map(note => (
                        <Box key={note._id} sx={{ p: 1.5, mb: 1, border: "1px solid", borderColor: "divider", borderRadius: 2, opacity: note.status === "Cancelled" ? 0.6 : 1 }}>
                            <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap" }}>
                                <Typography variant="body2" sx={{ fontWeight: 700 }}>{note.grnCode}</Typography>
                                <Typography variant="body2" color="text.secondary">
                                    {formatDate(note.receivedDate)}{note.deliveryNote ? ` · delivery note ${note.deliveryNote}` : ""}{note.receivedBy?.name ? ` · by ${note.receivedBy.name}` : ""}
                                </Typography>
                                <StatusChip status={note.status} />
                                <Box sx={{ flex: 1 }} />
                                <Typography variant="body2" sx={{ fontWeight: 600 }}>{formatMoney(note.value, order.currency)}</Typography>
                                {can.cancelReceipt && note.status === "Recorded" && (
                                    <Link component="button" color="error" underline="hover" onClick={() => openDialog("cancelReceipt", note)}>Cancel</Link>
                                )}
                            </Stack>
                            {note.lines.map(line => (
                                <Typography key={idOf(line.item)} variant="caption" sx={{ display: "block" }}>
                                    {line.description}: {line.accepted} {line.unit} accepted
                                    {line.rejected ? `, ${line.rejected} rejected` : ""}{line.remark ? ` (${line.remark})` : ""}
                                </Typography>
                            ))}
                            {note.status === "Cancelled" && (
                                <Typography variant="caption" color="error" sx={{ display: "block" }}>Cancelled: {note.cancelReason}</Typography>
                            )}
                        </Box>
                    ))}

                <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>Payments</Typography>
                {(fulfilment.payments || []).length === 0
                    ? <Typography variant="body2" color="text.secondary">No payments yet.</Typography>
                    : fulfilment.payments.map(payment => (
                        <InfoRow
                            key={payment._id}
                            label={formatDate(payment.expenseDate)}
                            value={
                                <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap" }}>
                                    <Link component="button" underline="hover" onClick={() => navigate(`/expenses/${payment._id}`)}>{payment.expenseCode}</Link>
                                    <Typography variant="body2">{formatMoney(payment.amount, payment.currency)}</Typography>
                                    {payment.referenceNumber && <Typography variant="body2" color="text.secondary">invoice {payment.referenceNumber}</Typography>}
                                    <StatusChip status={payment.status} />
                                </Stack>
                            }
                        />
                    ))}
            </FormSection>

            {dialog === "receive" && (
                <ReceiptDialog
                    key={`receive-${dialogKey}`}
                    order={order}
                    loading={busy === "receive"}
                    error={error}
                    onClose={() => !busy && setDialog(null)}
                    onSave={(body) => run("receive", () => recordReceiptApi(order._id, body))}
                />
            )}

            {dialog === "pay" && (
                <PaymentDialog
                    key={`pay-${dialogKey}`}
                    order={order}
                    loading={busy === "pay"}
                    error={error}
                    onClose={() => !busy && setDialog(null)}
                    onSave={(body) => run("pay", async () => {
                        const expense = await createPaymentApi(order._id, body);
                        navigate(`/expenses/${expense._id}`);
                        return null;
                    })}
                />
            )}

            <ExpenseActionDialog
                key={`cancelReceipt-${dialogKey}`}
                open={dialog === "cancelReceipt"}
                title={`Cancel ${target?.grnCode || "Goods Received Note"}`}
                message="Use this to correct a mistake. Its goods no longer count as received. Not possible once the order has payments."
                commentLabel="Reason"
                requireComment
                confirmLabel="Cancel Note"
                confirmColor="error"
                loading={busy === "cancelReceipt"}
                error={error}
                onClose={() => !busy && setDialog(null)}
                onConfirm={({ comment }) => run("cancelReceipt", () => cancelReceiptApi(target._id, comment))}
            />

            <ExpenseActionDialog
                key={`close-${dialogKey}`}
                open={dialog === "close"}
                title="Close the Order Short"
                message={`What was received is paid. The rest (${formatMoney(unpaid, order.currency)}) will not be delivered and is released from Committed on the budget line.`}
                commentLabel="Reason"
                requireComment
                confirmLabel="Close Order"
                loading={busy === "close"}
                error={error}
                onClose={() => !busy && setDialog(null)}
                onConfirm={({ comment }) => run("close", () => closeOrderApi(order._id, comment))}
            />
        </PageCard>
    );

};


export default FulfilmentCard;
