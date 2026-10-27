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
    Typography
} from "@mui/material";

import {
    AppButton,
    AppDatePicker,
    AppTextField,
    FormGrid
} from "../../../components/ui";

import {
    formatMoney
} from "../../budgets/utils/budgetUtils";


// =====================================================
// ISSUE THE PURCHASE ORDER (from the approved bid analysis)
// =====================================================
//
// Items and prices come from the winning quotation. The
// delivery date defaults to the quoted delivery time.
//
// =====================================================

const today = () => new Date().toISOString().slice(0, 10);

const plusDays = (day, days) => {
    const date = new Date(`${day}T00:00:00Z`);
    date.setUTCDate(date.getUTCDate() + Number(days));
    return date.toISOString().slice(0, 10);
};

const IssueOrderDialog = ({ open, request, winner, loading = false, error = "", onClose, onIssue }) => {

    const [form, setForm] = useState(() => ({
        orderDate: today(),
        deliveryDate:
            Number.isInteger(winner?.deliveryDays)
                ? plusDays(today(), winner.deliveryDays)
                : request.neededBy ? String(request.neededBy).slice(0, 10) : "",
        deliveryLocation: request.deliveryLocation || "",
        paymentTerms: "",
        notes: ""
    }));

    const change = (patch) => setForm(prev => ({ ...prev, ...patch }));

    return (
        <Dialog open={open} onClose={loading ? undefined : onClose} fullWidth maxWidth="sm">

            <DialogTitle sx={{ fontWeight: 700 }}>Issue Purchase Order</DialogTitle>

            <DialogContent>

                {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    To <strong>{winner?.supplier?.name}</strong> for {formatMoney(winner?.total || 0, request.currency)}, at the quoted prices.
                    This amount replaces the estimate as committed on the budget line.
                </Typography>

                <FormGrid columns={2}>
                    <AppDatePicker
                        label="Order date"
                        required
                        value={form.orderDate || null}
                        maxDate={today()}
                        onChange={(date) => change({ orderDate: date ? date.format("YYYY-MM-DD") : "" })}
                    />
                    <AppDatePicker
                        label="Deliver by"
                        value={form.deliveryDate || null}
                        minDate={form.orderDate || undefined}
                        onChange={(date) => change({ deliveryDate: date ? date.format("YYYY-MM-DD") : "" })}
                        helperText={Number.isInteger(winner?.deliveryDays) ? `Quoted: ${winner.deliveryDays} days` : ""}
                    />
                </FormGrid>

                <Box sx={{ mt: 2 }}>
                    <AppTextField label="Deliver to" value={form.deliveryLocation} onChange={(e) => change({ deliveryLocation: e.target.value })} />
                </Box>
                <Box sx={{ mt: 2 }}>
                    <AppTextField label="Payment terms" placeholder="e.g. 30 days after delivery, by bank transfer" value={form.paymentTerms} onChange={(e) => change({ paymentTerms: e.target.value })} />
                </Box>
                <Box sx={{ mt: 2 }}>
                    <AppTextField label="Notes for the supplier" multiline rows={2} value={form.notes} onChange={(e) => change({ notes: e.target.value })} />
                </Box>

            </DialogContent>

            <DialogActions sx={{ px: 3, pb: 2 }}>
                <AppButton variant="outlined" onClick={onClose} disabled={loading}>Cancel</AppButton>
                <AppButton variant="contained" loading={loading} disabled={!form.orderDate} onClick={() => onIssue({ ...form, deliveryDate: form.deliveryDate || null })}>
                    Issue Order
                </AppButton>
            </DialogActions>

        </Dialog>
    );

};


export default IssueOrderDialog;
