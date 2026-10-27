import {
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
    Stack,
    Typography
} from "@mui/material";

import {
    AppAutoComplete,
    AppButton,
    AppDatePicker,
    AppTextField,
    FormGrid
} from "../../../components/ui";

import {
    getSupplierOptionsApi
} from "../api/procurementApi";

import {
    formatMoney
} from "../../budgets/utils/budgetUtils";

import {
    idOf,
    roundMoney
} from "../utils/procurementUtils";


// =====================================================
// ADD / EDIT A SUPPLIER'S QUOTATION
// =====================================================
//
// A unit price for every item of the request, in the
// request's currency. Mounted with a key per open, so the
// fields start from `quote` (edit) or empty (add).
//
// =====================================================

const today = () => new Date().toISOString().slice(0, 10);

const QuoteDialog = ({ open, request, quote = null, loading = false, error = "", onClose, onSave }) => {

    const [suppliers, setSuppliers] = useState([]);
    const [form, setForm] = useState(() => ({
        supplier: quote ? idOf(quote.supplier) : "",
        reference: quote?.reference || "",
        quoteDate: quote?.quoteDate ? String(quote.quoteDate).slice(0, 10) : today(),
        validUntil: quote?.validUntil ? String(quote.validUntil).slice(0, 10) : "",
        deliveryDays: quote?.deliveryDays ?? "",
        notes: quote?.notes || "",
        prices: Object.fromEntries((request.items || []).map(item => [
            idOf(item._id),
            String(quote?.items?.find(entry => idOf(entry.item) === idOf(item._id))?.unitPrice ?? "")
        ]))
    }));

    useEffect(() => {
        if (!open || quote) return;
        getSupplierOptionsApi().then(setSuppliers).catch(() => setSuppliers([]));
    }, [open, quote]);

    const change = (patch) => setForm(prev => ({ ...prev, ...patch }));

    // one quotation per supplier
    const quoted = new Set((request.sourcing?.quotes || []).map(item => idOf(item.supplier)));
    const options = suppliers.filter(item => !quoted.has(idOf(item._id)));

    const total = roundMoney((request.items || []).reduce((sum, item) => sum + Number(form.prices[idOf(item._id)] || 0) * item.quantity, 0));
    const currency = request.currency;

    const missing = !form.supplier || (request.items || []).some(item => !(Number(form.prices[idOf(item._id)]) > 0));

    const save = () => onSave({
        ...(quote ? {} : { supplier: form.supplier }),
        reference: form.reference.trim(),
        quoteDate: form.quoteDate || null,
        validUntil: form.validUntil || null,
        deliveryDays: form.deliveryDays === "" ? null : Number(form.deliveryDays),
        notes: form.notes.trim(),
        items: (request.items || []).map(item => ({ item: item._id, unitPrice: Number(form.prices[idOf(item._id)]) }))
    });

    return (
        <Dialog open={open} onClose={loading ? undefined : onClose} fullWidth maxWidth="md">

            <DialogTitle sx={{ fontWeight: 700 }}>{quote ? "Edit Quotation" : "Add Quotation"}</DialogTitle>

            <DialogContent>

                {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

                <Box sx={{ mt: 1 }}>
                    {quote
                        ? <Typography sx={{ fontWeight: 700, mb: 2 }}>{quote.supplier?.name}</Typography>
                        : (
                            <AppAutoComplete
                                label="Supplier"
                                required
                                options={options}
                                value={options.find(item => idOf(item._id) === form.supplier) || null}
                                placeholder="From the supplier list (active suppliers)"
                                helperText={quoted.size ? "Suppliers that already quoted are not offered again; edit their quotation instead." : ""}
                                getOptionLabel={(option) => option ? `${option.supplierCode} · ${option.name}` : ""}
                                isOptionEqualToValue={(a, b) => a._id === b._id}
                                onChange={(value) => change({ supplier: value?._id || "" })}
                            />
                        )}
                </Box>

                <Box sx={{ mt: 2 }}>
                    <FormGrid columns={4}>
                        <AppTextField label="Quotation no." value={form.reference} onChange={(e) => change({ reference: e.target.value })} />
                        <AppDatePicker
                            label="Quotation date"
                            value={form.quoteDate || null}
                            maxDate={today()}
                            onChange={(date) => change({ quoteDate: date ? date.format("YYYY-MM-DD") : "" })}
                        />
                        <AppDatePicker
                            label="Valid until"
                            value={form.validUntil || null}
                            minDate={form.quoteDate || undefined}
                            onChange={(date) => change({ validUntil: date ? date.format("YYYY-MM-DD") : "" })}
                        />
                        <AppTextField
                            label="Delivery (days)"
                            type="number"
                            value={form.deliveryDays}
                            onChange={(e) => change({ deliveryDays: e.target.value })}
                            inputProps={{ min: 0, step: 1 }}
                        />
                    </FormGrid>
                </Box>

                <Typography variant="subtitle2" sx={{ mt: 3, mb: 1 }}>
                    Prices ({currency}), for the quantities requested
                </Typography>

                <Stack spacing={1.5}>
                    {(request.items || []).map((item, index) => {
                        const price = Number(form.prices[idOf(item._id)] || 0);
                        return (
                            <Stack key={idOf(item._id)} direction={{ xs: "column", sm: "row" }} spacing={2} sx={{ alignItems: { sm: "center" } }}>
                                <Box sx={{ flex: 1, minWidth: 0 }}>
                                    <Typography variant="body2" sx={{ fontWeight: 600 }}>{index + 1}. {item.description}</Typography>
                                    <Typography variant="caption" color="text.secondary">
                                        {Number(item.quantity).toLocaleString("en-US")} {item.unit}{item.specification ? ` · ${item.specification}` : ""} · estimate {formatMoney(item.unitPrice, currency)} each
                                    </Typography>
                                </Box>
                                <AppTextField
                                    label="Unit price"
                                    required
                                    type="number"
                                    value={form.prices[idOf(item._id)]}
                                    onChange={(e) => change({ prices: { ...form.prices, [idOf(item._id)]: e.target.value } })}
                                    inputProps={{ min: 0, step: "any" }}
                                    sx={{ width: { sm: 180 } }}
                                    fullWidth={false}
                                />
                                <Typography variant="body2" sx={{ width: { sm: 150 }, textAlign: { sm: "right" }, fontWeight: 600 }}>
                                    {formatMoney(roundMoney(price * item.quantity), currency)}
                                </Typography>
                            </Stack>
                        );
                    })}
                </Stack>

                <Typography variant="h6" sx={{ fontWeight: 700, textAlign: "right", mt: 2 }}>
                    Total: {formatMoney(total, currency)}
                </Typography>

                <Box sx={{ mt: 2 }}>
                    <AppTextField label="Notes" multiline rows={2} value={form.notes} onChange={(e) => change({ notes: e.target.value })} placeholder="e.g. warranty 1 year, price includes VAT" />
                </Box>

            </DialogContent>

            <DialogActions sx={{ px: 3, pb: 2 }}>
                <AppButton variant="outlined" onClick={onClose} disabled={loading}>Cancel</AppButton>
                <AppButton variant="contained" loading={loading} disabled={missing} onClick={save}>
                    {quote ? "Save Quotation" : "Add Quotation"}
                </AppButton>
            </DialogActions>

        </Dialog>
    );

};


export default QuoteDialog;
