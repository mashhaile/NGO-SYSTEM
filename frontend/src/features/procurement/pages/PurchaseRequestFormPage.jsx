import {
    useEffect,
    useState
} from "react";

import {
    useNavigate,
    useParams,
    useSearchParams
} from "react-router-dom";

import {
    Alert,
    Box,
    Stack,
    Typography
} from "@mui/material";

import {
    Add,
    ArrowBack,
    DeleteOutlined,
    Send
} from "@mui/icons-material";

import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    FormGrid,
    AppTextField,
    AppSelect,
    AppAutoComplete,
    AppDatePicker,
    AppButton,
    AppIconButton,
    LoadingState
} from "../../../components/ui";

import {
    getPurchaseRequestByIdApi,
    createPurchaseRequestApi,
    updatePurchaseRequestApi,
    submitPurchaseRequestApi,
    getSupplierOptionsApi
} from "../api/procurementApi";

import {
    getApprovedProjectBudgetsApi,
    getProjectActivitiesApi
} from "../../expenses/api/expenseApi";

import {
    getBudgetByIdApi,
    getApiErrorMessage
} from "../../budgets/api/budgetApi";

import {
    CURRENCIES,
    formatMoney
} from "../../budgets/utils/budgetUtils";

import {
    EDITABLE_STATUSES,
    UNITS,
    itemTotal,
    roundMoney
} from "../utils/procurementUtils";

import {
    fiscalYearOf,
    fiscalYearLabel
} from "../../../utils/fiscalYear";

import { useModuleOn } from "../../../utils/modules";


const today = () => new Date().toISOString().slice(0, 10);

const emptyItem = () => ({ description: "", specification: "", unit: "pcs", quantity: "1", unitPrice: "" });

const emptyForm = {
    budget: "",
    budgetLine: "",
    requestDate: today(),
    neededBy: "",
    title: "",
    justification: "",
    deliveryLocation: "",
    currency: "",
    exchangeRate: "",
    activity: "",
    suggestedSupplier: "",
    items: [emptyItem()]
};

const toNumber = (value) => {
    const number = Number(value);
    return Number.isFinite(number) ? number : 0;
};


// =====================================================
// WRITE / EDIT PURCHASE REQUEST
// =====================================================

const PurchaseRequestFormPage = () => {

    const { id } = useParams();

    const isEdit = Boolean(id);

    const [searchParams] = useSearchParams();

    const navigate = useNavigate();

    const [form, setForm] = useState({ ...emptyForm, budget: searchParams.get("budget") || "" });
    const [existing, setExisting] = useState(null);
    const [budgets, setBudgets] = useState([]);
    const [suppliers, setSuppliers] = useState([]);
    const [details, setDetails] = useState(null);
    const [activities, setActivities] = useState([]);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState("");
    const [error, setError] = useState("");

    const activitiesOn = useModuleOn("activities");


    // ---------------- load ----------------

    useEffect(() => {

        let cancelled = false;

        Promise.all([
            getApprovedProjectBudgetsApi(),
            getSupplierOptionsApi().catch(() => []),
            isEdit ? getPurchaseRequestByIdApi(id) : Promise.resolve(null)
        ])
            .then(([budgetList, supplierList, request]) => {

                if (cancelled) return;

                setBudgets(budgetList);

                // the current supplier stays shown even if it is no longer active
                const current = request?.suggestedSupplier;
                setSuppliers(current && !supplierList.some(item => item._id === current._id) ? [...supplierList, current] : supplierList);

                if (request) {
                    setExisting(request);
                    setForm({
                        budget: request.budget?._id || "",
                        budgetLine: String(request.budgetLine || ""),
                        requestDate: String(request.requestDate).slice(0, 10),
                        neededBy: request.neededBy ? String(request.neededBy).slice(0, 10) : "",
                        title: request.title || "",
                        justification: request.justification || "",
                        deliveryLocation: request.deliveryLocation || "",
                        currency: request.currency,
                        exchangeRate: request.exchangeRate && request.exchangeRate !== 1 ? String(request.exchangeRate) : "",
                        activity: request.activity?._id || "",
                        suggestedSupplier: request.suggestedSupplier?._id || "",
                        items: (request.items || []).map(item => ({
                            description: item.description,
                            specification: item.specification || "",
                            unit: item.unit || "pcs",
                            quantity: String(item.quantity),
                            unitPrice: String(item.unitPrice)
                        }))
                    });
                }

                setLoading(false);

            })
            .catch(err => {
                if (!cancelled) {
                    setError(getApiErrorMessage(err, "Failed to load."));
                    setLoading(false);
                }
            });

        return () => {
            cancelled = true;
        };

    }, [id, isEdit]);


    // Budget details (lines with what is left per year) and the project's activities

    useEffect(() => {

        if (!form.budget) return undefined;

        let cancelled = false;

        getBudgetByIdApi(form.budget)
            .then(async budget => {
                const projectActivities =
                    activitiesOn && budget?.project?._id
                        ? await getProjectActivitiesApi(budget.project._id).catch(() => [])
                        : [];
                if (!cancelled) {
                    setDetails(budget);
                    setActivities(projectActivities);
                }
            })
            .catch(err => {
                if (!cancelled) setError(getApiErrorMessage(err, "Failed to load the budget."));
            });

        return () => {
            cancelled = true;
        };

    }, [form.budget, activitiesOn]);


    const change = (patch) => setForm(prev => ({ ...prev, ...patch }));

    const changeItem = (index, patch) =>
        setForm(prev => ({ ...prev, items: prev.items.map((item, i) => (i === index ? { ...item, ...patch } : item)) }));

    const addItem = () => setForm(prev => ({ ...prev, items: [...prev.items, emptyItem()] }));

    const removeItem = (index) => setForm(prev => ({ ...prev, items: prev.items.filter((_, i) => i !== index) }));


    // ---------------- derived ----------------

    const budget = details && String(details._id) === String(form.budget) ? details : null;
    const budgetCurrency = budget?.currency || "ETB";
    const currency = form.currency || budgetCurrency;
    const foreign = currency !== budgetCurrency;
    const fiscalYear = fiscalYearOf(form.requestDate);
    const lines = budget?.summary?.lines || [];
    const line = lines.find(item => String(item._id) === String(form.budgetLine)) || null;
    const lineYear = line?.amounts?.find(item => item.fiscalYear === fiscalYear) || null;
    const inPeriod = budget && fiscalYear >= budget.startYear && fiscalYear <= budget.endYear;

    const estimatedTotal = roundMoney(form.items.reduce((sum, item) => sum + itemTotal(item), 0));

    const budgetAmount =
        foreign ? roundMoney(estimatedTotal * toNumber(form.exchangeRate)) : estimatedTotal;

    // what the line has for this request: an approved request being
    // edited after a return is not committed, so nothing to add back
    const available = lineYear ? lineYear.remaining : 0;
    const overBy = lineYear ? roundMoney(budgetAmount - available) : 0;


    // ---------------- save ----------------

    const payload = () => ({
        budget: form.budget,
        budgetLine: form.budgetLine,
        requestDate: form.requestDate,
        neededBy: form.neededBy || null,
        title: form.title.trim(),
        justification: form.justification.trim(),
        deliveryLocation: form.deliveryLocation.trim(),
        currency,
        exchangeRate: foreign ? toNumber(form.exchangeRate) : null,
        activity: form.activity || null,
        suggestedSupplier: form.suggestedSupplier || null,
        items: form.items.map(item => ({
            description: item.description.trim(),
            specification: item.specification.trim(),
            unit: item.unit.trim() || "pcs",
            quantity: toNumber(item.quantity),
            unitPrice: toNumber(item.unitPrice)
        }))
    });

    const save = async (andSubmit) => {

        setError("");

        if (!form.budget || !form.budgetLine) return setError("Select the budget and the budget line.");
        if (!inPeriod) return setError(`${fiscalYearLabel(fiscalYear)} is outside this budget's period.`);
        if (form.title.trim().length < 3) return setError("Give the request a title (what is being bought).");
        if (!form.items.length) return setError("Add at least one item.");
        const bad = form.items.findIndex(item => item.description.trim().length < 2 || !(toNumber(item.quantity) > 0) || !(toNumber(item.unitPrice) > 0));
        if (bad >= 0) return setError(`Item ${bad + 1}: enter the description, quantity and estimated unit price.`);
        if (foreign && !(toNumber(form.exchangeRate) > 0)) return setError(`Enter the exchange rate from ${currency} to ${budgetCurrency}.`);
        if (andSubmit && lineYear && overBy > 0.005) {
            return setError(`This request is ${formatMoney(overBy, budgetCurrency)} more than the line has left. Save it as a draft, reduce it, or have the budget revised first.`);
        }

        setSaving(andSubmit ? "submit" : "draft");

        let saved = null;

        try {
            saved = isEdit ? await updatePurchaseRequestApi(id, payload()) : await createPurchaseRequestApi(payload());
            if (andSubmit) await submitPurchaseRequestApi(saved._id);
            navigate(`/purchase-requests/${saved._id}`);
        }
        catch (err) {
            const message = getApiErrorMessage(err, "Failed to save the purchase request.");
            // saved as a draft but not submitted: go on from the saved draft
            if (saved && !isEdit) {
                navigate(`/purchase-requests/${saved._id}`, { replace: true, state: { error: `Saved as a draft, but not submitted: ${message}` } });
                return;
            }
            setError(message);
        }
        finally {
            setSaving("");
        }

    };


    // ---------------- render ----------------

    const header = (
        <PageHeader
            title={isEdit ? "Edit Purchase Request" : "New Purchase Request"}
            subtitle={isEdit ? existing?.requestCode : "Ask to buy goods or services for a project, charged to a line of its approved budget."}
            action={() => navigate(isEdit ? `/purchase-requests/${id}` : "/purchase-requests")}
            actionLabel="Back"
            actionIcon={<ArrowBack />}
        />
    );

    if (loading) {
        return <PageContainer>{header}<PageCard><LoadingState message="Loading..." /></PageCard></PageContainer>;
    }

    if (isEdit && existing && !EDITABLE_STATUSES.includes(existing.status)) {
        return (
            <PageContainer>
                {header}
                <Alert severity="info">This purchase request is {existing.status.toLowerCase()} and can no longer be edited.</Alert>
            </PageContainer>
        );
    }

    if (!budgets.length) {
        return (
            <PageContainer>
                {header}
                <Alert severity="info">
                    There is no approved project budget yet. Purchase requests are charged to budget lines, so a project budget must be approved first.
                </Alert>
            </PageContainer>
        );
    }

    const selectedBudget = budgets.find(item => item._id === form.budget) || null;
    const selectedActivity = activities.find(item => item._id === form.activity) || null;
    const selectedSupplier = suppliers.find(item => item._id === form.suggestedSupplier) || null;

    return (

        <PageContainer>

            {header}

            {existing?.status === "Returned" && existing.reviewComment && (
                <Alert severity="warning" sx={{ mb: 3 }}><strong>Returned for changes:</strong> {existing.reviewComment}</Alert>
            )}

            {error && <Alert severity="error" sx={{ mb: 3 }}>{error}</Alert>}

            <PageCard>

                <FormSection title="Request">

                    <AppTextField
                        label="Title"
                        required
                        placeholder="e.g. Laptops for the field officers"
                        value={form.title}
                        onChange={(e) => change({ title: e.target.value })}
                    />

                    <Box sx={{ mt: 2 }}>
                        <AppTextField
                            label="Why it is needed"
                            multiline
                            rows={2}
                            placeholder="What it is for and why now"
                            value={form.justification}
                            onChange={(e) => change({ justification: e.target.value })}
                        />
                    </Box>

                    <Box sx={{ mt: 2 }}>
                        <FormGrid columns={3}>
                            <AppDatePicker
                                label="Request date"
                                required
                                value={form.requestDate || null}
                                onChange={(date) => change({ requestDate: date ? date.format("YYYY-MM-DD") : "" })}
                                minDate={budget ? `${budget.startYear}-01-01` : undefined}
                                maxDate={budget && `${budget.endYear}-12-31` < today() ? `${budget.endYear}-12-31` : today()}
                                helperText={
                                    budget && !inPeriod
                                        ? `${fiscalYearLabel(fiscalYear)} is outside this budget (${fiscalYearLabel(budget.startYear)}–${fiscalYearLabel(budget.endYear)})`
                                        : budget
                                            ? `The budget runs 01/01/${budget.startYear} – 31/12/${budget.endYear}. Charged to ${fiscalYearLabel(fiscalYear)}.`
                                            : `Charged to ${fiscalYearLabel(fiscalYear)}`
                                }
                                error={Boolean(budget && !inPeriod)}
                            />
                            <AppDatePicker
                                label="Needed by"
                                value={form.neededBy || null}
                                onChange={(date) => change({ neededBy: date ? date.format("YYYY-MM-DD") : "" })}
                                minDate={form.requestDate || undefined}
                                helperText="Optional: when the items must arrive"
                            />
                            <AppTextField
                                label="Deliver to"
                                placeholder="e.g. Adama field office"
                                value={form.deliveryLocation}
                                onChange={(e) => change({ deliveryLocation: e.target.value })}
                            />
                        </FormGrid>
                    </Box>

                </FormSection>

            </PageCard>


            <PageCard>

                <FormSection title="Charge To" subtitle="The approved project budget and line that pays for it.">

                    <FormGrid columns={2}>
                        <AppAutoComplete
                            label="Project budget"
                            required
                            options={budgets}
                            value={selectedBudget}
                            placeholder="Select an approved project budget"
                            getOptionLabel={(option) => option ? `${option.budgetCode} · ${option.project?.name || option.name}` : ""}
                            isOptionEqualToValue={(a, b) => a._id === b._id}
                            onChange={(value) => change({ budget: value?._id || "", budgetLine: "", activity: "", currency: "" })}
                        />
                        <AppSelect
                            label="Budget line"
                            required
                            disabled={!budget}
                            value={form.budgetLine}
                            onChange={(e) => change({ budgetLine: e.target.value })}
                            options={lines.map(item => {
                                const year = item.amounts?.find(entry => entry.fiscalYear === fiscalYear);
                                return {
                                    value: String(item._id),
                                    label: `${item.category}${item.description ? ` — ${item.description}` : ""}${year ? `  ·  ${formatMoney(year.remaining, budgetCurrency)} left in ${fiscalYearLabel(fiscalYear)}` : ""}`
                                };
                            })}
                        />
                    </FormGrid>

                    {lineYear && (
                        <Box sx={{ mt: 2, p: 2, borderRadius: 2, bgcolor: "action.hover" }}>
                            <Stack direction={{ xs: "column", sm: "row" }} spacing={{ xs: 0.5, sm: 4 }}>
                                <Typography variant="body2">Budget {fiscalYearLabel(fiscalYear)}: <strong>{formatMoney(lineYear.amount, budgetCurrency)}</strong></Typography>
                                <Typography variant="body2">Spent: <strong>{formatMoney(lineYear.spent, budgetCurrency)}</strong></Typography>
                                <Typography variant="body2">Committed: <strong>{formatMoney(lineYear.committed, budgetCurrency)}</strong></Typography>
                                <Typography variant="body2">Left: <strong>{formatMoney(lineYear.remaining, budgetCurrency)}</strong></Typography>
                            </Stack>
                        </Box>
                    )}

                    {activitiesOn && (
                        <Box sx={{ mt: 2 }}>
                            <AppAutoComplete
                                label="Activity (optional)"
                                disabled={!budget}
                                options={activities}
                                value={selectedActivity}
                                placeholder={budget ? "Select an activity of this project" : "Select the budget first"}
                                getOptionLabel={(option) => option ? `${option.activityCode} · ${option.name}` : ""}
                                isOptionEqualToValue={(a, b) => a._id === b._id}
                                onChange={(value) => change({ activity: value?._id || "" })}
                            />
                        </Box>
                    )}

                </FormSection>

            </PageCard>


            <PageCard>

                <FormSection title="Items" subtitle="What to buy, with estimated prices. The total is what the approved request reserves on the budget line.">

                    <Stack spacing={2}>
                        {form.items.map((item, index) => (
                            <Box key={index} sx={{ p: 2, borderRadius: 2, border: "1px solid", borderColor: "divider" }}>
                                <Stack direction="row" spacing={1} sx={{ alignItems: "center", mb: 1.5 }}>
                                    <Typography variant="subtitle2" sx={{ flex: 1 }}>Item {index + 1}</Typography>
                                    <Typography variant="body2" sx={{ fontWeight: 700 }}>{formatMoney(itemTotal(item), currency)}</Typography>
                                    <AppIconButton
                                        icon={<DeleteOutlined fontSize="small" />}
                                        tooltip="Remove item"
                                        color="error"
                                        disabled={form.items.length === 1}
                                        onClick={() => removeItem(index)}
                                    />
                                </Stack>
                                <FormGrid columns={2}>
                                    <AppTextField
                                        label="Item"
                                        required
                                        placeholder="e.g. Laptop"
                                        value={item.description}
                                        onChange={(e) => changeItem(index, { description: e.target.value })}
                                    />
                                    <AppTextField
                                        label="Specification"
                                        placeholder="e.g. Core i5, 8 GB RAM, 256 GB SSD"
                                        value={item.specification}
                                        onChange={(e) => changeItem(index, { specification: e.target.value })}
                                    />
                                </FormGrid>
                                <Box sx={{ mt: 2 }}>
                                    <FormGrid columns={3}>
                                        <AppAutoComplete
                                            label="Unit"
                                            freeSolo
                                            options={UNITS}
                                            value={item.unit}
                                            getOptionLabel={(option) => option || ""}
                                            onChange={(value) => changeItem(index, { unit: value || "" })}
                                            onInputChange={(event, value) => event && changeItem(index, { unit: value })}
                                        />
                                        <AppTextField
                                            label="Quantity"
                                            required
                                            type="number"
                                            value={item.quantity}
                                            onChange={(e) => changeItem(index, { quantity: e.target.value })}
                                            inputProps={{ min: 0, step: "any" }}
                                        />
                                        <AppTextField
                                            label={`Estimated unit price (${currency})`}
                                            required
                                            type="number"
                                            value={item.unitPrice}
                                            onChange={(e) => changeItem(index, { unitPrice: e.target.value })}
                                            inputProps={{ min: 0, step: "any" }}
                                        />
                                    </FormGrid>
                                </Box>
                            </Box>
                        ))}
                    </Stack>

                    <Stack direction={{ xs: "column", sm: "row" }} spacing={2} sx={{ mt: 2, alignItems: { sm: "center" } }}>
                        <AppButton variant="outlined" startIcon={<Add />} onClick={addItem}>Add Item</AppButton>
                        <Box sx={{ flex: 1 }} />
                        <Typography variant="h6" sx={{ fontWeight: 700 }}>
                            Estimated total: {formatMoney(estimatedTotal, currency)}
                        </Typography>
                    </Stack>

                    <Box sx={{ mt: 2 }}>
                        <FormGrid columns={3}>
                            <AppSelect
                                label="Currency"
                                value={currency}
                                onChange={(e) => change({ currency: e.target.value })}
                                options={[...new Set([budgetCurrency, ...CURRENCIES])].map(value => ({ value, label: value }))}
                                helperText={`Budget currency: ${budgetCurrency}`}
                            />
                            {foreign
                                ? (
                                    <AppTextField
                                        label={`Exchange rate (1 ${currency} = ? ${budgetCurrency})`}
                                        required
                                        type="number"
                                        value={form.exchangeRate}
                                        onChange={(e) => change({ exchangeRate: e.target.value })}
                                        inputProps={{ min: 0, step: "any" }}
                                        helperText={budgetAmount > 0 ? `Reserved: ${formatMoney(budgetAmount, budgetCurrency)}` : "Today's rate"}
                                    />
                                )
                                : <Box />}
                            <AppAutoComplete
                                label="Suggested supplier (optional)"
                                options={suppliers}
                                value={selectedSupplier}
                                placeholder="From the supplier list"
                                getOptionLabel={(option) => option ? `${option.supplierCode} · ${option.name}` : ""}
                                isOptionEqualToValue={(a, b) => a._id === b._id}
                                onChange={(value) => change({ suggestedSupplier: value?._id || "" })}
                            />
                        </FormGrid>
                    </Box>

                    {lineYear && budgetAmount > 0 && overBy > 0.005 && (
                        <Alert severity="warning" sx={{ mt: 2 }}>
                            This request is {formatMoney(overBy, budgetCurrency)} more than the line has left for {fiscalYearLabel(fiscalYear)} ({formatMoney(Math.max(0, available), budgetCurrency)}).
                            It can be saved as a draft but not submitted. Reduce it, or have the budget revised first.
                        </Alert>
                    )}

                </FormSection>

                <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} sx={{ justifyContent: "flex-end", mt: 1 }}>
                    <AppButton variant="outlined" onClick={() => navigate(isEdit ? `/purchase-requests/${id}` : "/purchase-requests")} disabled={Boolean(saving)}>
                        Cancel
                    </AppButton>
                    <AppButton variant="outlined" onClick={() => save(false)} loading={saving === "draft"} disabled={Boolean(saving)}>
                        Save Draft
                    </AppButton>
                    <AppButton variant="contained" startIcon={<Send />} onClick={() => save(true)} loading={saving === "submit"} disabled={Boolean(saving)}>
                        Save &amp; Submit
                    </AppButton>
                </Stack>

            </PageCard>

        </PageContainer>

    );

};


export default PurchaseRequestFormPage;
