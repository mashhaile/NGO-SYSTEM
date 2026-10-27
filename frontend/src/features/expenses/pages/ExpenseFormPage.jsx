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
    ArrowBack,
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
    LoadingState
} from "../../../components/ui";

import {
    getExpenseByIdApi,
    createExpenseApi,
    updateExpenseApi,
    submitExpenseApi,
    getApprovedProjectBudgetsApi,
    getDonationOptionsApi,
    getProjectActivitiesApi
} from "../api/expenseApi";

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
    PAYMENT_METHODS
} from "../utils/expenseUtils";

import {
    fiscalYearOf,
    fiscalYearLabel
} from "../../../utils/fiscalYear";

import { useModuleOn } from "../../../utils/modules";


const today = () => new Date().toISOString().slice(0, 10);

const emptyForm = {
    budget: "",
    budgetLine: "",
    expenseDate: today(),
    description: "",
    payee: "",
    referenceNumber: "",
    paymentMethod: "Bank Transfer",
    amount: "",
    currency: "",
    exchangeRate: "",
    donation: "",
    activity: ""
};

const toNumber = (value) => {
    const number = Number(value);
    return Number.isFinite(number) ? number : 0;
};


// =====================================================
// RECORD / EDIT EXPENSE
// =====================================================

const ExpenseFormPage = () => {

    const { id } = useParams();

    const isEdit = Boolean(id);

    const [searchParams] = useSearchParams();

    const navigate = useNavigate();

    const [form, setForm] = useState({ ...emptyForm, budget: searchParams.get("budget") || "" });
    const [existing, setExisting] = useState(null);
    const [budgets, setBudgets] = useState([]);
    const [donations, setDonations] = useState([]);
    const [details, setDetails] = useState(null);
    const [activities, setActivities] = useState([]);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState("");
    const [error, setError] = useState("");

    // the links belong to other modules
    const fundingOn = useModuleOn("funding");
    const activitiesOn = useModuleOn("activities");


    // ---------------- load ----------------

    useEffect(() => {

        let cancelled = false;

        Promise.all([
            getApprovedProjectBudgetsApi(),
            getDonationOptionsApi().catch(() => []),
            isEdit ? getExpenseByIdApi(id) : Promise.resolve(null)
        ])
            .then(([budgetList, donationList, expense]) => {

                if (cancelled) return;

                setBudgets(budgetList);
                setDonations(donationList);

                if (expense) {
                    setExisting(expense);
                    setForm({
                        budget: expense.budget?._id || "",
                        budgetLine: String(expense.budgetLine || ""),
                        expenseDate: String(expense.expenseDate).slice(0, 10),
                        description: expense.description || "",
                        payee: expense.payee || "",
                        referenceNumber: expense.referenceNumber || "",
                        paymentMethod: expense.paymentMethod || "Cash",
                        amount: String(expense.amount ?? ""),
                        currency: expense.currency,
                        exchangeRate: expense.exchangeRate && expense.exchangeRate !== 1 ? String(expense.exchangeRate) : "",
                        donation: expense.donation?._id || "",
                        activity: expense.activity?._id || ""
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


    // Budget details (lines with remaining per year) and the project's activities

    useEffect(() => {

        if (!form.budget) {
            return;
        }

        let cancelled = false;

        getBudgetByIdApi(form.budget)
            .then(async budget => {
                const projectActivities =
                    budget?.project?._id
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

    }, [form.budget]);


    const change = (patch) => setForm(prev => ({ ...prev, ...patch }));


    // ---------------- derived ----------------

    const budget = details && String(details._id) === String(form.budget) ? details : null;
    const budgetCurrency = budget?.currency || "ETB";
    const currency = form.currency || budgetCurrency;
    const foreign = currency !== budgetCurrency;
    const fiscalYear = fiscalYearOf(form.expenseDate);
    const lines = budget?.summary?.lines || [];
    const line = lines.find(item => String(item._id) === String(form.budgetLine)) || null;
    const lineYear = line?.amounts?.find(item => item.fiscalYear === fiscalYear) || null;
    const inPeriod = budget && fiscalYear >= budget.startYear && fiscalYear <= budget.endYear;

    const budgetAmount =
        foreign
            ? Math.round(toNumber(form.amount) * toNumber(form.exchangeRate) * 100) / 100
            : toNumber(form.amount);

    const overBy =
        lineYear ? Math.round((budgetAmount - lineYear.remaining) * 100) / 100 : 0;


    // ---------------- save ----------------

    const payload = () => ({
        budget: form.budget,
        budgetLine: form.budgetLine,
        expenseDate: form.expenseDate,
        description: form.description.trim(),
        payee: form.payee,
        referenceNumber: form.referenceNumber,
        paymentMethod: form.paymentMethod,
        amount: toNumber(form.amount),
        currency,
        exchangeRate: foreign ? toNumber(form.exchangeRate) : null,
        donation: form.donation || null,
        activity: form.activity || null
    });

    const save = async (andSubmit) => {

        setError("");

        if (!form.budget || !form.budgetLine) return setError("Select the budget and the budget line.");
        if (!inPeriod) return setError(`${fiscalYearLabel(fiscalYear)} is outside this budget's period.`);
        if (form.description.trim().length < 3) return setError("Describe the expense.");
        if (!(toNumber(form.amount) > 0)) return setError("Enter the amount.");
        if (foreign && !(toNumber(form.exchangeRate) > 0)) return setError(`Enter the exchange rate from ${currency} to ${budgetCurrency}.`);

        setSaving(andSubmit ? "submit" : "draft");

        try {
            const saved = isEdit ? await updateExpenseApi(id, payload()) : await createExpenseApi(payload());
            if (andSubmit) await submitExpenseApi(saved._id);
            navigate(`/expenses/${saved._id}`);
        }
        catch (err) {
            setError(getApiErrorMessage(err, "Failed to save the expense."));
        }
        finally {
            setSaving("");
        }

    };


    // ---------------- render ----------------

    const header = (
        <PageHeader
            title={isEdit ? "Edit Expense" : "Record Expense"}
            subtitle={isEdit ? existing?.expenseCode : "Charge actual spending to a line of an approved project budget."}
            action={() => navigate(isEdit ? `/expenses/${id}` : "/expenses")}
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
                <Alert severity="info">This expense is {existing.status.toLowerCase()} and can no longer be edited.</Alert>
            </PageContainer>
        );
    }

    if (!budgets.length) {
        return (
            <PageContainer>
                {header}
                <Alert severity="info">
                    There is no approved project budget yet. Expenses are charged to budget lines, so a project budget must be approved first.
                </Alert>
            </PageContainer>
        );
    }

    const selectedBudget = budgets.find(item => item._id === form.budget) || null;
    const selectedDonation = donations.find(item => item._id === form.donation) || null;

    // The donations that may pay for this budget's work (the server
    // checks the same): not cancelled; a restricted one only for its
    // own program / project / activity; an unrestricted one for anything.
    const idOf = (value) => String(value?._id || value || "");
    const work = {
        program: idOf(budget?.program),
        project: idOf(budget?.project),
        activity: form.activity || "",
        activityRun: ""
    };
    const mayPay = (donation) => {
        if (donation.status === "Cancelled") return false;
        if (String(donation.fundingRestriction || "Unrestricted") !== "Restricted") return true;
        const key = ["activityRun", "activity", "project", "program"].find(name => idOf(donation[name]));
        return !key || idOf(donation[key]) === work[key];
    };
    const donationOptions = budget ? donations.filter(mayPay) : donations.filter(item => item.status !== "Cancelled");
    const hiddenDonations = donations.length - donationOptions.length;
    const selectedActivity = activities.find(item => item._id === form.activity) || null;

    return (

        <PageContainer>

            {header}

            {error && <Alert severity="error" sx={{ mb: 3 }}>{error}</Alert>}

            <PageCard>

                <FormSection title="Charge To">

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

                        <AppDatePicker
                            label="Expense date"
                            required
                            value={form.expenseDate || null}
                            onChange={(date) => change({ expenseDate: date ? date.format("YYYY-MM-DD") : "" })}
                            // inside the budget's period, and not in the future
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

                    </FormGrid>

                    <Box sx={{ mt: 2 }}>
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
                    </Box>

                    {lineYear && (
                        <Box sx={{ mt: 2, p: 2, borderRadius: 2, bgcolor: "action.hover" }}>
                            <Stack direction={{ xs: "column", sm: "row" }} spacing={{ xs: 0.5, sm: 4 }}>
                                <Typography variant="body2">Budget {fiscalYearLabel(fiscalYear)}: <strong>{formatMoney(lineYear.amount, budgetCurrency)}</strong></Typography>
                                <Typography variant="body2">Spent: <strong>{formatMoney(lineYear.spent, budgetCurrency)}</strong></Typography>
                                {lineYear.pending > 0 && (
                                    <Typography variant="body2">Pending: <strong>{formatMoney(lineYear.pending, budgetCurrency)}</strong></Typography>
                                )}
                                <Typography variant="body2">Remaining: <strong>{formatMoney(lineYear.remaining, budgetCurrency)}</strong></Typography>
                            </Stack>
                        </Box>
                    )}

                    {lineYear && budgetAmount > 0 && overBy > 0.005 && (
                        <Alert severity="warning" sx={{ mt: 2 }}>
                            This expense is {formatMoney(overBy, budgetCurrency)} over what is left on this line for {fiscalYearLabel(fiscalYear)}.
                            You can still submit it; the approver will have to confirm approving over budget and give a reason.
                        </Alert>
                    )}

                </FormSection>

            </PageCard>


            <PageCard>

                <FormSection title="Expense Details">

                    <AppTextField
                        label="Description"
                        required
                        placeholder="e.g. Facilitator fees, leadership workshop in Adama"
                        value={form.description}
                        onChange={(e) => change({ description: e.target.value })}
                    />

                    <Box sx={{ mt: 2 }}>
                        <FormGrid columns={3}>
                            <AppTextField
                                label="Paid to (payee)"
                                value={form.payee}
                                onChange={(e) => change({ payee: e.target.value })}
                            />
                            <AppTextField
                                label="Receipt / invoice no."
                                value={form.referenceNumber}
                                onChange={(e) => change({ referenceNumber: e.target.value })}
                            />
                            <AppSelect
                                label="Payment method"
                                value={form.paymentMethod}
                                onChange={(e) => change({ paymentMethod: e.target.value })}
                                options={PAYMENT_METHODS.map(value => ({ value, label: value }))}
                            />
                        </FormGrid>
                    </Box>

                    <Box sx={{ mt: 2 }}>
                        <FormGrid columns={3}>
                            <AppTextField
                                label="Amount"
                                required
                                type="number"
                                value={form.amount}
                                onChange={(e) => change({ amount: e.target.value })}
                                inputProps={{ min: 0, step: "any" }}
                            />
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
                                        helperText={budgetAmount > 0 ? `Charged: ${formatMoney(budgetAmount, budgetCurrency)}` : "Rate on the payment date"}
                                    />
                                )
                                : <Box />}
                        </FormGrid>
                    </Box>

                </FormSection>

            </PageCard>


            <PageCard>

                <FormSection title="Links (optional)" subtitle="Which donation paid for it (for donor tracing) and which activity it was for.">

                    <FormGrid columns={2}>
                        {/* each link only with its module */}
                        {fundingOn && (
                        <AppAutoComplete
                            label="Paid from donation"
                            options={donationOptions}
                            value={selectedDonation}
                            placeholder="Select a donation"
                            helperText={
                                selectedDonation && !mayPay(selectedDonation)
                                    ? "This donation cannot pay for this budget's work (cancelled, or restricted to other work). Choose another."
                                    : hiddenDonations > 0
                                        ? `${hiddenDonations} donation${hiddenDonations === 1 ? " is" : "s are"} not offered: cancelled, or restricted to other work.`
                                        : undefined
                            }
                            error={Boolean(selectedDonation && !mayPay(selectedDonation))}
                            getOptionLabel={(option) => option ? `${option.donationCode} · ${option.title}${option.donor?.name ? ` (${option.donor.name})` : ""}` : ""}
                            isOptionEqualToValue={(a, b) => a._id === b._id}
                            onChange={(value) => change({ donation: value?._id || "" })}
                        />
                        )}
                        {activitiesOn && (
                        <AppAutoComplete
                            label="Activity"
                            disabled={!budget}
                            options={activities}
                            value={selectedActivity}
                            placeholder={budget ? "Select an activity of this project" : "Select the budget first"}
                            getOptionLabel={(option) => option ? `${option.activityCode} · ${option.name}` : ""}
                            isOptionEqualToValue={(a, b) => a._id === b._id}
                            onChange={(value) => change({ activity: value?._id || "" })}
                        />
                        )}
                    </FormGrid>

                </FormSection>

                <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} sx={{ justifyContent: "flex-end", mt: 1 }}>
                    <AppButton variant="outlined" onClick={() => navigate(isEdit ? `/expenses/${id}` : "/expenses")} disabled={Boolean(saving)}>
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


export default ExpenseFormPage;
