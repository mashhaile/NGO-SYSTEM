import {
    useEffect,
    useMemo,
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
    ToggleButton,
    ToggleButtonGroup,
    Typography
} from "@mui/material";

import {
    ArrowBack
} from "@mui/icons-material";

import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    FormGrid,
    FormActions,
    AppTextField,
    AppSelect,
    AppAutoComplete,
    LoadingState
} from "../../../components/ui";

import BudgetGrid
    from "../components/BudgetGrid";

import {
    getBudgetByIdApi,
    getBudgetsApi,
    createBudgetApi,
    updateBudgetApi,
    updateRevisionApi,
    getProgramOptionsApi,
    getProjectOptionsApi,
    getApiErrorMessage
} from "../api/budgetApi";

import {
    CURRENCIES,
    EDITABLE_STATUSES,
    MAX_YEARS
} from "../utils/budgetUtils";

import {
    currentFiscalYear,
    fiscalYearLabel,
    fiscalYearRange
} from "../../../utils/fiscalYear";


const thisYear = currentFiscalYear();

const YEAR_OPTIONS =
    fiscalYearRange(thisYear - 5, thisYear + 10).map(year => ({
        value: String(year),
        label: fiscalYearLabel(year)
    }));

const CURRENCY_OPTIONS =
    CURRENCIES.map(code => ({ value: code, label: code }));


const emptyForm = {
    level: "project",
    program: "",
    project: "",
    name: "",
    description: "",
    currency: "ETB",
    startYear: String(thisYear),
    endYear: String(thisYear + 2),
    yearlyAmounts: [],
    lines: []
};


// Keep amounts of years still in the period, add empty
// ones for new years.

const fitAmounts = (amounts = [], years) =>
    years.map(fiscalYear => ({
        fiscalYear,
        amount: amounts.find(item => Number(item.fiscalYear) === fiscalYear)?.amount ?? ""
    }));

const toNumber = (value) => {
    const number = Number(value);
    return Number.isFinite(number) ? number : 0;
};


// =====================================================
// CREATE / EDIT BUDGET
// =====================================================

const BudgetFormPage = () => {

    const { id } = useParams();

    const isEdit = Boolean(id);

    // /budgets/:id/revise edits the pending revision of an
    // approved budget (figures + reason), not the budget itself
    const location = useLocation();
    const isRevise = location.pathname.endsWith("/revise");

    // /budgets/create?program=<id> or ?project=<id> (from the
    // program / project page) preselects what the budget is for
    const prefillSearch = isEdit ? "" : location.search;

    const navigate = useNavigate();

    const [form, setForm] = useState(emptyForm);
    const [existing, setExisting] = useState(null);
    const [programs, setPrograms] = useState([]);
    const [projects, setProjects] = useState([]);
    const [fetchedAvailable, setFetchedAvailable] =
        useState({ programId: null, value: null });
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState("");


    // ---------------- load ----------------

    useEffect(() => {

        let cancelled = false;

        Promise.all([
            getProgramOptionsApi(),
            getProjectOptionsApi(),
            isEdit ? getBudgetByIdApi(id) : Promise.resolve(null)
        ])
            .then(([programList, projectList, budget]) => {

                if (cancelled) return;

                setPrograms(programList);
                setProjects(projectList);

                if (budget) {
                    setExisting(budget);
                    const source = isRevise && budget.revision ? budget.revision : budget;
                    setForm({
                        level: budget.level,
                        program: budget.program?._id || "",
                        project: budget.project?._id || "",
                        name: budget.name,
                        description: budget.description || "",
                        currency: budget.currency,
                        startYear: String(source.startYear),
                        endYear: String(source.endYear),
                        yearlyAmounts: source.yearlyAmounts || [],
                        reason: budget.revision?.reason || "",
                        lines: (source.lines || []).map(line => ({
                            _id: line._id,
                            category: line.category,
                            description: line.description || "",
                            amounts: line.amounts || []
                        }))
                    });
                }
                else if (prefillSearch) {
                    const params = new URLSearchParams(prefillSearch);
                    const project = projectList.find(item => item._id === params.get("project"));
                    const program = programList.find(item => item._id === params.get("program"));
                    if (project) {
                        setForm(prev => ({ ...prev, level: "project", project: project._id, name: `${project.name} Budget` }));
                    }
                    else if (program) {
                        setForm(prev => ({ ...prev, level: "program", program: program._id, name: `${program.name} Program Budget` }));
                    }
                }

                setLoading(false);

            })
            .catch(err => {
                if (!cancelled) {
                    setError(getApiErrorMessage(err, "Failed to load the budget."));
                    setLoading(false);
                }
            });

        return () => {
            cancelled = true;
        };

    }, [id, isEdit, isRevise, prefillSearch]);


    const years = useMemo(() => {
        const start = Number(form.startYear);
        const end = Number(form.endYear);
        return end >= start ? fiscalYearRange(start, end) : [];
    }, [form.startYear, form.endYear]);

    const periodProblem =
        !years.length
            ? "The end year cannot be before the start year."
            : years.length > MAX_YEARS
                ? `A budget can cover at most ${MAX_YEARS} years.`
                : "";


    // The program the budget belongs to (a project budget's
    // program comes from the project)

    const programId =
        form.level === "project"
            ? projects.find(project => project._id === form.project)?.program || ""
            : form.program;


    // ---------------- what is left in the program budget ----------------

    // Editing: the budget's own summary already excludes itself.
    // Creating: fetch the program budget's unallocated amounts
    // (kept per program, so switching projects never shows a
    // stale program's numbers).

    const editAvailable =
        existing?.summary?.programBudget
            ? Object.fromEntries(
                existing.summary.programBudget.years.map(item => [item.fiscalYear, item.availableForThisProject])
            )
            : null;

    useEffect(() => {

        if (form.level !== "project" || !programId || existing) {
            return;
        }

        let cancelled = false;

        getBudgetsApi({ level: "program", program: programId, limit: 1 })
            .then(async response => {
                const envelope = response.data?.[0];
                const value = envelope
                    ? Object.fromEntries(
                        (await getBudgetByIdApi(envelope._id)).summary.allocation.years
                            .map(item => [item.fiscalYear, item.unallocated])
                    )
                    : null;
                if (!cancelled) setFetchedAvailable({ programId, value });
            })
            .catch(() => {
                if (!cancelled) setFetchedAvailable({ programId, value: null });
            });

        return () => {
            cancelled = true;
        };

    }, [form.level, programId, existing]);

    const available =
        form.level !== "project" || !programId
            ? null
            : existing
                ? editAvailable
                : fetchedAvailable.programId === programId
                    ? fetchedAvailable.value
                    : null;


    // ---------------- change helpers ----------------

    const change = (patch) =>
        setForm(prev => ({ ...prev, ...patch }));

    const changePeriod = (patch) =>
        setForm(prev => {
            const next = { ...prev, ...patch };
            const start = Number(next.startYear);
            const end = Number(next.endYear);
            if (end < start || end - start + 1 > MAX_YEARS) {
                return next;
            }
            const nextYears = fiscalYearRange(start, end);
            return {
                ...next,
                yearlyAmounts: fitAmounts(next.yearlyAmounts, nextYears),
                lines: next.lines.map(line => ({ ...line, amounts: fitAmounts(line.amounts, nextYears) }))
            };
        });

    const selectProject = (project) =>
        change({
            project: project?._id || "",
            name: form.name || (project ? `${project.name} Budget` : "")
        });

    const selectProgram = (program) =>
        change({
            program: program?._id || "",
            name: form.name || (program ? `${program.name} Program Budget` : "")
        });


    // ---------------- save ----------------

    const handleSave = async () => {

        setError("");

        if (periodProblem) {
            setError(periodProblem);
            return;
        }

        if (!isRevise && !form.name.trim()) {
            setError("Enter a name for the budget.");
            return;
        }

        if (!isEdit && form.level === "project" && !form.project) {
            setError("Select the project.");
            return;
        }

        if (!isEdit && form.level === "program" && !form.program) {
            setError("Select the program.");
            return;
        }

        const numbers = (amounts) =>
            fitAmounts(amounts, years).map(item => ({ fiscalYear: item.fiscalYear, amount: toNumber(item.amount) }));

        const payload = {
            name: form.name.trim(),
            description: form.description,
            currency: form.currency,
            startYear: years[0],
            endYear: years[years.length - 1],
            ...(form.level === "program"
                ? { yearlyAmounts: numbers(form.yearlyAmounts) }
                : {
                    lines: form.lines.map(line => ({
                        ...(line._id ? { _id: line._id } : {}),
                        category: line.category,
                        description: line.description,
                        amounts: numbers(line.amounts)
                    }))
                })
        };

        setSaving(true);

        try {

            const { startYear, endYear, yearlyAmounts, lines } = payload;

            const saved =
                isRevise
                    ? await updateRevisionApi(id, { reason: form.reason || "", startYear, endYear, ...(yearlyAmounts ? { yearlyAmounts } : { lines }) })
                    : isEdit
                    ? await updateBudgetApi(id, payload)
                    : await createBudgetApi({
                        ...payload,
                        level: form.level,
                        ...(form.level === "program" ? { program: form.program } : { project: form.project })
                    });

            navigate(`/budgets/${saved._id}`);

        }
        catch (err) {
            setError(getApiErrorMessage(err, "Failed to save the budget."));
        }
        finally {
            setSaving(false);
        }

    };


    // ---------------- render ----------------

    const header = (
        <PageHeader
            title={isRevise ? "Revise Budget" : isEdit ? "Edit Budget" : "New Budget"}
            subtitle={
                isEdit
                    ? existing?.budgetCode
                    : "A program budget sets the amount per year; project budgets plan the details and draw on it."
            }
            action={() => navigate(isEdit ? `/budgets/${id}` : "/budgets")}
            actionLabel="Back"
            actionIcon={<ArrowBack />}
        />
    );

    if (loading) {
        return (
            <PageContainer>
                {header}
                <PageCard>
                    <LoadingState message="Loading..." />
                </PageCard>
            </PageContainer>
        );
    }

    if (isRevise && existing && (!existing.revision || !["Draft", "Returned"].includes(existing.revision.status))) {
        return (
            <PageContainer>
                {header}
                <Alert severity="info">
                    {existing.revision
                        ? `The revision is ${existing.revision.status.toLowerCase()} and can no longer be edited.`
                        : "This budget has no revision in progress. Start one from the budget page."}
                </Alert>
            </PageContainer>
        );
    }

    if (isEdit && !isRevise && existing && !EDITABLE_STATUSES.includes(existing.status)) {
        return (
            <PageContainer>
                {header}
                <Alert severity="info">
                    This budget is {existing.status.toLowerCase()} and can no longer be edited.
                </Alert>
            </PageContainer>
        );
    }

    const selectedProject = projects.find(project => project._id === form.project) || null;
    const selectedProgram = programs.find(program => program._id === form.program) || null;
    const projectProgram = programs.find(program => program._id === programId);

    return (

        <PageContainer>

            {header}

            {error && (
                <Alert severity="error" sx={{ mb: 3 }}>
                    {error}
                </Alert>
            )}

            <PageCard>

                <FormSection title="Budget Information">

                    {!isEdit && (
                        <Box sx={{ mb: 2.5 }}>
                            <Typography variant="body2" sx={{ color: "text.secondary", mb: 1 }}>
                                Budget level
                            </Typography>
                            <ToggleButtonGroup
                                exclusive
                                size="small"
                                color="primary"
                                value={form.level}
                                onChange={(event, value) => value && change({ level: value, name: "" })}
                            >
                                <ToggleButton value="project">Project budget</ToggleButton>
                                <ToggleButton value="program">Program budget</ToggleButton>
                            </ToggleButtonGroup>
                        </Box>
                    )}

                    <FormGrid columns={2}>

                        {form.level === "project"
                            ? (
                                <AppAutoComplete
                                    label="Project"
                                    required
                                    disabled={isEdit}
                                    options={projects}
                                    value={selectedProject}
                                    placeholder="Select Project"
                                    getOptionLabel={(option) => option ? `${option.projectCode} - ${option.name}` : ""}
                                    isOptionEqualToValue={(a, b) => a._id === b._id}
                                    onChange={selectProject}
                                    helperText={projectProgram ? `Program: ${projectProgram.name}` : ""}
                                />
                            )
                            : (
                                <AppAutoComplete
                                    label="Program"
                                    required
                                    disabled={isEdit}
                                    options={programs}
                                    value={selectedProgram}
                                    placeholder="Select Program"
                                    getOptionLabel={(option) => option ? `${option.programCode} - ${option.name}` : ""}
                                    isOptionEqualToValue={(a, b) => a._id === b._id}
                                    onChange={selectProgram}
                                />
                            )}

                        <AppTextField
                            label="Budget name"
                            required
                            disabled={isRevise}
                            value={form.name}
                            onChange={(e) => change({ name: e.target.value })}
                        />

                        <AppSelect
                            label="Currency"
                            required
                            disabled={isRevise}
                            options={CURRENCY_OPTIONS}
                            value={form.currency}
                            onChange={(e) => change({ currency: e.target.value })}
                            helperText="A project budget must use its program budget's currency."
                        />

                        <FormGrid columns={2}>
                            <AppSelect
                                label="From"
                                required
                                options={YEAR_OPTIONS}
                                value={form.startYear}
                                onChange={(e) => changePeriod({ startYear: e.target.value })}
                            />
                            <AppSelect
                                label="To"
                                required
                                options={YEAR_OPTIONS}
                                value={form.endYear}
                                onChange={(e) => changePeriod({ endYear: e.target.value })}
                                error={Boolean(periodProblem)}
                                helperText={periodProblem || `${years.length} year${years.length === 1 ? "" : "s"}`}
                            />
                        </FormGrid>

                    </FormGrid>

                    <Box sx={{ mt: 2 }}>
                        {isRevise && (
                            <Box sx={{ mb: 2 }}>
                                <AppTextField
                                    label="Reason for this revision"
                                    required
                                    multiline
                                    rows={2}
                                    placeholder="e.g. Second facilitator from April; venue costs higher than planned"
                                    value={form.reason || ""}
                                    onChange={(e) => change({ reason: e.target.value })}
                                    helperText="Required before submitting. Shown in the budget's version history."
                                />
                            </Box>
                        )}
                        <AppTextField
                            label="Description"
                            disabled={isRevise}
                            multiline
                            rows={2}
                            value={form.description}
                            onChange={(e) => change({ description: e.target.value })}
                        />
                    </Box>

                </FormSection>

            </PageCard>


            <PageCard>

                <FormSection
                    title={form.level === "program" ? "Amount per Year" : "Budget Lines"}
                    subtitle={
                        form.level === "program"
                            ? "The total available to this program's projects each year."
                            : available
                                ? "Plan each cost category per year. Totals in red go over what is left in the program budget."
                                : "Plan each cost category per year."
                    }
                >

                    {periodProblem
                        ? <Alert severity="warning">{periodProblem}</Alert>
                        : (
                            <BudgetGrid
                                level={form.level}
                                years={years}
                                currency={form.currency}
                                yearlyAmounts={fitAmounts(form.yearlyAmounts, years)}
                                lines={form.lines.map(line => ({ ...line, amounts: fitAmounts(line.amounts, years) }))}
                                available={form.level === "project" ? available : null}
                                onChangeYearly={(yearlyAmounts) => change({ yearlyAmounts })}
                                onChangeLines={(lines) => change({ lines })}
                            />
                        )}

                </FormSection>

                <FormActions
                    onCancel={() => navigate(isEdit ? `/budgets/${id}` : "/budgets")}
                    onSubmit={handleSave}
                    submitLabel={isRevise ? "Save Revision" : isEdit ? "Save Changes" : "Create Budget"}
                    submitLoading={saving}
                />

            </PageCard>

        </PageContainer>

    );

};


export default BudgetFormPage;
