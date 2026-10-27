import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";

import { Alert, Box, Stack, Typography } from "@mui/material";
import { Save } from "@mui/icons-material";

import {
    AppButton,
    AppDatePicker,
    AppSelect,
    AppTextField,
    FormGrid,
    FormSection,
    LoadingState,
    PageCard,
    PageContainer,
    PageHeader
} from "../../../components/ui";

import { getApiErrorMessage } from "../../../utils/apiError";

import {
    createIndicatorApi,
    getIndicatorApi,
    getMeasuresApi,
    getProgramOptionsApi,
    getProjectOptionsApi,
    updateIndicatorApi
} from "../api/indicatorApi";

import { FREQUENCIES, FREQUENCY_HELP, LEVELS, nameOf, periodLabel, periodsOf } from "../utils/indicatorUtils";


// =====================================================
// NEW / EDIT INDICATOR
// =====================================================
//
// What it measures (program or project, level, result),
// how (automatic from the system's records, or entered),
// its baseline and its targets per period. Targets are
// typed in a row per period of the chosen years.
//
// =====================================================

const THIS_YEAR = new Date().getFullYear();

const yearOf = (date, fallback) => (date ? new Date(date).getUTCFullYear() : fallback);

const emptyForm = {
    program: "",
    project: "",
    level: "Output",
    result: "",
    name: "",
    definition: "",
    source: "manual",
    measure: "",
    unit: "number",
    direction: "increase",
    baselineValue: "",
    baselineDate: "",
    frequency: "Annual",
    fromYear: THIS_YEAR,
    toYear: THIS_YEAR,
    targets: {},
    dataSource: "",
    status: "Active"
};


const IndicatorFormPage = () => {

    const { id } = useParams();
    const isEdit = Boolean(id);
    const [searchParams] = useSearchParams();
    const navigate = useNavigate();

    const [form, setForm] = useState({
        ...emptyForm,
        program: searchParams.get("program") || "",
        project: searchParams.get("project") || ""
    });
    const [programs, setPrograms] = useState([]);
    const [projects, setProjects] = useState([]);
    const [measures, setMeasures] = useState([]);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState("");

    useEffect(() => {
        let alive = true;
        Promise.all([
            getProgramOptionsApi(),
            getProjectOptionsApi(),
            getMeasuresApi(),
            isEdit ? getIndicatorApi(id) : Promise.resolve(null)
        ])
            .then(([programList, projectList, measureList, indicator]) => {
                if (!alive) return;
                setPrograms(programList);
                setProjects(projectList);
                setMeasures(measureList);
                if (indicator) {
                    const years = (indicator.targets || []).map(item => Number(String(item.period).slice(0, 4)));
                    setForm({
                        program: indicator.program?._id || "",
                        project: indicator.project?._id || "",
                        level: indicator.level,
                        result: indicator.result || "",
                        name: indicator.name,
                        definition: indicator.definition || "",
                        source: indicator.source,
                        measure: indicator.measure || "",
                        unit: indicator.unit,
                        direction: indicator.direction,
                        baselineValue: indicator.baseline?.value ?? "",
                        baselineDate: indicator.baseline?.date ? String(indicator.baseline.date).slice(0, 10) : "",
                        frequency: indicator.frequency,
                        fromYear: years.length ? Math.min(...years) : THIS_YEAR,
                        toYear: years.length ? Math.max(...years) : THIS_YEAR,
                        targets: Object.fromEntries((indicator.targets || []).map(item => [item.period, String(item.value)])),
                        dataSource: indicator.dataSource || "",
                        status: indicator.status || "Active"
                    });
                }
                setLoading(false);
            })
            .catch(loadError => {
                if (!alive) return;
                setError(getApiErrorMessage(loadError, "The indicator could not be loaded."));
                setLoading(false);
            });
        return () => { alive = false; };
    }, [id, isEdit]);

    const change = (patch) => setForm(previous => ({ ...previous, ...patch }));

    const projectChoices = projects.filter(item => !form.program || String(item.program?._id || item.program) === String(form.program));

    // a new indicator: its years follow the program / project
    const choose = (patch) => {
        const next = { ...form, ...patch };
        if (!isEdit) {
            const owner = next.project
                ? projects.find(item => item._id === next.project)
                : programs.find(item => item._id === next.program);
            if (owner?.startDate) {
                next.fromYear = yearOf(owner.startDate, THIS_YEAR);
                next.toYear = Math.max(next.fromYear, yearOf(owner.endDate, next.fromYear));
            }
        }
        setForm(next);
    };

    const measure = measures.find(item => item.key === form.measure) || null;
    const unit = form.source === "auto" ? measure?.unit || "number" : form.unit;

    const periods = useMemo(
        () => periodsOf(form.frequency, form.fromYear, Math.max(form.fromYear, form.toYear)),
        [form.frequency, form.fromYear, form.toYear]
    );

    const yearOptions = Array.from({ length: 12 }, (_, index) => THIS_YEAR - 4 + index).map(year => ({ value: year, label: String(year) }));

    const save = async () => {
        setError("");
        if (!form.program) return setError("Choose the program.");
        if (!form.name.trim()) return setError("Give the indicator a name.");
        if (form.source === "auto" && !form.measure) return setError("Choose what the automatic indicator counts.");
        const payload = {
            program: form.program,
            project: form.project || null,
            level: form.level,
            result: form.result,
            name: form.name,
            definition: form.definition,
            source: form.source,
            measure: form.source === "auto" ? form.measure : null,
            unit,
            direction: form.direction,
            baseline: { value: form.baselineValue === "" ? null : Number(form.baselineValue), date: form.baselineDate || null },
            frequency: form.frequency,
            targets: periods
                .filter(period => form.targets[period] !== undefined && form.targets[period] !== "")
                .map(period => ({ period, value: Number(form.targets[period]) })),
            dataSource: form.dataSource,
            status: form.status
        };
        setSaving(true);
        try {
            const saved = isEdit ? await updateIndicatorApi(id, payload) : await createIndicatorApi(payload);
            navigate(`/indicators/${saved._id}`);
        }
        catch (saveError) {
            setError(getApiErrorMessage(saveError, "The indicator could not be saved."));
        }
        finally {
            setSaving(false);
        }
    };

    if (loading) {
        return (
            <PageContainer>
                <LoadingState message="Loading..." />
            </PageContainer>
        );
    }

    return (
        <PageContainer>

            <PageHeader
                title={isEdit ? "Edit Indicator" : "New Indicator"}
                subtitle="An indicator of a program's or project's logframe, with its baseline and targets."
            />

            {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

            <PageCard>
                <FormSection title="What it measures">
                    <FormGrid columns={2}>
                        <AppSelect
                            label="Program"
                            required
                            value={form.program}
                            placeholder="Select Program"
                            options={programs.map(item => ({ value: item._id, label: nameOf(item) }))}
                            onChange={(event) => choose({ program: event.target.value, project: "" })}
                        />
                        <AppSelect
                            label="Project"
                            value={form.project}
                            placeholder={form.program ? "Whole program (no project)" : "Select Program First"}
                            disabled={!form.program}
                            options={[{ value: "", label: "Whole program (no project)" }, ...projectChoices.map(item => ({ value: item._id, label: nameOf(item) }))]}
                            onChange={(event) => choose({ project: event.target.value })}
                        />
                        <AppSelect
                            label="Level"
                            required
                            value={form.level}
                            options={LEVELS.map(level => ({ value: level, label: level }))}
                            onChange={(event) => change({ level: event.target.value })}
                        />
                        <AppTextField
                            label="Result it measures"
                            placeholder="e.g. Outcome 1: Women run profitable businesses"
                            value={form.result}
                            onChange={(event) => change({ result: event.target.value })}
                        />
                    </FormGrid>
                    <Box sx={{ mt: 2, display: "grid", gap: 2 }}>
                        <AppTextField
                            label="Indicator"
                            required
                            placeholder="e.g. Number of women trained in business skills"
                            value={form.name}
                            onChange={(event) => change({ name: event.target.value })}
                        />
                        <AppTextField
                            label="Definition"
                            placeholder="How it is counted, who is included"
                            multiline
                            minRows={2}
                            value={form.definition}
                            onChange={(event) => change({ definition: event.target.value })}
                        />
                    </Box>
                </FormSection>
            </PageCard>

            <PageCard>
                <FormSection title="How it is measured">
                    <FormGrid columns={2}>
                        <AppSelect
                            label="Actual values"
                            required
                            value={form.source}
                            options={[
                                { value: "auto", label: "Automatic (from the system's records)" },
                                { value: "manual", label: "Entered (e.g. from a survey)" }
                            ]}
                            onChange={(event) => change({ source: event.target.value })}
                            helperText={form.source === "auto"
                                ? "Counted for each period from the records of this program / project; the same figure as the reports."
                                : "Someone with the right enters the value of each period."}
                        />
                        {form.source === "auto"
                            ? (
                                <AppSelect
                                    label="What it counts"
                                    required
                                    value={form.measure}
                                    placeholder="Select what to count"
                                    options={measures.map(item => ({ value: item.key, label: `${item.name}${item.unit === "percent" ? " (%)" : ""}` }))}
                                    onChange={(event) => change({ measure: event.target.value })}
                                />
                            )
                            : (
                                <AppSelect
                                    label="Unit"
                                    value={form.unit}
                                    options={[{ value: "number", label: "Number" }, { value: "percent", label: "Percentage (%)" }]}
                                    onChange={(event) => change({ unit: event.target.value })}
                                />
                            )}
                        <AppSelect
                            label="Better when"
                            value={form.direction}
                            options={[
                                { value: "increase", label: "Higher (e.g. people trained)" },
                                { value: "decrease", label: "Lower (e.g. children malnourished)" }
                            ]}
                            onChange={(event) => change({ direction: event.target.value })}
                        />
                        <AppTextField
                            label="Means of verification"
                            placeholder="e.g. Attendance sheets; follow-up survey"
                            value={form.dataSource}
                            onChange={(event) => change({ dataSource: event.target.value })}
                        />
                        <AppTextField
                            label={`Baseline${unit === "percent" ? " (%)" : ""}`}
                            type="number"
                            value={form.baselineValue}
                            onChange={(event) => change({ baselineValue: event.target.value })}
                            inputProps={{ min: 0, step: "any" }}
                        />
                        <AppDatePicker
                            label="Baseline date"
                            value={form.baselineDate || null}
                            onChange={(value) => change({ baselineDate: value ? value.format("YYYY-MM-DD") : "" })}
                        />
                        {isEdit && (
                            <AppSelect
                                label="Status"
                                value={form.status}
                                options={[{ value: "Active", label: "Active" }, { value: "Inactive", label: "Inactive (not reported)" }]}
                                onChange={(event) => change({ status: event.target.value })}
                            />
                        )}
                    </FormGrid>
                </FormSection>
            </PageCard>

            <PageCard>
                <FormSection title="Targets" subtitle="Leave a period empty when it has no target.">
                    <FormGrid columns={3}>
                        <AppSelect
                            label="Frequency"
                            value={form.frequency}
                            options={FREQUENCIES.map(item => ({ value: item, label: item }))}
                            onChange={(event) => change({ frequency: event.target.value, targets: {} })}
                            helperText={FREQUENCY_HELP[form.frequency]}
                        />
                        <AppSelect
                            label="From"
                            value={form.fromYear}
                            options={yearOptions}
                            onChange={(event) => change({ fromYear: Number(event.target.value) })}
                        />
                        <AppSelect
                            label="To"
                            value={form.toYear}
                            options={yearOptions}
                            onChange={(event) => change({ toYear: Number(event.target.value) })}
                        />
                    </FormGrid>
                    <Box sx={{ mt: 2, display: "grid", gridTemplateColumns: { xs: "1fr 1fr", sm: "repeat(4, 1fr)", md: "repeat(6, 1fr)" }, gap: 1.5 }}>
                        {periods.map(period => (
                            <AppTextField
                                key={period}
                                label={periodLabel(period)}
                                type="number"
                                value={form.targets[period] ?? ""}
                                onChange={(event) => change({ targets: { ...form.targets, [period]: event.target.value } })}
                                inputProps={{ min: 0, max: unit === "percent" ? 100 : undefined, step: "any" }}
                            />
                        ))}
                    </Box>
                    {periods.length > 36 && (
                        <Typography variant="caption" color="warning.main">Many periods: choose fewer years, or a longer frequency.</Typography>
                    )}
                </FormSection>

                <Stack direction="row" spacing={1.5} sx={{ justifyContent: "flex-end", mt: 2 }}>
                    <AppButton variant="outlined" onClick={() => navigate(isEdit ? `/indicators/${id}` : "/indicators")} disabled={saving}>
                        Cancel
                    </AppButton>
                    <AppButton variant="contained" startIcon={<Save />} onClick={save} loading={saving}>
                        Save Indicator
                    </AppButton>
                </Stack>
            </PageCard>

        </PageContainer>
    );

};

export default IndicatorFormPage;
