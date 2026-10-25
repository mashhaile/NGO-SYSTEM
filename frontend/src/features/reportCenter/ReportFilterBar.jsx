import { WORK_STATUSES } from "../../constants/workStatus";
import {
    useEffect,
    useMemo,
    useState
} from "react";

import {
    Box,
    Paper
} from "@mui/material";

import {
    AppDatePicker,
    AppSelect
} from "../../components/ui";

import axiosClient
    from "../../services/axiosClient";

import {
    getLocationsApi
} from "../locations/api/locationApi";


// =====================================================
// A DATE THAT APPLIES ONCE IT IS COMPLETE
// =====================================================
//
// DD/MM/YYYY like every date. While a date is typed the
// picker passes half dates (year 2, 20, 202 …); only a whole
// date (year 2000–2100) or a cleared box rebuilds the report,
// so typing stays quick.
//
// =====================================================

const DateFilter = ({ label, value, onApply }) => (
    <AppDatePicker
        label={label}
        value={value || null}
        onChange={(newValue) => {
            if (!newValue) {
                if (value) onApply("");
                return;
            }
            if (!newValue.isValid() || newValue.year() < 2000 || newValue.year() > 2100) return;
            const day = newValue.format("YYYY-MM-DD");
            if (day !== value) onApply(day);
        }}
    />
);


// =====================================================
// REPORT FILTER BAR
// =====================================================
//
// The period (year, half, quarter, month, custom range or
// all time) and the filters the chosen report takes.
// Values live in the address bar, so a report can be
// shared or bookmarked and Back returns to it.
//
// =====================================================

const THIS_YEAR = new Date().getFullYear();

const YEARS = Array.from({ length: 8 }, (_, index) => THIS_YEAR + 1 - index);

const MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

const PERIODS = [
    { value: "year", label: "Year (Jan–Dec)" },
    { value: "half", label: "Half year" },
    { value: "quarter", label: "Quarter" },
    { value: "month", label: "Month" },
    { value: "custom", label: "Date range" },
    { value: "all", label: "All time" }
];

// status choices of each report that filters by status
const STATUS_OPTIONS = {
    beneficiaries: ["Active", "Inactive"],
    programs: WORK_STATUSES,
    activities: WORK_STATUSES,
    enterprises: ["Active", "Inactive"],
    budgets: ["Draft", "Submitted", "Approved", "Returned"]
};

const toOptions = (values) => values.map(value => ({ value, label: value }));

const listOf = (data) => (Array.isArray(data) ? data : data?.items || data?.data || data?.docs || []);


const ReportFilterBar = ({ report, values, onChange }) => {

    const wants = (name) => (report?.filters || []).includes(name);

    const [programs, setPrograms] = useState([]);
    const [projects, setProjects] = useState([]);
    const [regions, setRegions] = useState([]);
    const [genders, setGenders] = useState([]);

    useEffect(() => {
        let alive = true;
        const load = async () => {
            const [programList, projectList, genderList, regionList] = await Promise.all([
                axiosClient.get("/programs", { params: { limit: 500 } }).then(res => listOf(res.data.data)).catch(() => []),
                axiosClient.get("/projects", { params: { limit: 500 } }).then(res => listOf(res.data.data)).catch(() => []),
                axiosClient.get("/lookups/module/Beneficiary/category/Gender").then(res => listOf(res.data.data)).catch(() => []),
                Promise.resolve(getLocationsApi(1)).then(res => listOf(res?.data ?? res)).catch(() => [])
            ]);
            if (!alive) return;
            setPrograms(programList);
            setProjects(projectList);
            setGenders(genderList);
            setRegions(regionList);
        };
        load();
        return () => { alive = false; };
    }, []);

    const projectOptions = useMemo(
        () =>
            projects
                .filter(project => !values.program || String(project.program?._id || project.program) === String(values.program))
                .map(project => ({ value: project._id, label: `${project.projectCode ? `${project.projectCode} – ` : ""}${project.name}` })),
        [projects, values.program]
    );

    const set = (name) => (event) => {
        const value = event?.target?.value ?? event;
        // only what changed: merged into the current filters, so
        // two quick changes (From, To) cannot undo each other
        const change = { [name]: value };
        if (name === "program") change.project = "";
        onChange(change);
    };

    const period = values.period || "year";

    return (
        <Paper variant="outlined" sx={{ p: 2, mb: 3, borderRadius: 2 }}>
            <Box
                sx={{
                    display: "grid",
                    gridTemplateColumns: { xs: "1fr 1fr", md: "repeat(4, 1fr)", lg: "repeat(6, 1fr)" },
                    gap: 1.5
                }}
            >

                <AppSelect label="Period" value={period} options={PERIODS} onChange={set("period")} />

                {["year", "half", "quarter", "month"].includes(period) && (
                    <AppSelect label="Year" value={values.year || THIS_YEAR} options={YEARS.map(year => ({ value: year, label: `FY ${year}` }))} onChange={set("year")} />
                )}

                {period === "half" && (
                    <AppSelect label="Half" value={values.half || 1} options={[{ value: 1, label: "H1 (Jan–Jun)" }, { value: 2, label: "H2 (Jul–Dec)" }]} onChange={set("half")} />
                )}

                {period === "quarter" && (
                    <AppSelect label="Quarter" value={values.quarter || 1} options={[1, 2, 3, 4].map(q => ({ value: q, label: `Q${q} (${MONTHS[(q - 1) * 3].slice(0, 3)}–${MONTHS[q * 3 - 1].slice(0, 3)})` }))} onChange={set("quarter")} />
                )}

                {period === "month" && (
                    <AppSelect label="Month" value={values.month || new Date().getMonth() + 1} options={MONTHS.map((name, index) => ({ value: index + 1, label: name }))} onChange={set("month")} />
                )}

                {period === "custom" && (
                    <>
                        <DateFilter label="From" value={values.startDate} onApply={set("startDate")} />
                        <DateFilter label="To" value={values.endDate} onApply={set("endDate")} />
                    </>
                )}

                {wants("program") && (
                    <AppSelect label="Program" placeholder="All programs" value={values.program || ""} options={programs.map(program => ({ value: program._id, label: program.name }))} onChange={set("program")} />
                )}

                {wants("project") && (
                    <AppSelect label="Project" placeholder="All projects" value={values.project || ""} options={projectOptions} onChange={set("project")} />
                )}

                {wants("region") && (
                    <AppSelect label="Region" placeholder="All regions" value={values.region || ""} options={regions.map(region => ({ value: region.name, label: region.name }))} onChange={set("region")} />
                )}

                {wants("gender") && (
                    <AppSelect label="Gender" placeholder="Everyone" value={values.gender || ""} options={genders.map(gender => ({ value: gender._id, label: gender.value }))} onChange={set("gender")} />
                )}

                {wants("status") && STATUS_OPTIONS[report.key] && (
                    <AppSelect label="Status" placeholder="Any status" value={values.status || ""} options={toOptions(STATUS_OPTIONS[report.key])} onChange={set("status")} />
                )}

            </Box>
        </Paper>
    );

};

export default ReportFilterBar;
