import {
    useEffect,
    useMemo,
    useState
} from "react";

import {
    useSearchParams
} from "react-router-dom";

import {
    Alert,
    Box,
    ButtonBase,
    Paper,
    Stack,
    Typography
} from "@mui/material";

import {
    PictureAsPdf,
    TableChart,
    Description
} from "@mui/icons-material";

import {
    PageContainer,
    PageHeader,
    AppButton,
    LoadingState
} from "../../components/ui";

import ReportFilterBar from "./ReportFilterBar";
import ReportView from "./ReportView";

import {
    getCatalogApi,
    getReportApi,
    downloadReportApi
} from "./api";

import {
    getApiErrorMessage
} from "../../utils/apiError";


// =====================================================
// REPORTS
// =====================================================
//
// One page for every report: pick the report, set the
// period and filters, read it, export it. Rows open the
// record's own report.
//
// =====================================================

const FILTER_KEYS = ["period", "year", "half", "quarter", "month", "startDate", "endDate", "program", "project", "region", "gender", "status"];

const THIS_YEAR = new Date().getFullYear();


const ReportCenterPage = () => {

    const [params, setParams] = useSearchParams();

    const [catalog, setCatalog] = useState([]);
    // the last answer, and the request it answers
    const [result, setResult] = useState({ request: "", report: null, error: "" });
    const [catalogError, setCatalogError] = useState("");
    const [downloadError, setDownloadError] = useState("");
    const [downloading, setDownloading] = useState("");

    const selectedKey = params.get("report") || catalog[0]?.key || "";

    const selected = catalog.find(item => item.key === selectedKey) || null;

    // the filters in the address bar (period defaults to this year)
    const values = useMemo(() => {
        const result = { period: "year", year: THIS_YEAR };
        for (const key of FILTER_KEYS) if (params.get(key)) result[key] = params.get(key);
        return result;
    }, [params]);

    // only the filters this report takes, plus the period
    const query = useMemo(() => {
        const result = {};
        for (const key of ["period", "year", "half", "quarter", "month", "startDate", "endDate"]) if (values[key]) result[key] = values[key];
        for (const key of selected?.filters || []) if (values[key]) result[key] = values[key];
        return result;
    }, [values, selected]);

    useEffect(() => {
        getCatalogApi()
            .then(setCatalog)
            .catch(err => setCatalogError(getApiErrorMessage(err, "Reports could not be loaded.")));
    }, []);

    const request = selectedKey ? `${selectedKey}?${new URLSearchParams(query)}` : "";

    useEffect(() => {
        if (!selectedKey) return;
        let alive = true;
        getReportApi(selectedKey, query)
            .then(data => { if (alive) setResult({ request, report: data, error: "" }); })
            .catch(err => { if (alive) setResult({ request, report: null, error: getApiErrorMessage(err, "The report could not be made.") }); });
        return () => { alive = false; };
    }, [selectedKey, query, request]);

    // the previous report stays visible (dimmed) while the next one loads
    const loading = Boolean(request) && result.request !== request;
    const report = result.report;
    const error = catalogError || downloadError || (loading ? "" : result.error);

    const choose = (key) => {
        const next = new URLSearchParams(params);
        next.set("report", key);
        setParams(next);
    };

    const changeFilters = (nextValues) => {
        const next = new URLSearchParams();
        next.set("report", selectedKey);
        for (const [key, value] of Object.entries(nextValues)) if (value !== "" && value !== null && value !== undefined) next.set(key, value);
        setParams(next);
    };

    const download = async (format) => {
        try {
            setDownloading(format);
            setDownloadError("");
            await downloadReportApi(`/report-center/${selectedKey}`, query, format);
        }
        catch (err) {
            setDownloadError(getApiErrorMessage(err, "The file could not be made."));
        }
        finally {
            setDownloading("");
        }
    };

    return (
        <PageContainer>

            <PageHeader
                title="Reports"
                subtitle="Choose a report, set the period and filters. Click any row to open that record's full report."
            />

            {/* ---------- the reports ---------- */}
            <Box
                sx={{
                    display: "grid",
                    gridTemplateColumns: { xs: "1fr 1fr", md: "repeat(4, 1fr)" },
                    gap: 1.5,
                    mb: 3
                }}
            >
                {catalog.map(item => {
                    const active = item.key === selectedKey;
                    return (
                        <ButtonBase
                            key={item.key}
                            onClick={() => choose(item.key)}
                            sx={{ display: "block", textAlign: "left", borderRadius: 2 }}
                        >
                            <Paper
                                variant="outlined"
                                sx={{
                                    p: 1.75,
                                    height: "100%",
                                    borderRadius: 2,
                                    borderColor: active ? "primary.main" : "divider",
                                    borderWidth: active ? 2 : 1,
                                    bgcolor: active ? "action.selected" : "background.paper"
                                }}
                            >
                                <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                                    {item.title}
                                </Typography>
                                <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 0.5, lineHeight: 1.35 }}>
                                    {item.description}
                                </Typography>
                            </Paper>
                        </ButtonBase>
                    );
                })}
            </Box>

            {selected && (
                <ReportFilterBar report={selected} values={values} onChange={changeFilters} />
            )}

            {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

            {/* ---------- the report ---------- */}
            {report && !error && (
                <Box sx={{ opacity: loading ? 0.5 : 1, transition: "opacity 0.2s" }}>

                    <Stack
                        direction={{ xs: "column", sm: "row" }}
                        spacing={1.5}
                        sx={{ justifyContent: "space-between", alignItems: { sm: "flex-end" }, mb: 2 }}
                    >
                        <Box>
                            <Typography variant="h5" sx={{ fontWeight: 700 }}>
                                {report.title}
                            </Typography>
                            <Typography variant="body2" sx={{ color: "text.secondary" }}>
                                {report.period?.label}
                                {report.description ? ` · ${report.description}` : ""}
                            </Typography>
                        </Box>

                        <Stack direction="row" spacing={1}>
                            <AppButton variant="outlined" startIcon={<TableChart />} loading={downloading === "excel"} onClick={() => download("excel")}>Excel</AppButton>
                            <AppButton variant="outlined" startIcon={<PictureAsPdf />} loading={downloading === "pdf"} onClick={() => download("pdf")}>PDF</AppButton>
                            <AppButton variant="outlined" startIcon={<Description />} loading={downloading === "csv"} onClick={() => download("csv")}>CSV</AppButton>
                        </Stack>
                    </Stack>

                    <ReportView report={report} />

                </Box>
            )}

            {loading && !report && <LoadingState message="Making the report…" />}

        </PageContainer>
    );

};

export default ReportCenterPage;
