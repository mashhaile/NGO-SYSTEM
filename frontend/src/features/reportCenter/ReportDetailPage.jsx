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
    Stack,
    Typography
} from "@mui/material";

import {
    ArrowBack,
    PictureAsPdf,
    TableChart,
    Description
} from "@mui/icons-material";

import {
    PageContainer,
    AppButton,
    LoadingState
} from "../../components/ui";

import ReportView from "./ReportView";

import {
    getDetailApi,
    downloadReportApi
} from "./api";

import {
    getApiErrorMessage
} from "../../utils/apiError";


// =====================================================
// DETAIL REPORT (one record)
// =====================================================
//
// /reports/detail/:kind/:id: a beneficiary's profile, a
// program, a project, an activity run, an enterprise or a
// donor, with everything about it, printable.
//
// =====================================================

const ReportDetailPage = () => {

    const { kind, id } = useParams();
    const navigate = useNavigate();

    // the last answer, and the record it is for
    const [result, setResult] = useState({ request: "", report: null, error: "" });
    const [downloadError, setDownloadError] = useState("");
    const [downloading, setDownloading] = useState("");

    const request = `${kind}/${id}`;

    useEffect(() => {
        let alive = true;
        getDetailApi(kind, id)
            .then(data => { if (alive) setResult({ request, report: data, error: "" }); })
            .catch(err => { if (alive) setResult({ request, report: null, error: getApiErrorMessage(err, "This report could not be made.") }); });
        return () => { alive = false; };
    }, [kind, id, request]);

    const current = result.request === request;
    const report = current ? result.report : null;
    const error = downloadError || (current ? result.error : "");

    const download = async (format) => {
        try {
            setDownloading(format);
            await downloadReportApi(`/report-center/detail/${kind}/${id}`, {}, format);
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

            <Stack
                direction={{ xs: "column", sm: "row" }}
                spacing={1.5}
                sx={{ justifyContent: "space-between", alignItems: { sm: "center" }, mb: 3 }}
            >
                <Box>
                    <AppButton variant="text" startIcon={<ArrowBack />} onClick={() => navigate(-1)} sx={{ mb: 1, px: 0 }}>
                        Back
                    </AppButton>
                    <Typography variant="h4" sx={{ fontWeight: 800 }}>
                        {report?.title || " "}
                    </Typography>
                    {report?.description && (
                        <Typography variant="body2" sx={{ color: "text.secondary", mt: 0.5 }}>
                            {report.description}
                        </Typography>
                    )}
                </Box>

                {report && (
                    <Stack direction="row" spacing={1}>
                        <AppButton variant="outlined" startIcon={<TableChart />} loading={downloading === "excel"} onClick={() => download("excel")}>Excel</AppButton>
                        <AppButton variant="outlined" startIcon={<PictureAsPdf />} loading={downloading === "pdf"} onClick={() => download("pdf")}>PDF</AppButton>
                        <AppButton variant="outlined" startIcon={<Description />} loading={downloading === "csv"} onClick={() => download("csv")}>CSV</AppButton>
                    </Stack>
                )}
            </Stack>

            {error && <Alert severity="error">{error}</Alert>}

            {!report && !error && <LoadingState message="Making the report…" />}

            {report && <ReportView report={report} />}

        </PageContainer>
    );

};

export default ReportDetailPage;
