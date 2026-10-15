import {
    useEffect,
    useMemo,
    useState
} from "react";


import {
    Box,
    MenuItem,
    Typography
} from "@mui/material";


import {
    Assessment,
    PictureAsPdf,
    TableChart,
    Refresh
} from "@mui/icons-material";


import {
    PageCard,
    FormSection,
    FormGrid,
    FormActions,
    AppSelect,
    AppButton
} from "../../../components/ui";


import {
    useDispatch,
    useSelector
} from "react-redux";


import {
    getReportsThunk,
    generateReportThunk,
    exportReportPdfThunk,
    exportReportExcelThunk
} from "../store/reportThunks";


import {
    setSelectedReport,
    clearReport,
    clearReportFilters
} from "../store/reportSlice";


import {
    getReportConfig,
    getReportLabel
} from "../config/reportConfig";


import ReportFilters
    from "../components/ReportFilters";


import ReportSummary
    from "../components/ReportSummary";


import ReportStatistics
    from "../components/ReportStatistics";


import ReportCharts
    from "../components/ReportCharts";


import ServiceDeliveryReportDetails
    from "../components/ServiceDelivery/ServiceDeliveryReportDetails";


// =====================================================
// PAGE
// =====================================================

const ReportsPage = () => {

    const dispatch =
        useDispatch();


    // =================================================
    // LOCAL EXPORT STATE
    // =================================================

    const [
        pdfLoading,
        setPdfLoading
    ] =
        useState(false);


    const [
        excelLoading,
        setExcelLoading
    ] =
        useState(false);


    const [
        exportError,
        setExportError
    ] =
        useState(null);


    // =================================================
    // REDUX STATE
    // =================================================

    const {
        reports = [],
        selectedReport = null,
        reportData = null,
        filters = {},
        loading = false,
        reportLoading = false,
        error = null,
        reportError = null
    } =
        useSelector(
            (
                state
            ) =>
                state.reports || {}
        );


    const {
        startDate = null,
        endDate = null,
        program = "",
        project = "",
        activity = "",
        activityRun = "",
        enterprise = ""
    } =
        filters;


    // =================================================
    // LOAD REPORTS
    // =================================================

    useEffect(
        () => {

            dispatch(
                getReportsThunk()
            );

        },
        [
            dispatch
        ]
    );


    // =================================================
    // REPORT NAME HELPER
    // =================================================

    const getReportName = (
        report
    ) => {

        if (
            typeof report === "string"
        ) {

            return report;

        }


        if (
            report &&
            typeof report === "object"
        ) {

            return (
                report.key ||
                report.name ||
                report.reportName ||
                ""
            );

        }


        return "";

    };


    // =================================================
    // REPORT OPTIONS
    // =================================================

    const reportOptions =
        useMemo(
            () => {

                if (
                    !Array.isArray(
                        reports
                    )
                ) {

                    return [];

                }


                const seen =
                    new Set();


                return reports
                    .map(
                        (
                            report
                        ) => {

                            const reportName =
                                getReportName(
                                    report
                                );


                            if (
                                !reportName
                            ) {

                                return null;

                            }


                            if (
                                seen.has(
                                    reportName
                                )
                            ) {

                                return null;

                            }


                            seen.add(
                                reportName
                            );


                            return {

                                value:
                                    reportName,

                                label:
                                    getReportLabel(
                                        reportName
                                    )

                            };

                        }
                    )
                    .filter(
                        Boolean
                    );

            },
            [
                reports
            ]
        );


    // =================================================
    // AUTO SELECT FIRST REPORT
    // =================================================

    useEffect(
        () => {

            if (
                selectedReport
            ) {

                return;

            }


            if (
                reportOptions.length === 0
            ) {

                return;

            }


            dispatch(
                setSelectedReport(
                    reportOptions[0].value
                )
            );

        },
        [
            dispatch,
            reportOptions,
            selectedReport
        ]
    );


    // =================================================
    // CURRENT REPORT CONFIG
    // =================================================

    const currentReportConfig =
        useMemo(
            () => {

                if (
                    !selectedReport
                ) {

                    return {};

                }


                return (
                    getReportConfig(
                        selectedReport
                    ) ||
                    {}
                );

            },
            [
                selectedReport
            ]
        );


    // =================================================
    // CURRENT REPORT LABEL
    // =================================================

    const currentReportLabel =
        useMemo(
            () => {

                if (
                    !selectedReport
                ) {

                    return "";

                }


                return getReportLabel(
                    selectedReport
                );

            },
            [
                selectedReport
            ]
        );


    // =================================================
    // BUILD CURRENT REPORT FILTERS
    // =================================================

    const buildCurrentReportFilters =
        () => {

            const reportFilters =
                {};


            if (
                startDate
            ) {

                reportFilters.startDate =
                    formatDate(
                        startDate
                    );

            }


            if (
                endDate
            ) {

                reportFilters.endDate =
                    formatDate(
                        endDate
                    );

            }


            if (
                program
            ) {

                reportFilters.program =
                    program;

            }


            if (
                project
            ) {

                reportFilters.project =
                    project;

            }


            if (
                activity
            ) {

                reportFilters.activity =
                    activity;

            }


            if (
                activityRun
            ) {

                reportFilters.activityRun =
                    activityRun;

            }


            if (
                enterprise
            ) {

                reportFilters.enterprise =
                    enterprise;

            }


            return reportFilters;

        };


    // =================================================
    // SELECT REPORT
    // =================================================

    const handleReportChange =
        (
            event
        ) => {

            const value =
                event?.target?.value ||
                "";


            dispatch(
                setSelectedReport(
                    value ||
                    null
                )
            );


            dispatch(
                clearReport()
            );


            dispatch(
                clearReportFilters()
            );


            setExportError(
                null
            );

        };


    // =================================================
    // GENERATE REPORT
    // =================================================

    const handleGenerateReport =
        () => {

            if (
                !selectedReport
            ) {

                return;

            }


            setExportError(
                null
            );


            const reportFilters =
                buildCurrentReportFilters();


            dispatch(
                generateReportThunk({
                    reportName:
                        selectedReport,

                    filters:
                        reportFilters
                })
            );

        };


    // =================================================
    // EXPORT PDF
    // =================================================

    const handleExportPdf =
        async () => {

            if (
                !selectedReport ||
                !reportData
            ) {

                return;

            }


            setPdfLoading(
                true
            );


            setExportError(
                null
            );


            try {

                await dispatch(
                    exportReportPdfThunk({
                        reportName:
                            selectedReport,

                        filters:
                            buildCurrentReportFilters()
                    })
                ).unwrap();

            } catch (
                error
            ) {

                setExportError(
                    getErrorMessage(
                        error,
                        "Failed downloading PDF report."
                    )
                );

            } finally {

                setPdfLoading(
                    false
                );

            }

        };


    // =================================================
    // EXPORT EXCEL
    // =================================================

    const handleExportExcel =
        async () => {

            if (
                !selectedReport ||
                !reportData
            ) {

                return;

            }


            setExcelLoading(
                true
            );


            setExportError(
                null
            );


            try {

                await dispatch(
                    exportReportExcelThunk({
                        reportName:
                            selectedReport,

                        filters:
                            buildCurrentReportFilters()
                    })
                ).unwrap();

            } catch (
                error
            ) {

                setExportError(
                    getErrorMessage(
                        error,
                        "Failed downloading Excel report."
                    )
                );

            } finally {

                setExcelLoading(
                    false
                );

            }

        };


    // =================================================
    // CLEAR REPORT
    // =================================================

    const handleClearReport =
        () => {

            dispatch(
                clearReport()
            );


            dispatch(
                clearReportFilters()
            );


            setExportError(
                null
            );

        };


    // =================================================
    // REFRESH
    // =================================================

    const handleRefresh =
        () => {

            setExportError(
                null
            );


            dispatch(
                getReportsThunk()
            );

        };


    // =================================================
    // RENDER
    // =================================================

    return (

        <Box
            sx={{
                width: "100%"
            }}
        >

            <PageCard>

                {/* =================================================
                    PAGE HEADER
                ================================================= */}

                <Box
                    sx={{
                        display: "flex",
                        alignItems: {
                            xs: "flex-start",
                            sm: "center"
                        },
                        justifyContent: "space-between",
                        gap: 2,
                        mb: 3,
                        flexWrap: "wrap"
                    }}
                >

                    <Box
                        sx={{
                            display: "flex",
                            alignItems: "flex-start",
                            gap: 1.5
                        }}
                    >

                        <Box
                            sx={{
                                display: "flex",
                                alignItems: "center",
                                justifyContent: "center",
                                width: 42,
                                height: 42,
                                borderRadius: 1.5,
                                backgroundColor:
                                    "action.hover"
                            }}
                        >

                            <Assessment />

                        </Box>


                        <Box>

                            <Typography
                                variant="h5"
                                fontWeight={600}
                            >
                                Reports
                            </Typography>


                            <Typography
                                variant="body2"
                                color="text.secondary"
                                sx={{
                                    mt: 0.5
                                }}
                            >
                                Generate, review and export
                                organizational reports.
                            </Typography>

                        </Box>

                    </Box>


                    <AppButton
                        variant="outlined"
                        startIcon={
                            <Refresh />
                        }
                        onClick={
                            handleRefresh
                        }
                        disabled={
                            loading ||
                            reportLoading
                        }
                    >
                        Refresh
                    </AppButton>

                </Box>


                {/* =================================================
                    REPORT SELECTION
                ================================================= */}

                <FormSection
                    title="Report Selection"
                >

                    <FormGrid>

                        <AppSelect
                            label="Report"
                            value={
                                selectedReport ||
                                ""
                            }
                            onChange={
                                handleReportChange
                            }
                            disabled={
                                loading ||
                                reportLoading ||
                                reportOptions.length === 0
                            }
                        >

                            <MenuItem
                                value=""
                            >
                                Select Report
                            </MenuItem>


                            {
                                reportOptions.map(
                                    (
                                        option
                                    ) => (

                                        <MenuItem
                                            key={
                                                option.value
                                            }
                                            value={
                                                option.value
                                            }
                                        >
                                            {
                                                option.label
                                            }
                                        </MenuItem>

                                    )
                                )
                            }

                        </AppSelect>

                    </FormGrid>

                </FormSection>


                {/* =================================================
                    SELECTED REPORT INDICATOR
                ================================================= */}

                {
                    selectedReport && (

                        <Box
                            sx={{
                                mt: 2,
                                px: 2,
                                py: 1.25,
                                borderRadius: 1.5,
                                backgroundColor:
                                    "action.hover",
                                border:
                                    "1px solid",
                                borderColor:
                                    "divider"
                            }}
                        >

                            <Typography
                                variant="body2"
                                color="text.secondary"
                            >
                                Selected Report
                            </Typography>


                            <Typography
                                variant="subtitle1"
                                fontWeight={600}
                                sx={{
                                    mt: 0.25
                                }}
                            >
                                {
                                    currentReportLabel ||
                                    selectedReport
                                }
                            </Typography>

                        </Box>

                    )
                }


                {/* =================================================
                    REPORT FILTERS
                ================================================= */}

                {
                    selectedReport && (

                        <Box
                            sx={{
                                mt: 3
                            }}
                        >

                            <ReportFilters
                                reportConfig={
                                    currentReportConfig
                                }
                            />

                        </Box>

                    )
                }


                {/* =================================================
                    ACTIONS
                ================================================= */}

                {
                    selectedReport && (

                        <FormActions>

                            <AppButton
                                variant="contained"
                                onClick={
                                    handleGenerateReport
                                }
                                loading={
                                    reportLoading
                                }
                                disabled={
                                    !selectedReport ||
                                    reportLoading ||
                                    loading
                                }
                            >
                                Generate Report
                            </AppButton>


                            <AppButton
                                variant="outlined"
                                onClick={
                                    handleClearReport
                                }
                                disabled={
                                    reportLoading
                                }
                            >
                                Clear
                            </AppButton>

                        </FormActions>

                    )
                }


                {/* =================================================
                    GENERAL ERROR
                ================================================= */}

                {
                    error && (

                        <ReportMessage
                            severity="error"
                            message={
                                getErrorMessage(
                                    error,
                                    "Unable to load reports."
                                )
                            }
                        />

                    )
                }


                {/* =================================================
                    REPORT ERROR
                ================================================= */}

                {
                    reportError && (

                        <ReportMessage
                            severity="error"
                            message={
                                getErrorMessage(
                                    reportError,
                                    "Unable to generate the report."
                                )
                            }
                        />

                    )
                }


                {/* =================================================
                    EXPORT ERROR
                ================================================= */}

                {
                    exportError && (

                        <ReportMessage
                            severity="error"
                            message={
                                getErrorMessage(
                                    exportError,
                                    "Unable to export the report."
                                )
                            }
                        />

                    )
                }


                {/* =================================================
                    REPORT LIST LOADING
                ================================================= */}

                {
                    loading && (

                        <ReportMessage
                            severity="info"
                            message="Loading available reports..."
                        />

                    )
                }


                {/* =================================================
                    NO REPORTS
                ================================================= */}

                {
                    !loading &&
                    reportOptions.length === 0 &&
                    !error && (

                        <ReportMessage
                            severity="info"
                            message="No reports are currently available."
                        />

                    )
                }


                {/* =================================================
                    REPORT RESULT
                ================================================= */}

                {
                    reportData && (

                        <Box
                            sx={{
                                mt: 4
                            }}
                        >

                            <ReportResult
                                reportData={
                                    reportData
                                }

                                reportName={
                                    selectedReport
                                }

                                reportLabel={
                                    currentReportLabel
                                }

                                onExportPdf={
                                    handleExportPdf
                                }

                                onExportExcel={
                                    handleExportExcel
                                }

                                pdfLoading={
                                    pdfLoading
                                }

                                excelLoading={
                                    excelLoading
                                }

                                exportDisabled={
                                    reportLoading ||
                                    pdfLoading ||
                                    excelLoading
                                }
                            />

                        </Box>

                    )
                }

            </PageCard>

        </Box>

    );

};


// =====================================================
// REPORT RESULT
// =====================================================

const ReportResult = ({
    reportData,
    reportName,
    reportLabel,
    onExportPdf,
    onExportExcel,
    pdfLoading,
    excelLoading,
    exportDisabled
}) => {

    const reportTitle =
        reportData?.title ||
        reportData?.reportTitle ||
        reportLabel ||
        "Report";


    return (

        <Box
            sx={{
                width: "100%"
            }}
        >

            {/* =================================================
                RESULT HEADER
            ================================================= */}

            <Box
                sx={{
                    display: "flex",
                    alignItems: {
                        xs: "flex-start",
                        sm: "center"
                    },
                    justifyContent: "space-between",
                    gap: 2,
                    mb: 3,
                    pb: 2,
                    borderBottom:
                        "1px solid",
                    borderColor:
                        "divider",
                    flexWrap: "wrap"
                }}
            >

                <Box
                    sx={{
                        minWidth: 0
                    }}
                >

                    <Typography
                        variant="h5"
                        fontWeight={600}
                        sx={{
                            wordBreak: "break-word"
                        }}
                    >
                        {
                            reportTitle
                        }
                    </Typography>


                    {
                        reportData?.description && (

                            <Typography
                                variant="body2"
                                color="text.secondary"
                                sx={{
                                    mt: 0.75,
                                    maxWidth: 800
                                }}
                            >
                                {
                                    reportData.description
                                }
                            </Typography>

                        )
                    }


                    {
                        reportData?.generatedAt && (

                            <Typography
                                variant="body2"
                                color="text.secondary"
                                sx={{
                                    mt: 0.75
                                }}
                            >
                                Generated:
                                {" "}
                                {
                                    formatDisplayDateTime(
                                        reportData.generatedAt
                                    )
                                }
                            </Typography>

                        )
                    }

                </Box>


                {/* =================================================
                    EXPORT ACTIONS
                ================================================= */}

                <Box
                    sx={{
                        display: "flex",
                        alignItems: "center",
                        gap: 1,
                        flexWrap: "wrap"
                    }}
                >

                    <AppButton
                        variant="outlined"
                        startIcon={
                            <PictureAsPdf />
                        }
                        onClick={
                            onExportPdf
                        }
                        loading={
                            pdfLoading
                        }
                        disabled={
                            exportDisabled
                        }
                    >
                        PDF
                    </AppButton>


                    <AppButton
                        variant="outlined"
                        startIcon={
                            <TableChart />
                        }
                        onClick={
                            onExportExcel
                        }
                        loading={
                            excelLoading
                        }
                        disabled={
                            exportDisabled
                        }
                    >
                        Excel
                    </AppButton>

                </Box>

            </Box>


            {/* =================================================
                REPORT CONTENT
            ================================================= */}

            {
                reportName === "serviceDeliveryReport" ? (

                    /*
                     * SERVICE DELIVERY OWNS ITS COMPLETE
                     * PRESENTATION.
                     *
                     * Do NOT render the generic:
                     *
                     * - ReportSummary
                     * - ReportStatistics
                     * - ReportCharts
                     *
                     * because ServiceDeliveryReportDetails
                     * already provides the Service Delivery
                     * summary and detailed presentation.
                     */

                    <Box
                        sx={{
                            mt: 3
                        }}
                    >

                        <ServiceDeliveryReportDetails
                            report={
                                reportData
                            }
                        />

                    </Box>

                ) : (

                    /*
                     * ALL OTHER REPORTS CONTINUE USING
                     * THE SHARED GENERIC PRESENTATION.
                     */

                    <Box
                        sx={{
                            mt: 3
                        }}
                    >

                        <ReportSummary
                            summary={
                                reportData?.summary
                            }
                        />


                        <ReportStatistics
                            statistics={
                                reportData?.statistics
                            }
                        />


                        <ReportCharts
                            charts={
                                reportData?.charts
                            }
                        />

                    </Box>

                )
            }

        </Box>

    );

};


// =====================================================
// REPORT MESSAGE
// =====================================================

const ReportMessage = ({
    severity = "info",
    message
}) => {

    const isError =
        severity === "error";


    return (

        <Box
            sx={{
                mt: 3,
                px: 2,
                py: 1.5,
                borderRadius: 1.5,
                border:
                    "1px solid",
                borderColor:
                    isError
                        ? "error.light"
                        : "divider",
                backgroundColor:
                    isError
                        ? "error.lighter"
                        : "action.hover"
            }}
        >

            <Typography
                variant="body2"
                color={
                    isError
                        ? "error.main"
                        : "text.secondary"
                }
            >
                {
                    message
                }
            </Typography>

        </Box>

    );

};


// =====================================================
// ERROR MESSAGE
// =====================================================

const getErrorMessage = (
    error,
    fallback
) => {

    if (
        typeof error === "string" &&
        error.trim()
    ) {

        return error;

    }


    if (
        error?.message &&
        typeof error.message === "string"
    ) {

        return error.message;

    }


    if (
        error?.response?.data?.message &&
        typeof error.response.data.message === "string"
    ) {

        return error.response.data.message;

    }


    return fallback;

};


// =====================================================
// FORMAT DATE
// =====================================================

const formatDate = (
    value
) => {

    if (
        !value
    ) {

        return "";

    }


    if (
        value instanceof Date
    ) {

        return value
            .toISOString()
            .split(
                "T"
            )[0];

    }


    if (
        typeof value === "string"
    ) {

        if (
            /^\d{4}-\d{2}-\d{2}$/.test(
                value
            )
        ) {

            return value;

        }


        const date =
            new Date(
                value
            );


        if (
            Number.isNaN(
                date.getTime()
            )
        ) {

            return value;

        }


        return [

            date.getFullYear(),

            String(
                date.getMonth() + 1
            ).padStart(
                2,
                "0"
            ),

            String(
                date.getDate()
            ).padStart(
                2,
                "0"
            )

        ].join(
            "-"
        );

    }


    if (
        typeof value?.format ===
        "function"
    ) {

        return value.format(
            "YYYY-MM-DD"
        );

    }


    return "";

};


// =====================================================
// FORMAT DISPLAY DATE/TIME
// =====================================================

const formatDisplayDateTime = (
    value
) => {

    if (
        !value
    ) {

        return "";

    }


    const date =
        new Date(
            value
        );


    if (
        Number.isNaN(
            date.getTime()
        )
    ) {

        return String(
            value
        );

    }


    return date.toLocaleString();

};


export default ReportsPage;