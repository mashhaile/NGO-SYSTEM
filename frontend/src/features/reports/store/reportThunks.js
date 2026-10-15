import {
    createAsyncThunk
} from "@reduxjs/toolkit";


import {
    getReportsService,
    generateReportService,
    exportReportService,
    getReportProgramsService,
    getReportProjectsService,
    getReportActivitiesService,
    getReportActivityRunsService,
    getReportEnterprisesService
} from "../services/reportService";


// =====================================================
// RESPONSE DATA HELPER
// =====================================================

const getResponseData = (
    response
) => {

    const data =
        response?.data?.data ??
        response?.data ??
        [];

    return (
        Array.isArray(data)
            ? data
            : []
    );

};


// =====================================================
// REPORT FILTER HELPER
// =====================================================

const buildReportFilters = (
    filters = {}
) => {

    const cleanedFilters = {};


    Object.entries(
        filters
    ).forEach(
        (
            [
                key,
                value
            ]
        ) => {

            if (
                value !==
                    undefined &&
                value !==
                    null &&
                value !==
                    ""
            ) {

                cleanedFilters[key] =
                    value;

            }

        }
    );


    return cleanedFilters;

};


// =====================================================
// FILE NAME HELPER
// =====================================================

const getFileNameFromResponse = (
    response,
    reportName,
    format
) => {

    const contentDisposition =
        response?.headers?.[
            "content-disposition"
        ];


    if (
        contentDisposition
    ) {

        const utf8Match =
            contentDisposition.match(
                /filename\*=UTF-8''([^;]+)/i
            );


        if (
            utf8Match &&
            utf8Match[1]
        ) {

            return decodeURIComponent(
                utf8Match[1]
            );

        }


        const filenameMatch =
            contentDisposition.match(
                /filename="?([^"]+)"?/i
            );


        if (
            filenameMatch &&
            filenameMatch[1]
        ) {

            return filenameMatch[1];

        }

    }


    const extension =
        format === "pdf"
            ? "pdf"
            : "xlsx";


    const safeReportName =
        String(
            reportName ||
            "report"
        )
            .replace(
                /[^a-zA-Z0-9-_]+/g,
                "-"
            )
            .replace(
                /^-+|-+$/g,
                ""
            )
            .toLowerCase();


    return (
        `${safeReportName || "report"}` +
        `.${extension}`
    );

};


// =====================================================
// DOWNLOAD BLOB
// =====================================================

const downloadBlob = (
    response,
    reportName,
    format
) => {

    if (
        !response?.data
    ) {

        throw new Error(
            "The server returned an empty report file."
        );

    }


    const blob =
        response.data instanceof Blob
            ? response.data
            : new Blob(
                [
                    response.data
                ]
            );


    const url =
        window.URL.createObjectURL(
            blob
        );


    const link =
        document.createElement(
            "a"
        );


    const fileName =
        getFileNameFromResponse(
            response,
            reportName,
            format
        );


    link.href =
        url;

    link.download =
        fileName;

    document.body.appendChild(
        link
    );

    link.click();

    link.remove();


    window.URL.revokeObjectURL(
        url
    );


    return {
        fileName,
        format
    };

};


// =====================================================
// GET AVAILABLE REPORTS
// =====================================================

export const getReportsThunk =
    createAsyncThunk(
        "reports/getAll",

        async (
            _,
            thunkAPI
        ) => {

            try {

                const response =
                    await getReportsService();

                return response;

            } catch (
                error
            ) {

                return thunkAPI.rejectWithValue(
                    error.response?.data?.message ||
                    error.message ||
                    "Failed loading reports"
                );

            }

        }
    );


// =====================================================
// GENERATE REPORT
// =====================================================

export const generateReportThunk =
    createAsyncThunk(
        "reports/generate",

        async (
            {
                reportName,
                filters = {}
            },
            thunkAPI
        ) => {

            try {

                const reportFilters =
                    buildReportFilters(
                        filters
                    );


                const response =
                    await generateReportService(
                        reportName,
                        reportFilters
                    );

                return response;

            } catch (
                error
            ) {

                return thunkAPI.rejectWithValue(
                    error.response?.data?.message ||
                    error.message ||
                    "Failed generating report"
                );

            }

        }
    );


// =====================================================
// EXPORT PDF REPORT
// =====================================================

export const exportReportPdfThunk =
    createAsyncThunk(
        "reports/exportPdf",

        async (
            {
                reportName,
                filters = {}
            },
            thunkAPI
        ) => {

            try {

                const reportFilters =
                    buildReportFilters(
                        filters
                    );


                const response =
                    await exportReportService(
                        reportName,
                        reportFilters,
                        "pdf"
                    );


                return downloadBlob(
                    response,
                    reportName,
                    "pdf"
                );

            } catch (
                error
            ) {

                return thunkAPI.rejectWithValue(
                    error.response?.data?.message ||
                    error.message ||
                    "Failed downloading PDF report"
                );

            }

        }
    );


// =====================================================
// EXPORT EXCEL REPORT
// =====================================================

export const exportReportExcelThunk =
    createAsyncThunk(
        "reports/exportExcel",

        async (
            {
                reportName,
                filters = {}
            },
            thunkAPI
        ) => {

            try {

                const reportFilters =
                    buildReportFilters(
                        filters
                    );


                const response =
                    await exportReportService(
                        reportName,
                        reportFilters,
                        "excel"
                    );


                return downloadBlob(
                    response,
                    reportName,
                    "excel"
                );

            } catch (
                error
            ) {

                return thunkAPI.rejectWithValue(
                    error.response?.data?.message ||
                    error.message ||
                    "Failed downloading Excel report"
                );

            }

        }
    );


// =====================================================
// GET PROGRAMS
// =====================================================

export const getReportProgramsThunk =
    createAsyncThunk(
        "reports/getPrograms",

        async (
            _,
            thunkAPI
        ) => {

            try {

                const response =
                    await getReportProgramsService();

                return getResponseData(
                    response
                );

            } catch (
                error
            ) {

                return thunkAPI.rejectWithValue(
                    error.response?.data?.message ||
                    error.message ||
                    "Failed loading programs"
                );

            }

        }
    );


// =====================================================
// GET PROJECTS
// =====================================================

export const getReportProjectsThunk =
    createAsyncThunk(
        "reports/getProjects",

        async (
            _,
            thunkAPI
        ) => {

            try {

                const response =
                    await getReportProjectsService();

                return getResponseData(
                    response
                );

            } catch (
                error
            ) {

                return thunkAPI.rejectWithValue(
                    error.response?.data?.message ||
                    error.message ||
                    "Failed loading projects"
                );

            }

        }
    );


// =====================================================
// GET ACTIVITIES
// =====================================================

export const getReportActivitiesThunk =
    createAsyncThunk(
        "reports/getActivities",

        async (
            _,
            thunkAPI
        ) => {

            try {

                const response =
                    await getReportActivitiesService();

                return getResponseData(
                    response
                );

            } catch (
                error
            ) {

                return thunkAPI.rejectWithValue(
                    error.response?.data?.message ||
                    error.message ||
                    "Failed loading activities"
                );

            }

        }
    );


// =====================================================
// GET ACTIVITY RUNS
// =====================================================

export const getReportActivityRunsThunk =
    createAsyncThunk(
        "reports/getActivityRuns",

        async (
            _,
            thunkAPI
        ) => {

            try {

                const response =
                    await getReportActivityRunsService();

                return getResponseData(
                    response
                );

            } catch (
                error
            ) {

                return thunkAPI.rejectWithValue(
                    error.response?.data?.message ||
                    error.message ||
                    "Failed loading activity runs"
                );

            }

        }
    );


// =====================================================
// GET ENTERPRISES
// =====================================================

export const getReportEnterprisesThunk =
    createAsyncThunk(
        "reports/getEnterprises",

        async (
            _,
            thunkAPI
        ) => {

            try {

                const response =
                    await getReportEnterprisesService();

                return getResponseData(
                    response
                );

            } catch (
                error
            ) {

                return thunkAPI.rejectWithValue(
                    error.response?.data?.message ||
                    error.message ||
                    "Failed loading enterprises"
                );

            }

        }
    );