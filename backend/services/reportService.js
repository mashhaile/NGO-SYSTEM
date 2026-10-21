const reportEngine =
    require("./reports/reportEngine");

const reportRegistry =
    require("./reports/reportRegistry");


// =====================================================
// DATE / PERIOD FILTER VALIDATION
// =====================================================

const hasReportingPeriod =
    (filters = {}) => {

        return Boolean(

            filters.startDate ||

            filters.endDate ||

            filters.year ||

            filters.period ||

            filters.month ||

            filters.quarter ||

            filters.half

        );

    };


// =====================================================
// VALIDATE REPORTING PERIOD
// =====================================================

const validateReportingPeriod =
    (filters = {}) => {

        if (
            !hasReportingPeriod(filters)
        ) {

            const error =
                new Error(
                    "Please select a date or reporting period before generating the report."
                );

            error.statusCode =
                400;

            throw error;

        }

    };


// =====================================================
// GET AVAILABLE REPORTS
// =====================================================

const getAvailableReports = async (
    context
) => {

    if (
        !context ||
        !context.organizationId
    ) {

        throw new Error(
            "Report organization context is required."
        );

    }


    return Object.keys(
        reportRegistry
    );

};


// =====================================================
// GENERATE REPORT
// =====================================================

const generateReport = async (

    reportName,

    filters = {},

    context

) => {

    if (!reportName) {

        throw new Error(
            "Report name is required."
        );

    }


    if (
        !context ||
        !context.organizationId
    ) {

        throw new Error(
            "Report organization context is required."
        );

    }


    // ---------------------------------------------
    // Reporting Period Is Mandatory
    // ---------------------------------------------

    // Except Budget vs Actual: it is for one fiscal year and
    // defaults to the current one (or the start date's year).
    if (reportName !== "budgetVsActualReport") {
        validateReportingPeriod(
            filters
        );
    }


    // ---------------------------------------------
    // Validate Report
    // ---------------------------------------------

    if (
        !reportRegistry[
            reportName
        ]
    ) {

        const error =
            new Error(
                `Unknown report: ${reportName}`
            );

        error.statusCode =
            400;

        throw error;

    }


    // ---------------------------------------------
    // Generate Report
    // ---------------------------------------------

    return await reportEngine.generateReport(

        reportName,

        filters,

        context

    );

};


// =====================================================
// CHECK REPORT EXISTS
// =====================================================

const reportExists = (

    reportName

) => {

    return Boolean(
        reportRegistry[
            reportName
        ]
    );

};


// =====================================================
// EXPORT
// =====================================================

module.exports = {

    getAvailableReports,

    generateReport,

    reportExists

};