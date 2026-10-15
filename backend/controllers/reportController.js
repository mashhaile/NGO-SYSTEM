const reportService =
    require("../services/reportService");

const reportExport =
    require("../services/reports");

const {
    buildReportContext
} =
    require("../services/reports/reportContext");


// =====================================================
// REPORT TYPE NORMALIZER
// =====================================================

const getReportType = (
    reportName
) => {

    const value =
        String(
            reportName || ""
        )
            .trim()
            .toLowerCase();


    const aliases = {

        servicedelivery:
            "serviceDelivery",

        "service-delivery":
            "serviceDelivery",

        "service_delivery":
            "serviceDelivery",

        servicedeliveryreport:
            "serviceDelivery",

        "service-delivery-report":
            "serviceDelivery"

    };


    return (
        aliases[value] ||
        reportName
    );

};


// =====================================================
// GET AVAILABLE REPORTS
// =====================================================

const getReports = async (
    req,
    res
) => {

    try {

        const context =
            await buildReportContext(
                req
            );


        const reports =
            await reportService.getAvailableReports(
                context
            );


        return res.json({

            success:
                true,

            message:
                "Reports retrieved successfully",

            data:
                reports

        });

    }

    catch (error) {

        console.error(
            "GET REPORTS ERROR:",
            error
        );


        return res.status(
            error.statusCode || 500
        ).json({

            success:
                false,

            message:
                error.message,

            errors:
                []

        });

    }

};


// =====================================================
// GENERATE REPORT
// =====================================================

const getReport = async (
    req,
    res
) => {

    try {

        const {
            reportName
        } =
            req.params;


        // ---------------------------------------------
        // Validate Report Name
        // ---------------------------------------------

        if (!reportName) {

            return res.status(
                400
            ).json({

                success:
                    false,

                message:
                    "Report name is required.",

                errors:
                    []

            });

        }


        // ---------------------------------------------
        // Determine Report Type
        // ---------------------------------------------

        const reportType =
            getReportType(
                reportName
            );


        // ---------------------------------------------
        // Export Format
        // ---------------------------------------------

        const format =
            String(
                req.query.format ||
                "json"
            )
                .trim()
                .toLowerCase();


        // ---------------------------------------------
        // Filters
        // ---------------------------------------------

        const filters = {
            ...req.query
        };


        delete filters.format;


        // ---------------------------------------------
        // Build SaaS Context
        // ---------------------------------------------

        const context =
            await buildReportContext(
                req
            );


        // ---------------------------------------------
        // Generate Report
        // ---------------------------------------------

        const report =
            await reportService.generateReport(

                reportName,

                filters,

                context

            );


        // =================================================
        // JSON
        // =================================================

        if (
            format === "json"
        ) {

            return res.json({

                success:
                    true,

                message:
                    "Report generated successfully",

                data:
                    report

            });

        }


        // =================================================
        // EXPORT PERMISSION
        // =================================================

        const normalizedFormat =
            format === "xlsx"
                ? "excel"
                : format;


        const allowedExports =
            req.plan?.features?.exports ||
            {};


        if (
            allowedExports[
                normalizedFormat
            ] !== true
        ) {

            const planName =
                req.plan?.name ||
                "current";


            return res.status(
                403
            ).json({

                success:
                    false,

                message:
                    `Your ${planName} plan does not allow ${normalizedFormat.toUpperCase()} exports.`,

                errors:
                    []

            });

        }


        // =================================================
        // EXPORT OPTIONS
        // =================================================

        const options = {

            context,

            filters,

            reportName

        };


        // =================================================
        // EXCEL EXPORT
        // =================================================

        if (
            normalizedFormat === "excel"
        ) {

            const file =
                await reportExport.exportExcel({

                    reportType,

                    report,

                    options

                });


            res.setHeader(

                "Content-Type",

                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

            );


            res.setHeader(

                "Content-Disposition",

                `attachment; filename="${reportName}.xlsx"`

            );


            return res.send(
                file
            );

        }


        // =================================================
        // CSV EXPORT
        // =================================================

        if (
            normalizedFormat === "csv"
        ) {

            const file =
                await reportExport.exportCsv({

                    reportType,

                    report,

                    options

                });


            res.setHeader(

                "Content-Type",

                "text/csv"

            );


            res.setHeader(

                "Content-Disposition",

                `attachment; filename="${reportName}.csv"`

            );


            return res.send(
                file
            );

        }


        // =================================================
        // PDF EXPORT
        // =================================================

        if (
            normalizedFormat === "pdf"
        ) {

            const file =
                await reportExport.exportPdf({

                    reportType,

                    report,

                    options

                });


            res.setHeader(

                "Content-Type",

                "application/pdf"

            );


            res.setHeader(

                "Content-Disposition",

                `attachment; filename="${reportName}.pdf"`

            );


            return res.send(
                file
            );

        }


        // =================================================
        // INVALID FORMAT
        // =================================================

        return res.status(
            400
        ).json({

            success:
                false,

            message:
                `Unsupported report format: ${format}`,

            errors:
                []

        });

    }

    catch (error) {

        console.error(
            "GENERATE REPORT ERROR:",
            error
        );


        return res.status(
            error.statusCode || 500
        ).json({

            success:
                false,

            message:
                error.message,

            errors:
                []

        });

    }

};


// =====================================================
// EXPORT
// =====================================================

module.exports = {

    getReports,

    getReport

};