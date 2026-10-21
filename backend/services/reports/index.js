const {
    createPdfDocument
} = require("./pdf");

const {
    createWorkbook
} = require("./excel");

const {
    createCsv
} = require("./csv");

const serviceDeliveryExport =
    require("./exports/servicedeliveryexport");

// Generic Excel / PDF / CSV built from summary, statistics
// and details (all reports except Service Delivery)
const genericExport =
    require("./reportExport");


/* =========================================================
   REPORT BUILDERS
========================================================= */

const REPORT_BUILDERS = {
    serviceDelivery:
        serviceDeliveryExport
};


/* =========================================================
   GET REPORT BUILDER
========================================================= */

const getReportBuilder = (
    reportType
) => {

    const builder =
        REPORT_BUILDERS[
            reportType
        ];

    if (!builder) {

        throw new Error(
            `Unsupported report type: ${reportType}`
        );

    }

    return builder;
};


/* =========================================================
   NORMALIZE FORMAT
========================================================= */

const normalizeFormat = (
    format
) => {

    const value =
        String(
            format || "pdf"
        )
            .trim()
            .toLowerCase();


    if (
        ![
            "pdf",
            "excel",
            "xlsx",
            "csv"
        ].includes(value)
    ) {

        throw new Error(
            `Unsupported report format: ${format}`
        );

    }


    if (
        value === "xlsx"
    ) {

        return "excel";

    }


    return value;
};


/* =========================================================
   BUILD REPORT DATA
========================================================= */

const buildReport = async ({
    reportType,
    report,
    options = {}
}) => {

    const builder =
        getReportBuilder(
            reportType
        );


    if (
        !builder ||
        typeof builder.build !==
            "function"
    ) {

        throw new Error(
            `Report builder for ${reportType} must export a build() function`
        );

    }


    return builder.build(
        report,
        options
    );
};


/* =========================================================
   EXPORT PDF
========================================================= */

const exportPdf = async ({
    reportType,
    report,
    options = {}
}) => {

    // No custom builder (only Service Delivery has one):
    // use the generic exporter for every other report.
    if (!REPORT_BUILDERS[reportType]) {
        return genericExport.exportPDF(report, options.context || {});
    }

    const builder =
        getReportBuilder(
            reportType
        );


    if (
        typeof builder.toPdf !==
            "function"
    ) {

        throw new Error(
            `PDF export is not implemented for ${reportType}`
        );

    }


    const doc =
        createPdfDocument(
            options.pdf || {}
        );


    return new Promise(
        async (
            resolve,
            reject
        ) => {

            const chunks = [];


            // ---------------------------------------------
            // Collect generated PDF data
            // ---------------------------------------------

            doc.on(
                "data",
                chunk => {

                    chunks.push(
                        chunk
                    );

                }
            );


            // ---------------------------------------------
            // PDF completed
            // ---------------------------------------------

            doc.on(
                "end",
                () => {

                    try {

                        const buffer =
                            Buffer.concat(
                                chunks
                            );


                        resolve(
                            buffer
                        );

                    }

                    catch (error) {

                        reject(
                            error
                        );

                    }

                }
            );


            // ---------------------------------------------
            // PDF stream error
            // ---------------------------------------------

            doc.on(
                "error",
                error => {

                    reject(
                        error
                    );

                }
            );


            try {

                // -----------------------------------------
                // Build report into PDF document
                // -----------------------------------------

                await builder.toPdf(
                    doc,
                    report,
                    options
                );


                // -----------------------------------------
                // IMPORTANT:
                // Finish PDFKit document
                // -----------------------------------------

                doc.end();

            }

            catch (error) {

                reject(
                    error
                );

            }

        }
    );
};


/* =========================================================
   EXPORT EXCEL
========================================================= */

const exportExcel = async ({
    reportType,
    report,
    options = {}
}) => {

    // No custom builder (only Service Delivery has one):
    // use the generic exporter for every other report.
    if (!REPORT_BUILDERS[reportType]) {
        return genericExport.exportExcel(report, options.context || {});
    }

    const builder =
        getReportBuilder(
            reportType
        );


    if (
        typeof builder.toExcel !==
            "function"
    ) {

        throw new Error(
            `Excel export is not implemented for ${reportType}`
        );

    }


    const workbook =
        createWorkbook(
            options.excel || {}
        );


    await builder.toExcel(
        workbook,
        report,
        options
    );


    return workbook;
};


/* =========================================================
   EXPORT CSV
========================================================= */

const exportCsv = async ({
    reportType,
    report,
    options = {}
}) => {

    // No custom builder (only Service Delivery has one):
    // use the generic exporter for every other report.
    if (!REPORT_BUILDERS[reportType]) {
        return genericExport.exportCSV(report, options.context || {});
    }

    const builder =
        getReportBuilder(
            reportType
        );


    if (
        typeof builder.toCsv !==
            "function"
    ) {

        throw new Error(
            `CSV export is not implemented for ${reportType}`
        );

    }


    return builder.toCsv(
        report,
        options
    );
};


/* =========================================================
   MAIN EXPORT
========================================================= */

const exportReport = async ({
    reportType,
    format = "pdf",
    report,
    options = {}
}) => {

    if (!reportType) {

        throw new Error(
            "reportType is required"
        );

    }


    if (!report) {

        throw new Error(
            "report data is required"
        );

    }


    const normalizedFormat =
        normalizeFormat(
            format
        );


    switch (
        normalizedFormat
    ) {

        case "pdf":

            return exportPdf({

                reportType,

                report,

                options

            });


        case "excel":

            return exportExcel({

                reportType,

                report,

                options

            });


        case "csv":

            return exportCsv({

                reportType,

                report,

                options

            });


        default:

            throw new Error(
                `Unsupported report format: ${format}`
            );

    }

};


/* =========================================================
   REGISTER REPORT BUILDER
========================================================= */

const registerReportBuilder = (
    reportType,
    builder
) => {

    if (!reportType) {

        throw new Error(
            "reportType is required"
        );

    }


    if (
        !builder ||
        typeof builder !==
            "object"
    ) {

        throw new Error(
            `Invalid report builder for ${reportType}`
        );

    }


    REPORT_BUILDERS[
        reportType
    ] = builder;
};


/* =========================================================
   EXPORT
========================================================= */

module.exports = {

    REPORT_BUILDERS,

    getReportBuilder,

    normalizeFormat,

    buildReport,

    exportPdf,

    exportExcel,

    exportCsv,

    exportReport,

    registerReportBuilder

};