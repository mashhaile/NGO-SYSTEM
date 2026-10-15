const PDFDocument = require("pdfkit");

const {
    normalizeText,
    formatMoney,
    formatDate,
    formatDateTime,
    formatNumber
} = require("./helpers");


/* =========================================================
   DOCUMENT
========================================================= */

const createPdfDocument = (
    options = {}
) => {
    return new PDFDocument({
        size:
            options.size || "A4",

        layout:
            options.layout || "landscape",

        margins: {
            top: 40,
            bottom: 45,
            left: 35,
            right: 35
        },

        /*
         * Required so that footers can be added after
         * the complete report has been rendered.
         */
        bufferPages: true,

        autoFirstPage: true
    });
};


/* =========================================================
   TEXT
========================================================= */

const drawTitle = (
    doc,
    title,
    subtitle = null
) => {

    /*
     * Report title
     */
    doc
        .font("Helvetica-Bold")
        .fontSize(19)
        .text(
            normalizeText(
                title,
                "Report"
            ),
            {
                align: "center"
            }
        );


    /*
     * Optional subtitle
     */
    if (subtitle) {

        doc
            .moveDown(0.25)
            .font("Helvetica")
            .fontSize(9.5)
            .text(
                normalizeText(
                    subtitle,
                    ""
                ),
                {
                    align: "center"
                }
            );
    }


    doc.moveDown(0.7);
};


/* =========================================================
   SECTION TITLE
========================================================= */

const drawSectionTitle = (
    doc,
    title
) => {

    /*
     * Keep the section heading together with
     * at least a small amount of content.
     */
    ensureSpace(
        doc,
        32
    );


    /*
     * Available printable width.
     */
    const availableWidth =
        doc.page.width -
        doc.page.margins.left -
        doc.page.margins.right;


    /*
     * Center section title.
     */
    doc
        .font("Helvetica-Bold")
        .fontSize(11.5)
        .text(
            normalizeText(
                title,
                ""
            ),
            doc.page.margins.left,
            doc.y,
            {
                width:
                    availableWidth,

                align:
                    "center"
            }
        );


    doc.moveDown(0.35);
};


/* =========================================================
   KEY / VALUE
========================================================= */

const drawKeyValue = (
    doc,
    label,
    value,
    options = {}
) => {

    const labelWidth =
        options.labelWidth || 105;


    const valueWidth =
        options.valueWidth ||
        (
            doc.page.width -
            doc.page.margins.left -
            doc.page.margins.right -
            labelWidth
        );


    const startX =
        options.x ??
        doc.page.margins.left;


    const startY =
        options.y ??
        doc.y;


    const fontSize =
        options.fontSize || 9;


    /*
     * Label
     */
    doc
        .font("Helvetica-Bold")
        .fontSize(fontSize)
        .text(
            normalizeText(
                label,
                ""
            ),
            startX,
            startY,
            {
                width:
                    labelWidth,

                continued:
                    false
            }
        );


    /*
     * Value
     */
    doc
        .font("Helvetica")
        .fontSize(fontSize)
        .text(
            normalizeText(
                value,
                "—"
            ),
            startX + labelWidth,
            startY,
            {
                width:
                    valueWidth
            }
        );


    /*
     * Preserve the largest resulting Y position.
     */
    doc.y =
        Math.max(
            doc.y,
            startY +
                fontSize +
                3
        );
};


/* =========================================================
   KEY / VALUE GRID
========================================================= */

const drawKeyValueGrid = (
    doc,
    rows,
    options = {}
) => {

    if (
        !Array.isArray(rows) ||
        rows.length === 0
    ) {
        return;
    }


    const columns =
        options.columns || 2;


    const gap =
        options.gap || 15;


    const availableWidth =
        doc.page.width -
        doc.page.margins.left -
        doc.page.margins.right;


    const columnWidth =
        (
            availableWidth -
            (
                gap *
                (columns - 1)
            )
        ) /
        columns;


    const labelWidth =
        options.labelWidth || 80;


    const valueWidth =
        columnWidth -
        labelWidth;


    const fontSize =
        options.fontSize || 9;


    let index = 0;


    while (
        index < rows.length
    ) {

        /*
         * Make sure this key/value row has room.
         */
        ensureSpace(
            doc,
            fontSize + 12
        );


        const rowStartY =
            doc.y;


        let rowHeight = 0;


        for (
            let column = 0;
            column < columns;
            column++
        ) {

            const row =
                rows[
                    index + column
                ];


            if (!row) {
                continue;
            }


            const x =
                doc.page.margins.left +
                column *
                    (
                        columnWidth +
                        gap
                    );


            drawKeyValue(
                doc,
                row.label,
                row.value,
                {
                    x,
                    y:
                        rowStartY,

                    labelWidth,
                    valueWidth,

                    fontSize
                }
            );


            rowHeight =
                Math.max(
                    rowHeight,
                    doc.y -
                        rowStartY
                );
        }


        doc.y =
            rowStartY +
            rowHeight +
            4;


        index += columns;
    }
};


/* =========================================================
   SUMMARY
========================================================= */

const drawSummaryGrid = (
    doc,
    rows
) => {

    /*
     * The calling report owns the section title.
     * Do not create another "Summary" heading here.
     */
    drawKeyValueGrid(
        doc,
        rows,
        {
            columns: 2,

            labelWidth: 125,

            fontSize: 9
        }
    );


    doc.moveDown(0.5);
};


/* =========================================================
   TABLE HELPERS
========================================================= */

const calculateColumnWidths = (
    doc,
    columns,
    options = {}
) => {

    const availableWidth =
        doc.page.width -
        doc.page.margins.left -
        doc.page.margins.right;


    /*
     * Explicit widths take priority.
     */
    if (
        Array.isArray(options.widths) &&
        options.widths.length ===
            columns.length
    ) {
        return options.widths;
    }


    /*
     * Weighted columns.
     */
    const totalWeight =
        columns.reduce(
            (
                sum,
                column
            ) =>
                sum +
                (
                    column.weight ||
                    1
                ),
            0
        );


    return columns.map(
        column =>
            availableWidth *
            (
                (
                    column.weight ||
                    1
                ) /
                totalWeight
            )
    );
};


/* =========================================================
   TABLE ROW HEIGHT
========================================================= */

const getTableRowHeight = (
    doc,
    values,
    widths,
    options = {}
) => {

    const fontSize =
        options.fontSize || 8.5;


    const padding =
        options.padding || 5;


    let maxHeight = 0;


    values.forEach(
        (
            value,
            index
        ) => {

            const text =
                normalizeText(
                    value,
                    "—"
                );


            const width =
                Math.max(
                    20,
                    widths[index] -
                    padding * 2
                );


            const height =
                doc.heightOfString(
                    text,
                    {
                        width,

                        lineGap:
                            1.5
                    }
                );


            maxHeight =
                Math.max(
                    maxHeight,
                    height +
                        padding * 2
                );
        }
    );


    return Math.max(
        options.minRowHeight || 24,
        maxHeight
    );
};


/* =========================================================
   TABLE HEADER
========================================================= */

const drawTableHeader = (
    doc,
    columns,
    widths,
    options = {}
) => {

    const fontSize =
        options.fontSize || 8.5;


    const padding =
        options.padding || 5;


    const height =
        options.headerHeight || 27;


    const x =
        doc.page.margins.left;


    const y =
        doc.y;


    const totalWidth =
        widths.reduce(
            (
                sum,
                width
            ) =>
                sum + width,
            0
        );


    /*
     * Header background.
     */
    doc
        .save()
        .fillColor("#E9ECEF")
        .rect(
            x,
            y,
            totalWidth,
            height
        )
        .fill()
        .restore();


    /*
     * Header border.
     */
    doc
        .save()
        .strokeColor("#B8B8B8")
        .lineWidth(0.6)
        .rect(
            x,
            y,
            totalWidth,
            height
        )
        .stroke()
        .restore();


    let currentX = x;


    columns.forEach(
        (
            column,
            index
        ) => {

            /*
             * Vertical separator.
             */
            if (index > 0) {

                doc
                    .save()
                    .strokeColor("#B8B8B8")
                    .lineWidth(0.5)
                    .moveTo(
                        currentX,
                        y
                    )
                    .lineTo(
                        currentX,
                        y + height
                    )
                    .stroke()
                    .restore();
            }


            /*
             * Header text.
             */
            doc
                .font("Helvetica-Bold")
                .fontSize(fontSize)
                .fillColor("#000000")
                .text(
                    normalizeText(
                        column.label,
                        ""
                    ),
                    currentX + padding,
                    y + padding,
                    {
                        width:
                            widths[index] -
                            padding * 2,

                        height:
                            height -
                            padding * 2,

                        align:
                            column.align ||
                            "left",

                        valign:
                            "center"
                    }
                );


            currentX +=
                widths[index];
        }
    );


    doc.y =
        y + height;
};


/* =========================================================
   TABLE ROW
========================================================= */

const drawTableRow = (
    doc,
    values,
    columns,
    widths,
    options = {}
) => {

    const fontSize =
        options.fontSize || 8.5;


    const padding =
        options.padding || 5;


    const height =
        getTableRowHeight(
            doc,
            values,
            widths,
            {
                fontSize,

                padding,

                minRowHeight:
                    options.minRowHeight ||
                    24
            }
        );


    const x =
        doc.page.margins.left;


    const y =
        doc.y;


    const totalWidth =
        widths.reduce(
            (
                sum,
                width
            ) =>
                sum + width,
            0
        );


    /*
     * Outer row border.
     */
    doc
        .save()
        .strokeColor("#C8C8C8")
        .lineWidth(0.5)
        .rect(
            x,
            y,
            totalWidth,
            height
        )
        .stroke()
        .restore();


    let currentX = x;


    values.forEach(
        (
            value,
            index
        ) => {

            const column =
                columns[index] ||
                {};


            /*
             * Vertical cell separator.
             */
            if (index > 0) {

                doc
                    .save()
                    .strokeColor("#D0D0D0")
                    .lineWidth(0.4)
                    .moveTo(
                        currentX,
                        y
                    )
                    .lineTo(
                        currentX,
                        y + height
                    )
                    .stroke()
                    .restore();
            }


            /*
             * Cell text.
             */
            doc
                .font("Helvetica")
                .fontSize(fontSize)
                .fillColor("#000000")
                .text(
                    normalizeText(
                        value,
                        "—"
                    ),
                    currentX + padding,
                    y + padding,
                    {
                        width:
                            widths[index] -
                            padding * 2,

                        height:
                            height -
                            padding * 2,

                        align:
                            column.align ||
                            "left",

                        valign:
                            "center"
                    }
                );


            currentX +=
                widths[index];
        }
    );


    doc.y =
        y + height;
};


/* =========================================================
   TABLE
========================================================= */

const drawTable = (
    doc,
    columns,
    rows,
    options = {}
) => {

    /*
     * Do not create an empty table.
     */
    if (
        !Array.isArray(columns) ||
        columns.length === 0 ||
        !Array.isArray(rows) ||
        rows.length === 0
    ) {
        return;
    }


    const widths =
        calculateColumnWidths(
            doc,
            columns,
            options
        );


    const headerHeight =
        options.headerHeight ||
        27;


    const fontSize =
        options.fontSize ||
        8.5;


    const padding =
        options.padding ||
        5;


    const minRowHeight =
        options.minRowHeight ||
        24;


    const bottomLimit =
        doc.page.height -
        doc.page.margins.bottom;


    /*
     * Draw table header.
     */
    const drawHeader = () => {

        drawTableHeader(
            doc,
            columns,
            widths,
            {
                headerHeight,
                fontSize,
                padding
            }
        );
    };


    /*
     * Build first row so we can determine
     * whether the table should start on
     * a new page.
     */
    const firstRow =
        rows[0];


    const firstValues =
        columns.map(
            column => {

                if (
                    typeof column.value ===
                    "function"
                ) {
                    return column.value(
                        firstRow
                    );
                }

                return firstRow[
                    column.key
                ];
            }
        );


    const firstRowHeight =
        getTableRowHeight(
            doc,
            firstValues,
            widths,
            {
                fontSize,
                padding,
                minRowHeight
            }
        );


    /*
     * If the current page cannot fit
     * the header plus the first row,
     * move to the next page.
     */
    ensureSpace(
        doc,
        headerHeight +
        firstRowHeight +
        8
    );


    drawHeader();


    rows.forEach(
        row => {

            const values =
                columns.map(
                    column => {

                        if (
                            typeof column.value ===
                            "function"
                        ) {
                            return column.value(
                                row
                            );
                        }

                        return row[
                            column.key
                        ];
                    }
                );


            const rowHeight =
                getTableRowHeight(
                    doc,
                    values,
                    widths,
                    {
                        fontSize,
                        padding,
                        minRowHeight
                    }
                );


            /*
             * If the row does not fit on
             * the current page, continue
             * on a new page.
             */
            if (
                doc.y +
                rowHeight >
                bottomLimit
            ) {

                doc.addPage();


                /*
                 * PDFKit starts the new page
                 * at the configured top margin.
                 */
                doc.y =
                    doc.page.margins.top;


                /*
                 * Repeat the table header.
                 */
                drawHeader();
            }


            drawTableRow(
                doc,
                values,
                columns,
                widths,
                {
                    fontSize,
                    padding,
                    minRowHeight
                }
            );
        }
    );


    doc.moveDown(0.35);
};


/* =========================================================
   PAGE CONTROL
========================================================= */

const ensureSpace = (
    doc,
    requiredHeight = 30
) => {

    const top =
        doc.page.margins.top;


    const bottom =
        doc.page.height -
        doc.page.margins.bottom;


    /*
     * If we are already at the beginning
     * of a page, don't create another page.
     *
     * This prevents cascading blank pages.
     */
    if (
        doc.y <=
        top + 2
    ) {
        return false;
    }


    if (
        doc.y +
        requiredHeight >
        bottom
    ) {

        doc.addPage();


        doc.y =
            top;


        return true;
    }


    return false;
};


/* =========================================================
   PAGE FOOTER
========================================================= */

const addPageFooters = (
    doc,
    options = {}
) => {

    const range =
        doc.bufferedPageRange();


    const leftText =
        normalizeText(
            options.leftText,
            ""
        );


    for (
        let index = 0;
        index < range.count;
        index++
    ) {

        doc.switchToPage(
            range.start + index
        );


        const footerY =
            doc.page.height -
            28;


        const rightText =
            `Page ${index + 1}`;


        /*
         * Left footer.
         */
        doc
            .font("Helvetica")
            .fontSize(8)
            .text(
                leftText,
                doc.page.margins.left,
                footerY,
                {
                    width:
                        doc.page.width -
                        doc.page.margins.left -
                        doc.page.margins.right -
                        60
                }
            );


        /*
         * Right footer.
         */
        doc
            .font("Helvetica")
            .fontSize(8)
            .text(
                rightText,
                doc.page.width -
                    doc.page.margins.right -
                    45,
                footerY,
                {
                    width: 45,

                    align:
                        "right"
                }
            );
    }
};


/* =========================================================
   REPORT METADATA
========================================================= */

const drawReportMetadata = (
    doc,
    {
        organization,
        generatedAt,
        reportingPeriod
    } = {}
) => {

    drawKeyValueGrid(
        doc,
        [
            {
                label:
                    "Organization",

                value:
                    normalizeText(
                        organization,
                        "—"
                    )
            },

            {
                label:
                    "Generated",

                value:
                    generatedAt
                        ? formatDateTime(
                            generatedAt
                        )
                        : "—"
            },

            {
                label:
                    "Reporting Period",

                value:
                    normalizeText(
                        reportingPeriod,
                        "—"
                    )
            }
        ],
        {
            columns: 2,

            labelWidth: 100,

            fontSize: 9
        }
    );


    doc.moveDown(0.5);
};


/* =========================================================
   FORMATTING HELPERS
========================================================= */

const pdfMoney = (
    value
) =>
    formatMoney(
        value
    );


const pdfNumber = (
    value,
    decimals = 2
) =>
    formatNumber(
        value,
        decimals
    );


const pdfDate = (
    value
) =>
    formatDate(
        value
    );


const pdfDateTime = (
    value
) =>
    formatDateTime(
        value
    );


/* =========================================================
   EXPORTS
========================================================= */

module.exports = {

    createPdfDocument,

    drawTitle,
    drawSectionTitle,

    drawKeyValue,
    drawKeyValueGrid,

    drawSummaryGrid,

    calculateColumnWidths,
    getTableRowHeight,

    drawTableHeader,
    drawTableRow,
    drawTable,

    ensureSpace,

    addPageFooters,

    drawReportMetadata,

    pdfMoney,
    pdfNumber,
    pdfDate,
    pdfDateTime
};