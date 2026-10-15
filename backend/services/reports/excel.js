const ExcelJS = require("exceljs");

const {
    normalizeText,
    toNumber
} = require("./helpers");


/* =========================================================
   WORKBOOK
========================================================= */

const createWorkbook = (
    options = {}
) => {
    const workbook =
        new ExcelJS.Workbook();

    workbook.creator =
        options.creator ||
        "NGO Management System";

    workbook.lastModifiedBy =
        options.lastModifiedBy ||
        workbook.creator;

    workbook.created =
        new Date();

    workbook.modified =
        new Date();

    workbook.properties = {
        title:
            options.title ||
            "NGO Management System Report",

        subject:
            options.subject ||
            "Organizational Report",

        company:
            options.company ||
            "NGO Management System"
    };

    return workbook;
};


/* =========================================================
   WORKSHEET
========================================================= */

const addWorksheet = (
    workbook,
    name,
    options = {}
) => {
    return workbook.addWorksheet(
        normalizeText(
            name,
            "Report"
        ),
        {
            views: [
                {
                    state:
                        options.freeze
                            ? "frozen"
                            : "normal",

                    ySplit:
                        options.freeze
                            ? (
                                options.freezeRows ||
                                1
                            )
                            : 0
                }
            ]
        }
    );
};


/* =========================================================
   TITLE
========================================================= */

const addTitle = (
    worksheet,
    title,
    options = {}
) => {
    const row =
        options.row || 1;

    const startColumn =
        options.startColumn || 1;

    const endColumn =
        options.endColumn ||
        Math.max(
            startColumn,
            worksheet.columnCount ||
                1
        );

    worksheet.mergeCells(
        row,
        startColumn,
        row,
        endColumn
    );

    const cell =
        worksheet.getCell(
            row,
            startColumn
        );

    cell.value =
        normalizeText(
            title,
            "Report"
        );

    cell.font = {
        bold: true,
        size:
            options.fontSize || 16
    };

    cell.alignment = {
        horizontal:
            "center",
        vertical:
            "middle"
    };

    worksheet.getRow(
        row
    ).height =
        options.height || 26;
};


/* =========================================================
   METADATA
========================================================= */

const addMetadata = (
    worksheet,
    rows,
    options = {}
) => {
    let rowNumber =
        options.startRow || 3;

    const labelColumn =
        options.labelColumn || 1;

    const valueColumn =
        options.valueColumn || 2;

    rows.forEach(
        row => {
            const labelCell =
                worksheet.getCell(
                    rowNumber,
                    labelColumn
                );

            const valueCell =
                worksheet.getCell(
                    rowNumber,
                    valueColumn
                );

            labelCell.value =
                normalizeText(
                    row.label,
                    ""
                );

            valueCell.value =
                row.value ?? "—";

            labelCell.font = {
                bold: true
            };

            rowNumber++;
        }
    );

    return rowNumber;
};


/* =========================================================
   SUMMARY
========================================================= */

const addSummary = (
    worksheet,
    rows,
    options = {}
) => {
    const startRow =
        options.startRow || 1;

    const labelColumn =
        options.labelColumn || 1;

    const valueColumn =
        options.valueColumn || 2;

    let currentRow =
        startRow;

    rows.forEach(
        row => {
            const label =
                worksheet.getCell(
                    currentRow,
                    labelColumn
                );

            const value =
                worksheet.getCell(
                    currentRow,
                    valueColumn
                );

            label.value =
                normalizeText(
                    row.label,
                    ""
                );

            value.value =
                row.value ?? "—";

            label.font = {
                bold: true
            };

            currentRow++;
        }
    );

    return {
        startRow,
        endRow:
            currentRow - 1
    };
};


/* =========================================================
   HEADER
========================================================= */

const styleHeader = (
    row,
    options = {}
) => {
    row.font = {
        bold: true,
        size:
            options.fontSize || 10
    };

    row.alignment = {
        vertical:
            "middle",
        horizontal:
            options.horizontal ||
            "center",
        wrapText: true
    };

    row.height =
        options.height || 24;

    row.eachCell(
        cell => {
            cell.border = {
                top: {
                    style: "thin"
                },
                bottom: {
                    style: "thin"
                },
                left: {
                    style: "thin"
                },
                right: {
                    style: "thin"
                }
            };
        }
    );
};


/* =========================================================
   DATA SHEET
========================================================= */

const addDataTable = (
    worksheet,
    columns,
    rows,
    options = {}
) => {
    const headerRow =
        options.headerRow || 1;

    const startColumn =
        options.startColumn || 1;

    /*
     * Write headers.
     */
    columns.forEach(
        (
            column,
            index
        ) => {
            const cell =
                worksheet.getCell(
                    headerRow,
                    startColumn +
                        index
                );

            cell.value =
                normalizeText(
                    column.header,
                    ""
                );
        }
    );

    styleHeader(
        worksheet.getRow(
            headerRow
        ),
        {
            fontSize:
                options.headerFontSize ||
                9,
            height:
                options.headerHeight ||
                28
        }
    );

    /*
     * Write data.
     */
    rows.forEach(
        (
            row,
            rowIndex
        ) => {
            const excelRow =
                headerRow +
                1 +
                rowIndex;

            columns.forEach(
                (
                    column,
                    columnIndex
                ) => {
                    const cell =
                        worksheet.getCell(
                            excelRow,
                            startColumn +
                                columnIndex
                        );

                    let value;

                    if (
                        typeof column.value ===
                        "function"
                    ) {
                        value =
                            column.value(
                                row
                            );
                    } else {
                        value =
                            row[
                                column.key
                            ];
                    }

                    cell.value =
                        value ?? "—";

                    cell.alignment = {
                        vertical:
                            "top",
                        horizontal:
                            column.align ||
                            "left",
                        wrapText: true
                    };
                }
            );
        }
    );

    /*
     * Column widths.
     */
    columns.forEach(
        (
            column,
            index
        ) => {
            const excelColumn =
                worksheet.getColumn(
                    startColumn +
                        index
                );

            excelColumn.width =
                column.width ||
                calculateColumnWidth(
                    worksheet,
                    startColumn +
                        index,
                    options
                );
        }
    );

    /*
     * Freeze header.
     */
    if (
        options.freezeHeader !== false
    ) {
        worksheet.views = [
            {
                state: "frozen",
                ySplit:
                    headerRow
            }
        ];
    }

    /*
     * Auto filter.
     */
    if (
        options.autoFilter !== false
    ) {
        const lastColumn =
            startColumn +
            columns.length -
            1;

        const lastRow =
            headerRow +
            rows.length;

        worksheet.autoFilter = {
            from: {
                row: headerRow,
                column: startColumn
            },

            to: {
                row: lastRow,
                column: lastColumn
            }
        };
    }

    return {
        headerRow,
        firstDataRow:
            headerRow + 1,

        lastDataRow:
            headerRow +
            rows.length,

        firstColumn:
            startColumn,

        lastColumn:
            startColumn +
            columns.length -
            1
    };
};


/* =========================================================
   COLUMN WIDTH
========================================================= */

const calculateColumnWidth = (
    worksheet,
    columnNumber,
    options = {}
) => {
    const min =
        options.minWidth || 10;

    const max =
        options.maxWidth || 40;

    let width = min;

    worksheet.eachRow(
        row => {
            const value =
                row.getCell(
                    columnNumber
                ).value;

            if (
                value === null ||
                value === undefined
            ) {
                return;
            }

            const text =
                typeof value ===
                "object"
                    ? JSON.stringify(
                        value
                    )
                    : String(value);

            width =
                Math.max(
                    width,
                    text.length + 2
                );
        }
    );

    return Math.min(
        max,
        Math.max(
            min,
            width
        )
    );
};


/* =========================================================
   NUMBER FORMATTING
========================================================= */

const formatNumberColumn = (
    worksheet,
    columnNumber,
    startRow,
    endRow,
    options = {}
) => {
    const decimals =
        options.decimals ?? 2;

    const format =
        decimals === 0
            ? "#,##0"
            : `#,##0.${"0".repeat(
                decimals
            )}`;

    for (
        let row = startRow;
        row <= endRow;
        row++
    ) {
        worksheet.getCell(
            row,
            columnNumber
        ).numFmt = format;
    }
};


const formatMoneyColumn = (
    worksheet,
    columnNumber,
    startRow,
    endRow,
    options = {}
) => {
    const currency =
        options.currency ||
        "ETB";

    for (
        let row = startRow;
        row <= endRow;
        row++
    ) {
        worksheet.getCell(
            row,
            columnNumber
        ).numFmt =
            `"${currency}" #,##0.00`;
    }
};


const formatPercentColumn = (
    worksheet,
    columnNumber,
    startRow,
    endRow,
    options = {}
) => {
    const decimals =
        options.decimals ?? 2;

    const format =
        `0.${"0".repeat(
            decimals
        )}%`;

    for (
        let row = startRow;
        row <= endRow;
        row++
    ) {
        worksheet.getCell(
            row,
            columnNumber
        ).numFmt = format;
    }
};


/* =========================================================
   GENERAL FORMATTING
========================================================= */

const applyMoneyColumns = (
    worksheet,
    ranges = []
) => {
    ranges.forEach(
        range => {
            formatMoneyColumn(
                worksheet,
                range.column,
                range.startRow,
                range.endRow,
                range
            );
        }
    );
};


const applyNumberColumns = (
    worksheet,
    ranges = []
) => {
    ranges.forEach(
        range => {
            formatNumberColumn(
                worksheet,
                range.column,
                range.startRow,
                range.endRow,
                range
            );
        }
    );
};


const applyPercentColumns = (
    worksheet,
    ranges = []
) => {
    ranges.forEach(
        range => {
            formatPercentColumn(
                worksheet,
                range.column,
                range.startRow,
                range.endRow,
                range
            );
        }
    );
};


/* =========================================================
   SUMMARY VALUE HELPERS
========================================================= */

const setMoneyCell = (
    cell,
    value,
    currency = "ETB"
) => {
    cell.value =
        toNumber(
            value,
            0
        );

    cell.numFmt =
        `"${currency}" #,##0.00`;
};


const setNumberCell = (
    cell,
    value,
    decimals = 0
) => {
    cell.value =
        toNumber(
            value,
            0
        );

    cell.numFmt =
        decimals === 0
            ? "#,##0"
            : `#,##0.${"0".repeat(
                decimals
            )}`;
};


const setPercentCell = (
    cell,
    value,
    decimals = 2
) => {
    cell.value =
        toNumber(
            value,
            0
        ) / 100;

    cell.numFmt =
        `0.${"0".repeat(
            decimals
        )}%`;
};


/* =========================================================
   WORKBOOK HELPERS
========================================================= */

const setWorkbookColumns = (
    worksheet,
    widths
) => {
    Object.entries(
        widths || {}
    ).forEach(
        (
            [column, width]
        ) => {
            worksheet.getColumn(
                column
            ).width = width;
        }
    );
};


const addBlankRow = (
    worksheet
) => {
    worksheet.addRow([]);
};


/* =========================================================
   EXPORT
========================================================= */

module.exports = {
    createWorkbook,
    addWorksheet,

    addTitle,
    addMetadata,
    addSummary,

    styleHeader,
    addDataTable,

    calculateColumnWidth,

    formatNumberColumn,
    formatMoneyColumn,
    formatPercentColumn,

    applyMoneyColumns,
    applyNumberColumns,
    applyPercentColumns,

    setMoneyCell,
    setNumberCell,
    setPercentCell,

    setWorkbookColumns,
    addBlankRow
};