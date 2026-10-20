const ExcelJS = require("exceljs");


// =====================================================
// EXCEL ROWS
// =====================================================
//
// Reads a workbook and returns each sheet as an array of
// objects keyed by the header row (first row), like
// xlsx's sheet_to_json. Empty cells are left out.
//
// =====================================================

const cellValue = (value) => {

    if (value === null || value === undefined) {
        return undefined;
    }

    if (value instanceof Date) {
        return value;
    }

    if (typeof value === "object") {

        // Formula result, rich text, hyperlink

        if ("result" in value) {
            return cellValue(value.result);
        }

        if (Array.isArray(value.richText)) {
            return value.richText.map(part => part.text).join("");
        }

        if ("text" in value) {
            return value.text;
        }

        return undefined;

    }

    return value;

};


const sheetToRows = (worksheet) => {

    const rows = [];

    let headers = [];

    worksheet.eachRow({ includeEmpty: false }, (row, rowNumber) => {

        if (rowNumber === 1) {

            headers =
                row.values.map(value => {
                    const header = cellValue(value);
                    return header === undefined ? undefined : String(header).trim();
                });

            return;

        }

        const record = {};

        row.values.forEach((value, column) => {

            const header = headers[column];
            const cell = cellValue(value);

            if (header && cell !== undefined && cell !== "") {
                record[header] = cell;
            }

        });

        if (Object.keys(record).length) {
            rows.push(record);
        }

    });

    return rows;

};


// Returns { [sheetName]: rows[] }

const readWorkbookRows = async (filePath) => {

    const workbook = new ExcelJS.Workbook();

    await workbook.xlsx.readFile(filePath);

    const sheets = {};

    workbook.eachSheet(worksheet => {
        sheets[worksheet.name] = sheetToRows(worksheet);
    });

    return sheets;

};


module.exports = {
    readWorkbookRows
};
