// =====================================================
// REPORT CENTER: EXCEL, PDF, CSV
// =====================================================
//
// One exporter for every report and detail report, built
// from the shared shape (summary, sections, details).
//
//   Excel  sheet "Report": title, period, filters, summary
//          and every section; sheet "Details": the detail
//          table (numbers stay numbers)
//   PDF    the same on A4 landscape, with page numbers
//   CSV    the detail table (a profile: its sections)
//
// =====================================================

const ExcelJS = require("exceljs");
const PDFDocument = require("pdfkit");


// ---------- values as text ----------

const isDateValue = (value) =>
    value instanceof Date || (typeof value === "string" && /^\d{4}-\d{2}-\d{2}T/.test(value));

// DD/MM/YYYY, the calendar day in Addis Ababa
const dateText = (value) =>
    !value ? "" : require("../../utils/dateFormat").formatDate(value, String(value));

const numberText = (value, digits = 0) =>
    value === null || value === undefined || value === ""
        ? ""
        : Number(value).toLocaleString("en-US", { minimumFractionDigits: digits, maximumFractionDigits: digits === 0 ? 2 : digits });

const valueText = (value, format, currency) => {
    if (value === null || value === undefined || value === "") return "";
    if (format === "money") return `${currency ? currency + " " : ""}${numberText(value, 2)}`;
    if (format === "number") return numberText(value);
    if (format === "percent") return `${numberText(value)}%`;
    if (format === "date" || isDateValue(value)) return dateText(value);
    if (Array.isArray(value)) return value.join(", ");
    return String(value);
};

const fileName = (report, extension) =>
    `${String(report.title || report.key || "report").replace(/[^\w\- ]+/g, "").trim().replace(/\s+/g, "-")}-${String(report.period?.label || "").replace(/[^\w]+/g, "-").replace(/^-|-$/g, "")}.${extension}`.replace(/-\./, ".");

const headerLines = (report, organizationName) => [
    organizationName || "",
    report.title,
    report.period?.label ? `Period: ${report.period.label}` : "",
    ...(report.filters || []).map(filter => `${filter.label}: ${filter.value}`),
    `Generated: ${dateText(report.generatedAt || new Date())}`
].filter(Boolean);

// a profile's record fields as a section
const recordSection = (report) =>
    report.record?.fields?.length
        ? {
            title: "Details",
            columns: [{ key: "label", label: "Field" }, { key: "value", label: "Value" }],
            rows: report.record.fields.map(field => ({ label: field.label, value: valueText(field.value, field.format) }))
        }
        : null;

const summarySection = (report) =>
    report.summary?.length
        ? {
            title: "Summary",
            columns: [{ key: "label", label: "Measure" }, { key: "value", label: "Value" }, { key: "note", label: "" }],
            rows: report.summary.map(item => ({ label: item.label, value: valueText(item.value, item.format, item.currency), note: item.note || "" }))
        }
        : null;

const allSections = (report) =>
    [recordSection(report), summarySection(report), ...(report.sections || [])].filter(Boolean);


// =====================================================
// EXCEL
// =====================================================

const toExcel = async (report, organizationName) => {

    const workbook = new ExcelJS.Workbook();
    workbook.creator = organizationName || "NGO Management System";
    workbook.created = new Date();

    const sheet = workbook.addWorksheet("Report");

    const lines = headerLines(report, organizationName);
    lines.forEach((line, index) => {
        const row = sheet.addRow([line]);
        row.font = index === 1 ? { bold: true, size: 14 } : index === 0 ? { bold: true, size: 11 } : { size: 10, color: { argb: "FF555555" } };
    });

    const addTable = (target, block) => {
        target.addRow([]);
        const title = target.addRow([block.title]);
        title.font = { bold: true, size: 12 };
        const head = target.addRow(block.columns.map(col => col.label));
        head.font = { bold: true };
        head.eachCell(cell => {
            cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFE8F1EC" } };
            cell.border = { bottom: { style: "thin", color: { argb: "FF9DB8A8" } } };
        });
        for (const data of block.rows) {
            const row = target.addRow(block.columns.map(col => {
                const value = data[col.key];
                if ((col.format === "money" || col.format === "number" || col.format === "percent") && value !== "" && value !== null && value !== undefined && Number.isFinite(Number(value))) return Number(value);
                if (col.format === "date" || isDateValue(value)) return dateText(value);
                return Array.isArray(value) ? value.join(", ") : value ?? "";
            }));
            block.columns.forEach((col, index) => {
                const cell = row.getCell(index + 1);
                if (col.format === "money") cell.numFmt = "#,##0.00";
                else if (col.format === "number") cell.numFmt = "#,##0.##";
                else if (col.format === "percent") cell.numFmt = "0.0\"%\"";
            });
        }
        if (block.total) {
            const row = target.addRow(block.columns.map((col, index) => (index === 0 ? "Total" : block.total[col.key] ?? "")));
            row.font = { bold: true };
        }
    };

    for (const block of allSections(report)) addTable(sheet, block);

    if (report.details?.rows?.length) {
        const details = workbook.addWorksheet("Details");
        details.addRow([`${report.title}: ${report.details.title}`]).font = { bold: true, size: 12 };
        if (report.period?.label) details.addRow([`Period: ${report.period.label}`]);
        addTable(details, { title: report.details.title, columns: report.details.columns, rows: report.details.rows });
        details.views = [{ state: "frozen", ySplit: 4 }];
    }

    for (const target of workbook.worksheets) {
        target.columns.forEach((col, index) => {
            let width = 10;
            col.eachCell({ includeEmpty: false }, cell => {
                if (cell.row <= 2 && index === 0) return;
                width = Math.max(width, Math.min(String(cell.text || "").length + 2, 60));
            });
            col.width = width;
        });
    }

    return { buffer: await workbook.xlsx.writeBuffer(), name: fileName(report, "xlsx"), type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" };

};


// =====================================================
// PDF
// =====================================================

const toPdf = (report, organizationName) => new Promise((resolve, reject) => {

    const doc = new PDFDocument({ size: "A4", layout: "landscape", margins: { top: 40, bottom: 45, left: 36, right: 36 }, bufferPages: true });
    const chunks = [];
    doc.on("data", chunk => chunks.push(chunk));
    doc.on("error", reject);
    doc.on("end", () => resolve({ buffer: Buffer.concat(chunks), name: fileName(report, "pdf"), type: "application/pdf" }));

    const left = doc.page.margins.left;
    const width = doc.page.width - doc.page.margins.left - doc.page.margins.right;
    const bottom = () => doc.page.height - doc.page.margins.bottom;
    const green = "#1E5B3A";

    // ---------- heading ----------
    doc.fillColor("#555555").fontSize(9).text(organizationName || "", left, doc.y);
    doc.fillColor(green).fontSize(18).font("Helvetica-Bold").text(report.title, left, doc.y + 2);
    doc.font("Helvetica").fillColor("#555555").fontSize(9.5)
        .text([report.period?.label ? `Period: ${report.period.label}` : "", ...(report.filters || []).map(filter => `${filter.label}: ${filter.value}`)].filter(Boolean).join("   ·   "));
    if (report.description) doc.moveDown(0.3).fillColor("#333333").fontSize(9.5).text(report.description, { width });
    doc.moveDown(0.8);

    // ---------- a table ----------
    const table = (block) => {

        const cols = block.columns;
        const numeric = (col) => ["money", "number", "percent"].includes(col.format);
        const weights = cols.map(col => (numeric(col) ? 1 : col.key === "label" || /name|program|services|location|activity|description|enterprise/i.test(col.key) ? 2.2 : 1.3));
        const total = weights.reduce((a, b) => a + b, 0);
        const widths = weights.map(weight => (weight / total) * width);
        const pad = 4;
        const fontSize = cols.length > 8 ? 7.5 : 8.5;

        const cellText = (row, col) => valueText(row[col.key], col.format, col.format === "money" ? "" : col.currency);

        const rowHeight = (texts, bold) => {
            doc.font(bold ? "Helvetica-Bold" : "Helvetica").fontSize(fontSize);
            return Math.max(...texts.map((text, i) => doc.heightOfString(String(text), { width: widths[i] - pad * 2 }))) + pad * 2;
        };

        const drawRow = (texts, { bold = false, fill = null } = {}) => {
            const height = rowHeight(texts, bold);
            if (doc.y + height > bottom()) { doc.addPage(); drawHeader(); }
            const top = doc.y;
            if (fill) doc.rect(left, top, width, height).fill(fill);
            let x = left;
            doc.font(bold ? "Helvetica-Bold" : "Helvetica").fontSize(fontSize).fillColor("#222222");
            texts.forEach((text, i) => {
                doc.text(String(text), x + pad, top + pad, { width: widths[i] - pad * 2, align: numeric(cols[i]) ? "right" : "left" });
                x += widths[i];
            });
            doc.moveTo(left, top + height).lineTo(left + width, top + height).strokeColor("#DDDDDD").lineWidth(0.5).stroke();
            doc.y = top + height;
        };

        const drawHeader = () => drawRow(cols.map(col => col.label + (col.format === "money" && col.currency ? ` (${col.currency})` : "")), { bold: true, fill: "#E8F1EC" });

        if (doc.y + 60 > bottom()) doc.addPage();
        doc.font("Helvetica-Bold").fontSize(11.5).fillColor(green).text(block.title, left, doc.y);
        if (block.note) doc.font("Helvetica").fontSize(8.5).fillColor("#555555").text(block.note, { width });
        doc.moveDown(0.3);

        if (!block.rows.length) {
            doc.font("Helvetica").fontSize(9).fillColor("#777777").text("Nothing in this period.");
            doc.moveDown(0.8);
            return;
        }

        drawHeader();
        block.rows.forEach((row, index) => drawRow(cols.map(col => cellText(row, col)), { fill: index % 2 ? "#FAFAFA" : null }));
        if (block.total) drawRow(cols.map((col, i) => (i === 0 ? "Total" : cellText(block.total, col))), { bold: true });
        doc.moveDown(0.8);
    };

    for (const block of allSections(report)) table(block);
    if (report.details?.rows?.length) table({ title: report.details.title, columns: report.details.columns, rows: report.details.rows });

    // ---------- footer ----------
    const range = doc.bufferedPageRange();
    for (let i = range.start; i < range.start + range.count; i++) {
        doc.switchToPage(i);
        // below the bottom margin pdfkit would start a new page
        const margin = doc.page.margins.bottom;
        doc.page.margins.bottom = 0;
        const footerY = doc.page.height - margin + 15;
        doc.font("Helvetica").fontSize(8).fillColor("#888888")
            .text(`${report.title} · ${report.period?.label || ""} · Generated ${dateText(report.generatedAt || new Date())}`, left, footerY, { width: width / 2, lineBreak: false })
            .text(`Page ${i - range.start + 1} of ${range.count}`, left + width / 2, footerY, { width: width / 2, align: "right", lineBreak: false });
        doc.page.margins.bottom = margin;
    }

    doc.end();

});


// =====================================================
// CSV
// =====================================================

const csvCell = (value) => {
    const text = value === null || value === undefined ? "" : String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
};

const toCsv = (report) => {

    const blocks =
        report.details?.rows?.length
            ? [{ title: report.details.title, columns: report.details.columns, rows: report.details.rows }]
            : allSections(report);

    const lines = [];
    for (const block of blocks) {
        if (blocks.length > 1) lines.push(csvCell(block.title));
        lines.push(block.columns.map(col => csvCell(col.label)).join(","));
        for (const row of block.rows) {
            lines.push(block.columns.map(col => {
                const value = row[col.key];
                if (col.format === "date" || isDateValue(value)) return csvCell(dateText(value));
                if (Array.isArray(value)) return csvCell(value.join("; "));
                return csvCell(value);
            }).join(","));
        }
        if (blocks.length > 1) lines.push("");
    }

    // BOM so Excel opens Amharic and other text correctly
    return { buffer: Buffer.from("﻿" + lines.join("\r\n"), "utf8"), name: fileName(report, "csv"), type: "text/csv; charset=utf-8" };

};


const exportReport = (report, format, organizationName) => {
    if (format === "excel" || format === "xlsx") return toExcel(report, organizationName);
    if (format === "pdf") return toPdf(report, organizationName);
    if (format === "csv") return toCsv(report);
    throw new Error(`Unknown export format: ${format}`);
};


module.exports = {
    exportReport,
    valueText
};
