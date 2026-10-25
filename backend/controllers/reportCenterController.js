// =====================================================
// REPORT CENTER CONTROLLER
// =====================================================

const reportCenter = require("../services/reportCenter");
const terminology = require("../services/terminologyService");
const { exportReport } = require("../services/reportCenter/export");
const { buildReportContext } = require("../services/reports/reportContext");
const { getErrorStatus } = require("../utils/errorStatus");


const fail = (res, error) => {
    const status = error.statusCode || getErrorStatus(error);
    if (status >= 500) console.error("REPORT CENTER ERROR:", error);
    return res.status(status).json({ success: false, message: error.message, errors: [] });
};

// JSON, or the same report as a file
const send = async (res, raw, query, context) => {
    // in the organization's own words (titles, labels; not data)
    const report = terminology.applyToReport(raw, await terminology.replacerFor(context.organizationId));
    const format = String(query.format || "json").toLowerCase();

    if (format === "json") {
        return res.json({ success: true, data: report });
    }

    const file = await exportReport(report, format, context.organization?.name);

    res.setHeader("Content-Type", file.type);
    res.setHeader("Content-Disposition", `attachment; filename="${file.name}"`);
    return res.send(Buffer.from(file.buffer));

};


const getCatalog = async (req, res) => {
    try {
        const context = await buildReportContext(req);
        const replace = await terminology.replacerFor(context.organizationId);
        return res.json({ success: true, data: terminology.applyToCatalog(reportCenter.getCatalog(context), replace) });
    }
    catch (error) {
        return fail(res, error);
    }
};


const getReport = async (req, res) => {
    try {
        const context = await buildReportContext(req);
        const report = await reportCenter.runReport(req.params.key, req.query, context);
        return await send(res, report, req.query, context);
    }
    catch (error) {
        return fail(res, error);
    }
};


const getDetail = async (req, res) => {
    try {
        const context = await buildReportContext(req);
        const report = await reportCenter.runDetail(req.params.kind, req.params.id, req.query, context);
        return await send(res, report, req.query, context);
    }
    catch (error) {
        return fail(res, error);
    }
};


module.exports = {
    getCatalog,
    getReport,
    getDetail
};
