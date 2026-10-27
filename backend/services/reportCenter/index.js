// =====================================================
// REPORT CENTER
// =====================================================
//
// Eight subject reports (one per area of work) and the
// detail reports their rows open. Each figure is counted
// in one place, so reports never disagree.
//
//   GET /report-center                 the catalog
//   GET /report-center/:key            a subject report
//   GET /report-center/detail/:kind/:id  one record
//   ?format=excel|pdf|csv              the same, as a file
//
// =====================================================

const { resolvePeriod } = require("./period");
const { assertPermission, hasPermission } = require("./core");
const ApiError = require("../../utils/apiError");


// order = the order on the screen
const REPORTS = [
    require("./reports/overview"),
    require("./reports/beneficiaries"),
    require("./reports/programs"),
    require("./reports/activities"),
    require("./reports/serviceDelivery"),
    require("./reports/enterprises"),
    require("./reports/donors"),
    require("./reports/budgets"),
    require("./reports/indicators"),
    require("./reports/procurement")
];

const DETAILS = [
    require("./details/beneficiary"),
    ...require("./details/programProject"),
    require("./details/activityRun"),
    require("./details/enterprise"),
    require("./details/donor")
];


// a report of a module that is off is left out (see
// config/modules.js); money reports need the finance permission
const REPORT_MODULE = {
    activities: "activities",
    serviceDelivery: "serviceDelivery",
    enterprises: "enterprises",
    donors: "funding",
    budgets: "finance",
    indicators: "me",
    procurement: "procurement"
};

const moduleOn = (context, key) =>
    !key || !context?.modules || context.modules.has(key);

const canSee = (report, context) =>
    moduleOn(context, REPORT_MODULE[report.key]) &&
    (!report.permission || hasPermission(context, report.permission));

const getCatalog = (context) =>
    REPORTS
        .filter(report => canSee(report, context))
        .map(report => ({
            key: report.key,
            title: report.title,
            description: report.description,
            filters: report.filters || [],
            detail: report.detail || null
        }));


const runReport = async (key, query, context) => {

    const report = REPORTS.find(item => item.key === key);

    if (!report) throw new ApiError(`Unknown report: ${key}`, 404);

    if (!moduleOn(context, REPORT_MODULE[report.key])) {
        throw new ApiError("This report's module is not enabled for your organization.", 403);
    }

    if (report.permission) assertPermission(context, report.permission, "this report");

    // a main project: its phases too
    if (query.project) {
        const organizationId = context.organizationId;
        query = { ...query, projectIds: await require("../projectPhases").projectAndPhases(query.project, organizationId) };
    }

    return report.generate(query, context, resolvePeriod(query));

};


const runDetail = async (kind, id, query, context) => {

    const detail = DETAILS.find(item => item.kind === kind);

    if (!detail) throw new ApiError(`Unknown detail report: ${kind}`, 404);

    if (detail.permission) assertPermission(context, detail.permission, "this report");

    // a profile shows everything unless a period is chosen
    return detail.generate(id, query, context, resolvePeriod({ period: "all", ...query }));

};


module.exports = {
    getCatalog,
    runReport,
    runDetail,
    REPORTS,
    DETAILS
};
