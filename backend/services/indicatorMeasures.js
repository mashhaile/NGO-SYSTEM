// =====================================================
// AUTOMATIC INDICATOR MEASURES
// =====================================================
//
// What an "auto" indicator counts, for its program (and
// project, with its phases) and a period. The value is the
// same figure the report shows, so an indicator and its
// report never disagree:
//
//   report  the Report Center report that counts it
//   item    the summary figure of that report
//   module  the module it needs (off: no value)
//
// =====================================================

const MEASURES = [
    { key: "beneficiariesReached", name: "Beneficiaries reached by services", report: "serviceDelivery", item: "Beneficiaries reached", module: "serviceDelivery", unit: "number" },
    { key: "institutionsReached", name: "Institutions reached by services", report: "serviceDelivery", item: "Institutions reached", module: "serviceDelivery", unit: "number" },
    { key: "groupsReached", name: "Households and groups reached by services", report: "serviceDelivery", item: "Households and groups reached", module: "serviceDelivery", unit: "number" },
    { key: "deliveries", name: "Service deliveries made", report: "serviceDelivery", item: "Deliveries", module: "serviceDelivery", unit: "number" },
    { key: "peopleTrained", name: "People trained", report: "activities", item: "People trained", module: "activities", unit: "number" },
    { key: "womenTrained", name: "Women trained", report: "activities", item: "Women trained", module: "activities", unit: "number" },
    { key: "completedTraining", name: "People who completed every training session", report: "activities", item: "Completed every session", module: "activities", unit: "number" },
    { key: "trainingSessions", name: "Training sessions held", report: "activities", item: "Training sessions held", module: "activities", unit: "number" },
    { key: "attendanceRate", name: "Training attendance rate", report: "activities", item: "Attendance rate", module: "activities", unit: "percent" },
    { key: "activeEnrollments", name: "Beneficiaries actively enrolled", report: "beneficiaries", item: "Active enrollments", module: "enrollments", unit: "number" }
];

const measureOf = (key) => MEASURES.find(measure => measure.key === key) || null;


// "2026" / "2026-Q2" / "2026-05" -> the Report Center period
const periodQuery = (period) => {
    const text = String(period || "");
    let match = text.match(/^(\d{4})$/);
    if (match) return { period: "year", year: Number(match[1]) };
    match = text.match(/^(\d{4})-Q([1-4])$/);
    if (match) return { period: "quarter", year: Number(match[1]), quarter: Number(match[2]) };
    match = text.match(/^(\d{4})-(0[1-9]|1[0-2])$/);
    if (match) return { period: "month", year: Number(match[1]), month: Number(match[2]) };
    return null;
};


// a context to run reports for an organization (counts only)
const contextFor = async (organizationId) => ({
    organizationId,
    role: "system",
    permissions: ["*"],
    modules: await require("./moduleService").enabledFor(organizationId),
    user: null,
    organization: null
});


// The value of an auto indicator for one period, or null
// (unknown measure, its module off, or no such figure).
// cache: Map shared by one request, so each report runs once
const autoValue = async (indicator, period, cache = new Map()) => {

    const measure = measureOf(indicator.measure);
    const query = periodQuery(period);
    if (!measure || !query) return null;

    const organizationId = String(indicator.organization);
    const context = cache.get(`ctx:${organizationId}`) || await contextFor(organizationId);
    cache.set(`ctx:${organizationId}`, context);
    if (!context.modules.has(measure.module)) return null;

    const program = String(indicator.program?._id || indicator.program || "");
    const project = String(indicator.project?._id || indicator.project || "");
    const key = `${measure.report}|${program}|${project}|${period}`;

    if (!cache.has(key)) {
        cache.set(key, require("./reportCenter").runReport(
            measure.report,
            { ...query, ...(program ? { program } : {}), ...(project ? { project } : {}) },
            context
        ).catch(() => null));
    }

    const report = await cache.get(key);
    const item = report?.summary?.find(entry => entry.label === measure.item);
    const value = Number(item?.value);
    return Number.isFinite(value) ? value : null;

};


module.exports = {
    MEASURES,
    measureOf,
    periodQuery,
    autoValue
};
