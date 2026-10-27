// =====================================================
// M&E: INDICATORS (module "me")
// =====================================================
//
// Each indicator of the programs / projects for a year:
// result, baseline, the year's target and actual, % achieved
// and status. Numbers add up the year's quarters / months;
// percentages take the year's last one (see
// indicatorService.yearFigures). The year comes from the
// chosen period.
//
// =====================================================

const Indicator = require("../../../models/Indicator");

const {
    objectId, toId, summaryItem, column, section, buildReport
} = require("../core");

const STATUS_ORDER = ["On track", "At risk", "Off track", "No data", "Not started"];


const generate = async (query, context, period) => {

    const year = period.year || (period.start ? new Date(period.start.getTime() + 3 * 3600 * 1000).getUTCFullYear() : new Date().getFullYear());

    const filter = { organization: context.organizationId, isDeleted: false, status: "Active" };
    if (objectId(query.program)) filter.program = objectId(query.program);
    if (Array.isArray(query.projectIds) && query.projectIds.length) filter.project = { $in: query.projectIds };
    else if (objectId(query.project)) filter.project = objectId(query.project);

    const indicators = await Indicator.find(filter)
        .populate("program", "programCode name")
        .populate("project", "projectCode name")
        .sort({ code: 1 })
        .lean();

    const { yearFigures, limitsOf } = require("../../indicatorService");
    const cache = new Map();
    const limits = await limitsOf(context.organizationId);

    const rows = [];
    for (const indicator of indicators) {
        const figures = await yearFigures(indicator, year, cache);
        rows.push({
            id: toId(indicator._id),
            code: indicator.code,
            name: indicator.name,
            level: indicator.level,
            result: indicator.result || "-",
            program: indicator.program?.name || "",
            project: indicator.project?.name || "(whole program)",
            unit: indicator.unit === "percent" ? "%" : "number",
            source: indicator.source === "auto" ? "Automatic" : "Entered",
            baseline: indicator.baseline?.value ?? null,
            target: figures.target,
            actual: figures.actual,
            percent: figures.percent,
            status: figures.status
        });
    }

    const count = (status) => rows.filter(row => row.status === status).length;
    const byStatus = STATUS_ORDER
        .map(status => ({ label: status, indicators: count(status) }))
        .filter(row => row.indicators > 0);

    return buildReport({
        key: "indicators",
        title: "M&E: Indicators",
        description: `Each indicator's target and actual for FY ${year}: numbers add up the year's periods, percentages take the latest. On track: ${limits.onTrack}% or more of the target; at risk: ${limits.atRisk}-${limits.onTrack - 1}%; off track: below ${limits.atRisk}%.`,
        period,
        summary: [
            summaryItem("Indicators", rows.length),
            summaryItem("On track", count("On track")),
            summaryItem("At risk", count("At risk")),
            summaryItem("Off track", count("Off track")),
            summaryItem("No data yet", count("No data"))
        ],
        sections: [
            section("status", "Indicators by status", [
                column("label", "Status"),
                column("indicators", "Indicators", "number")
            ], byStatus, { chart: { type: "bar", x: "label", series: ["indicators"], yLabel: "Indicators" } }),
            section("indicators", `Indicators, FY ${year}`, [
                column("code", "Code"),
                column("name", "Indicator"),
                column("level", "Level"),
                column("result", "Result"),
                column("project", "Project"),
                column("unit", "Unit"),
                column("source", "Source"),
                column("baseline", "Baseline", "number"),
                column("target", "Target", "number"),
                column("actual", "Actual", "number"),
                column("percent", "Achieved", "percent"),
                column("status", "Status")
            ], rows)
        ]
    });

};


module.exports = {
    key: "indicators",
    title: "M&E: Indicators",
    description: "Logframe indicators: targets against actual values, % achieved and status, per program and project.",
    filters: ["program", "project"],
    permission: "indicator.read",
    generate
};
