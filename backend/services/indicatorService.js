// =====================================================
// M&E INDICATORS
// =====================================================
//
// Indicators of a program or project with their baseline,
// targets per period and actual values; progress per period
// (target, actual, % achieved, status).
//
// Status of a period that has started and has a target:
//   on track   >= 90% achieved
//   at risk    60% - 89%
//   off track  < 60%
// "Decrease" indicators (fewer is better) are measured from
// the baseline: going from 40% to a target of 20%, an
// actual of 30% is half way (50%).
//
// =====================================================

const mongoose = require("mongoose");

const Indicator = require("../models/Indicator");
const { LEVELS, UNITS, DIRECTIONS, FREQUENCIES, SOURCES } = require("../models/Indicator");
const IndicatorValue = require("../models/IndicatorValue");
const Program = require("../models/program");
const Project = require("../models/Project");
const ApiError = require("../utils/apiError");
const generateSequence = require("../utils/generateSequence");
const { MEASURES, measureOf, periodQuery, autoValue } = require("./indicatorMeasures");

const ON_TRACK = 90;
const AT_RISK = 60;

const round1 = (value) => Math.round(Number(value) * 10) / 10;
const idOf = (value) => String(value?._id || value || "");


// ---------------------------------------------------------------- periods

const PERIOD_FORMAT = {
    Annual: /^\d{4}$/,
    Quarterly: /^\d{4}-Q[1-4]$/,
    Monthly: /^\d{4}-(0[1-9]|1[0-2])$/
};

const PERIOD_EXAMPLE = { Annual: "2026", Quarterly: "2026-Q1", Monthly: "2026-01" };

// the first day of a period (to know whether it has started)
const periodStart = (period) => {
    const query = periodQuery(period);
    if (!query) return null;
    const month = query.period === "quarter" ? (query.quarter - 1) * 3 : query.period === "month" ? query.month - 1 : 0;
    return new Date(Date.UTC(query.year, month, 1));
};

const sortPeriods = (periods) =>
    [...new Set(periods)].sort((a, b) => (periodStart(a) || 0) - (periodStart(b) || 0) || a.localeCompare(b));

const yearOf = (period) => Number(String(period).slice(0, 4));


// ---------------------------------------------------------------- progress

const achievement = (indicator, target, actual) => {
    if (target === null || target === undefined || actual === null || actual === undefined) return null;
    if (indicator.direction === "decrease") {
        const baseline = indicator.baseline?.value;
        if (baseline !== null && baseline !== undefined && baseline > target) {
            return round1(Math.max(0, ((baseline - actual) / (baseline - target)) * 100));
        }
        return actual <= target ? 100 : round1((target / actual) * 100);
    }
    return target > 0 ? round1((actual / target) * 100) : (actual > 0 ? 100 : null);
};

const statusOf = (percent, started) =>
    !started ? "Not started"
        : percent === null ? "No data"
            : percent >= ON_TRACK ? "On track"
                : percent >= AT_RISK ? "At risk"
                    : "Off track";


// Progress of one indicator: a row per period (targets and
// entered values), and the latest period that has started
const progressOf = async (indicator, cache = new Map()) => {

    const values = indicator.source === "manual"
        ? await IndicatorValue.find({ indicator: indicator._id }).lean()
        : [];
    const valueByPeriod = new Map(values.map(item => [item.period, item]));
    const targetByPeriod = new Map((indicator.targets || []).map(item => [item.period, item.value]));
    const today = new Date();

    const rows = [];
    for (const period of sortPeriods([...targetByPeriod.keys(), ...valueByPeriod.keys()])) {
        const started = (periodStart(period) || today) <= today;
        const entered = valueByPeriod.get(period);
        const actual = indicator.source === "auto"
            ? (started ? await autoValue(indicator, period, cache) : null)
            : entered ? entered.value : null;
        const target = targetByPeriod.has(period) ? targetByPeriod.get(period) : null;
        const percent = achievement(indicator, target, actual);
        rows.push({
            period,
            target,
            actual,
            female: entered?.female ?? null,
            male: entered?.male ?? null,
            notes: entered?.notes || "",
            percent,
            status: statusOf(percent, started),
            started
        });
    }

    // the latest reported period (a target and a value); before
    // any value, the latest period that has started
    const withTarget = [...rows].reverse().filter(row => row.started && row.target !== null);
    const current = withTarget.find(row => row.actual !== null) || withTarget[0] || null;

    return { rows, current };

};


// The figures of a whole year (the indicators report): the
// year's target and actual. Number indicators add up their
// quarters / months; percentages take the year's last one.
const yearFigures = async (indicator, year, cache = new Map()) => {

    const inYear = (period) => yearOf(period) === Number(year);
    const sumOrLast = (pairs) => {
        if (!pairs.length) return null;
        return indicator.unit === "percent"
            ? pairs[pairs.length - 1][1]
            : pairs.reduce((sum, [, value]) => sum + Number(value || 0), 0);
    };

    const targets = sortPeriods((indicator.targets || []).filter(item => inYear(item.period)).map(item => item.period))
        .map(period => [period, indicator.targets.find(item => item.period === period).value]);
    const target = sumOrLast(targets);

    let actual = null;
    if (indicator.source === "auto") {
        const started = new Date(Date.UTC(Number(year), 0, 1)) <= new Date();
        actual = started ? await autoValue(indicator, String(year), cache) : null;
    }
    else {
        const values = await IndicatorValue.find({ indicator: indicator._id }).lean();
        const pairs = sortPeriods(values.filter(item => inYear(item.period)).map(item => item.period))
            .map(period => [period, values.find(item => item.period === period).value]);
        actual = sumOrLast(pairs);
    }

    const percent = achievement(indicator, target, actual);
    const started = new Date(Date.UTC(Number(year), 0, 1)) <= new Date();
    return { target, actual, percent, status: statusOf(percent, started) };

};


// ---------------------------------------------------------------- checks

const assertId = (id, what = "Indicator") => {
    if (!mongoose.isValidObjectId(id)) throw new ApiError(`${what} not found.`, 404);
};

const cleanData = async (data, organizationId, existing = null) => {

    const next = { ...(existing ? existing.toObject() : {}), ...data };

    if (!next.program) throw new ApiError("Please check: Program is required.", 400);
    assertId(next.program, "Program");
    const program = await Program.findOne({ _id: next.program, organization: organizationId, isDeleted: { $ne: true } }).select("_id").lean();
    if (!program) throw new ApiError("Program not found.", 404);

    if (next.project) {
        assertId(next.project, "Project");
        const project = await Project.findOne({ _id: next.project, organization: organizationId, isDeleted: { $ne: true } }).select("program").lean();
        if (!project) throw new ApiError("Project not found.", 404);
        if (idOf(project.program) !== idOf(next.program)) throw new ApiError("The project does not belong to this program.", 400);
    }

    if (!String(next.name || "").trim()) throw new ApiError("Please check: Indicator name is required.", 400);
    if (!LEVELS.includes(next.level)) throw new ApiError(`Please check: Level must be ${LEVELS.join(", ")}.`, 400);
    if (!FREQUENCIES.includes(next.frequency)) throw new ApiError(`Please check: Frequency must be ${FREQUENCIES.join(", ")}.`, 400);
    if (!SOURCES.includes(next.source)) throw new ApiError("Please check: Source must be automatic or entered.", 400);
    if (!DIRECTIONS.includes(next.direction || "increase")) throw new ApiError("Please check: Direction must be increase or decrease.", 400);

    let unit = next.unit || "number";
    if (next.source === "auto") {
        const measure = measureOf(next.measure);
        if (!measure) throw new ApiError("Please check: choose what the automatic indicator counts.", 400);
        unit = measure.unit;
    }
    else {
        next.measure = null;
    }
    if (!UNITS.includes(unit)) throw new ApiError("Please check: Unit must be number or percent.", 400);

    const targets = (Array.isArray(next.targets) ? next.targets : [])
        .filter(item => item && String(item.period || "").trim() && item.value !== "" && item.value !== null && item.value !== undefined)
        .map(item => ({ period: String(item.period).trim(), value: Number(item.value) }));
    const seen = new Set();
    for (const target of targets) {
        if (!PERIOD_FORMAT[next.frequency].test(target.period)) {
            throw new ApiError(`Please check: target period "${target.period}" does not match the frequency (${next.frequency}, e.g. ${PERIOD_EXAMPLE[next.frequency]}).`, 400);
        }
        if (seen.has(target.period)) throw new ApiError(`Please check: two targets for ${target.period}.`, 400);
        seen.add(target.period);
        if (!Number.isFinite(target.value) || target.value < 0) throw new ApiError(`Please check: the target for ${target.period} must be 0 or more.`, 400);
        if (unit === "percent" && target.value > 100) throw new ApiError(`Please check: the target for ${target.period} is a percentage (0 - 100).`, 400);
    }

    const baselineValue = next.baseline?.value;
    const baseline = {
        value: baselineValue === "" || baselineValue === null || baselineValue === undefined ? null : Number(baselineValue),
        date: next.baseline?.date || null
    };
    if (baseline.value !== null && (!Number.isFinite(baseline.value) || baseline.value < 0)) {
        throw new ApiError("Please check: the baseline must be 0 or more.", 400);
    }

    return {
        program: next.program,
        project: next.project || null,
        level: next.level,
        result: String(next.result || "").trim(),
        name: String(next.name).trim(),
        definition: String(next.definition || "").trim(),
        unit,
        direction: next.direction || "increase",
        baseline,
        frequency: next.frequency,
        targets: sortPeriods(targets.map(item => item.period)).map(period => targets.find(item => item.period === period)),
        source: next.source,
        measure: next.source === "auto" ? next.measure : null,
        dataSource: String(next.dataSource || "").trim(),
        responsible: next.responsible || null,
        status: next.status === "Inactive" ? "Inactive" : "Active"
    };

};


// ---------------------------------------------------------------- CRUD

const POPULATE = [
    { path: "program", select: "programCode name" },
    { path: "project", select: "projectCode name" },
    { path: "responsible", select: "name email" }
];

const findIndicator = async (id, organizationId) => {
    assertId(id);
    const indicator = await Indicator.findOne({ _id: id, organization: organizationId, isDeleted: false });
    if (!indicator) throw new ApiError("Indicator not found.", 404);
    return indicator;
};

const createIndicator = async (data, organizationId, userId) => {
    const clean = await cleanData(data, organizationId);
    const code = await generateSequence("Indicator", "IND", organizationId,
        async (candidate) => Boolean(await Indicator.exists({ organization: organizationId, code: candidate })));
    const indicator = await Indicator.create({ ...clean, code, organization: organizationId, createdBy: userId, updatedBy: userId });
    return getIndicator(indicator._id, organizationId);
};

const updateIndicator = async (id, data, organizationId, userId) => {
    const indicator = await findIndicator(id, organizationId);
    const clean = await cleanData(data, organizationId, indicator);
    if (indicator.source === "manual" && clean.source === "auto" && await IndicatorValue.exists({ indicator: indicator._id })) {
        throw new ApiError("This indicator has entered values. Delete them first, or keep it as entered.", 400);
    }
    if (clean.frequency !== indicator.frequency && await IndicatorValue.exists({ indicator: indicator._id })) {
        throw new ApiError("This indicator has entered values for its current frequency. Delete them before changing the frequency.", 400);
    }
    Object.assign(indicator, clean, { updatedBy: userId });
    await indicator.save();
    return getIndicator(indicator._id, organizationId);
};

const deleteIndicator = async (id, organizationId, userId) => {
    const indicator = await findIndicator(id, organizationId);
    indicator.isDeleted = true;
    indicator.deletedAt = new Date();
    indicator.updatedBy = userId;
    await indicator.save();
    return { _id: indicator._id };
};

const getIndicator = async (id, organizationId) => {
    assertId(id);
    const indicator = await Indicator.findOne({ _id: id, organization: organizationId, isDeleted: false }).populate(POPULATE).lean();
    if (!indicator) throw new ApiError("Indicator not found.", 404);
    const progress = await progressOf(indicator);
    return { ...indicator, measureName: measureOf(indicator.measure)?.name || null, progress };
};

const listIndicators = async (organizationId, query = {}) => {
    const filter = { organization: organizationId, isDeleted: false };
    if (mongoose.isValidObjectId(query.program)) filter.program = query.program;
    if (mongoose.isValidObjectId(query.project)) filter.project = query.project;
    if (LEVELS.includes(query.level)) filter.level = query.level;
    if (query.status === "Active" || query.status === "Inactive") filter.status = query.status;
    if (query.search) {
        const escape = require("../utils/escapeRegex");
        const pattern = new RegExp(escape(String(query.search).trim()), "i");
        filter.$or = [{ name: pattern }, { code: pattern }, { result: pattern }];
    }
    const indicators = await Indicator.find(filter).populate(POPULATE).sort({ code: 1 }).lean();
    const cache = new Map();
    return Promise.all(indicators.map(async (indicator) => ({
        ...indicator,
        measureName: measureOf(indicator.measure)?.name || null,
        current: (await progressOf(indicator, cache)).current
    })));
};


// ---------------------------------------------------------------- entered values

const setValue = async (id, period, data, organizationId, userId) => {
    const indicator = await findIndicator(id, organizationId);
    if (indicator.source !== "manual") throw new ApiError("This indicator is counted automatically; its values cannot be entered.", 400);
    if (!PERIOD_FORMAT[indicator.frequency].test(String(period))) {
        throw new ApiError(`Please check: the period must be like ${PERIOD_EXAMPLE[indicator.frequency]} (${indicator.frequency}).`, 400);
    }
    if ((periodStart(period) || new Date()) > new Date()) throw new ApiError(`${period} has not started yet.`, 400);
    const value = Number(data?.value);
    if (data?.value === "" || data?.value === null || data?.value === undefined || !Number.isFinite(value) || value < 0) {
        throw new ApiError("Please check: the value must be 0 or more.", 400);
    }
    if (indicator.unit === "percent" && value > 100) throw new ApiError("Please check: this indicator is a percentage (0 - 100).", 400);
    const part = (key) => (data?.[key] === "" || data?.[key] === null || data?.[key] === undefined ? null : Number(data[key]));
    const female = part("female");
    const male = part("male");
    if ([female, male].some(item => item !== null && (!Number.isFinite(item) || item < 0))) throw new ApiError("Please check: female and male must be 0 or more.", 400);
    if (indicator.unit === "number" && female !== null && male !== null && female + male > value) {
        throw new ApiError("Please check: female and male together are more than the value.", 400);
    }
    await IndicatorValue.findOneAndUpdate(
        { indicator: indicator._id, period: String(period) },
        { $set: { organization: organizationId, value, female, male, notes: String(data?.notes || "").trim(), enteredBy: userId } },
        { upsert: true, setDefaultsOnInsert: true }
    );
    return getIndicator(indicator._id, organizationId);
};

const deleteValue = async (id, period, organizationId) => {
    const indicator = await findIndicator(id, organizationId);
    await IndicatorValue.deleteOne({ indicator: indicator._id, period: String(period) });
    return getIndicator(indicator._id, organizationId);
};


module.exports = {
    MEASURES,
    LEVELS,
    FREQUENCIES,
    createIndicator,
    updateIndicator,
    deleteIndicator,
    getIndicator,
    listIndicators,
    setValue,
    deleteValue,
    progressOf,
    yearFigures
};
