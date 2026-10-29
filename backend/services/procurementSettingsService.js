const Organization = require("../models/organization");

const ApiError = require("../utils/apiError");


// =====================================================
// PROCUREMENT SETTINGS: METHODS BY AMOUNT
// =====================================================
//
// Which procurement method a purchase decides, from the
// request's value in ETB:
//
//   value <= direct.upTo   Direct purchase         1 quote
//   value <= rfq.upTo      Request for quotation   3 quotes
//   above                  Tender                  3 quotes + committee
//
// Each organization admin sets its own limits, number of
// quotes and whether a committee approves (Settings >
// Procurement); "reset" goes back to the defaults.
//
// Emergency procurement: for projects of the chosen types
// (Lookups > Projects > Project Type; empty: the type named
// "Emergency"), whatever the amount: fewer quotations, no
// committee, a reason, and (afterPurchase) the order may be
// issued before the choice is approved; the approval follows.
// Every such purchase is an exception in the procurement
// report. Changes
// apply to bid analyses started afterwards; one in progress
// keeps the method it started with.
//
// =====================================================

const CURRENCY = "ETB";

const METHOD_NAMES = {
    direct: "Direct purchase",
    rfq: "Request for quotation",
    tender: "Tender",
    emergency: "Emergency procurement"
};

const DEFAULTS = {
    direct: { upTo: 50000, minQuotes: 1, committee: false },
    rfq: { upTo: 300000, minQuotes: 3, committee: false },
    tender: { upTo: null, minQuotes: 3, committee: true }
};

const EMERGENCY_DEFAULTS = { enabled: true, minQuotes: 1, afterPurchase: true, projectTypes: [] };

const KEYS = ["direct", "rfq", "tender"];

const CACHE_MS = 15 * 1000;
const cache = new Map();


const clean = (stored = {}) =>
    Object.fromEntries(KEYS.map(key => {
        const value = { ...DEFAULTS[key], ...(stored?.[key] || {}) };
        return [key, {
            key,
            name: METHOD_NAMES[key],
            upTo: key === "tender" ? null : Number(value.upTo),
            minQuotes: Number(value.minQuotes),
            committee: Boolean(value.committee)
        }];
    }));


const cleanEmergency = (stored = {}) => {
    const value = { ...EMERGENCY_DEFAULTS, ...(stored || {}) };
    return {
        key: "emergency",
        name: METHOD_NAMES.emergency,
        enabled: value.enabled !== false,
        minQuotes: Number(value.minQuotes),
        afterPurchase: Boolean(value.afterPurchase),
        projectTypes: (Array.isArray(value.projectTypes) ? value.projectTypes : []).map(String)
    };
};


// { currency, methods: { direct, rfq, tender }, emergency, defaults }
const getSettings = async (organizationId) => {

    const key = String(organizationId);
    const hit = cache.get(key);
    if (hit && hit.at > Date.now() - CACHE_MS) return hit.value;

    const organization = await Organization.findById(organizationId).select("procurementSettings").lean();

    const value = {
        currency: CURRENCY,
        methods: clean(organization?.procurementSettings?.methods),
        emergency: cleanEmergency(organization?.procurementSettings?.emergency),
        defaults: clean({}),
        emergencyDefaults: cleanEmergency({})
    };

    cache.set(key, { at: Date.now(), value });

    return value;

};


const check = (methods) => {

    const { direct, rfq, tender } = methods;

    for (const method of [direct, rfq]) {
        if (!(method.upTo > 0)) throw new ApiError(`${method.name}: enter the amount it goes up to (more than 0).`, 400);
    }

    if (rfq.upTo <= direct.upTo) {
        throw new ApiError(`${rfq.name} must go up to more than ${direct.name} (${direct.upTo.toLocaleString("en-US")} ${CURRENCY}).`, 400);
    }

    for (const method of [direct, rfq, tender]) {
        if (!Number.isInteger(method.minQuotes) || method.minQuotes < 1 || method.minQuotes > 10) {
            throw new ApiError(`${method.name}: the number of quotations must be a whole number from 1 to 10.`, 400);
        }
    }

};


// data: { methods: { direct: { upTo, minQuotes, committee }, ... }, emergency: { enabled, minQuotes, afterPurchase, projectTypes } } or { reset: true }
const updateSettings = async (organizationId, data, userId) => {

    const before = await getSettings(organizationId);

    const methods =
        data.reset
            ? clean({})
            : clean(Object.fromEntries(KEYS.map(key => [key, { ...before.methods[key], ...(data.methods?.[key] || {}) }])));

    check(methods);

    const emergency =
        data.reset ? cleanEmergency({}) : cleanEmergency({ ...before.emergency, ...(data.emergency || {}) });

    if (!Number.isInteger(emergency.minQuotes) || emergency.minQuotes < 1 || emergency.minQuotes > 10) {
        throw new ApiError("Emergency procurement: the number of quotations must be a whole number from 1 to 10.", 400);
    }

    if (emergency.projectTypes.length) {
        const found = await require("../models/Lookup").countDocuments({ _id: { $in: emergency.projectTypes }, organization: organizationId, module: "Project", category: "ProjectType" });
        if (found !== emergency.projectTypes.length) throw new ApiError("Emergency procurement: choose the project types from the list.", 400);
    }

    const stored =
        Object.fromEntries(KEYS.map(key => [key, { upTo: methods[key].upTo, minQuotes: methods[key].minQuotes, committee: methods[key].committee }]));

    const organization =
        await Organization.findByIdAndUpdate(
            organizationId,
            { $set: { procurementSettings: data.reset ? {} : { methods: stored, emergency: { enabled: emergency.enabled, minQuotes: emergency.minQuotes, afterPurchase: emergency.afterPurchase, projectTypes: emergency.projectTypes } } } },
            { returnDocument: "after" }
        ).select("_id");

    cache.delete(String(organizationId));

    const describe = (set) =>
        KEYS.map(key => `${set[key].name}: ${key === "tender" ? "above" : `up to ${set[key].upTo.toLocaleString("en-US")}`}, ${set[key].minQuotes} quote(s)${set[key].committee ? ", committee" : ""}`).join("; ");

    await require("./auditLogService").createAuditLog({
        organizationId,
        userId,
        action: "PROCUREMENT_SETTINGS_CHANGED",
        module: "Procurement",
        entityType: "Organization",
        entityId: organization?._id || organizationId,
        description: `${describe(methods)}; emergency: ${emergency.enabled ? `${emergency.minQuotes} quote(s)${emergency.afterPurchase ? ", approval after purchase" : ""}` : "off"}${data.reset ? " (back to the defaults)" : ""}.`,
        metadata: { before: { methods: before.methods, emergency: before.emergency }, after: { methods, emergency } },
        success: true,
        severity: "info"
    });

    return getSettings(organizationId);

};


// The method for a value in ETB; `atLeast` (a method key)
// lets the officer choose a stricter method than the amount needs
const methodFor = (settings, etbValue, atLeast = null) => {

    const { direct, rfq, tender } = settings.methods;

    const byAmount =
        etbValue <= direct.upTo + 0.005 ? direct
            : etbValue <= rfq.upTo + 0.005 ? rfq
                : tender;

    if (atLeast && KEYS.indexOf(atLeast) > KEYS.indexOf(byAmount.key)) {
        return settings.methods[atLeast];
    }

    return byAmount;

};


// The emergency rule when the project is of an emergency type,
// otherwise null. No types chosen: the type named "Emergency".
const emergencyFor = async (settings, organizationId, projectId) => {

    if (!settings.emergency?.enabled || !projectId) return null;

    const project = await require("../models/Project").findById(projectId).select("projectType").lean();
    if (!project?.projectType) return null;

    let types = settings.emergency.projectTypes;
    if (!types.length) {
        const named = await require("../models/Lookup").find({ organization: organizationId, module: "Project", category: "ProjectType", value: /^emergency$/i }).select("_id").lean();
        types = named.map(type => String(type._id));
    }

    return types.includes(String(project.projectType)) ? settings.emergency : null;

};


module.exports = {
    emergencyFor,
    CURRENCY,
    KEYS,
    METHOD_NAMES,
    getSettings,
    updateSettings,
    methodFor
};
