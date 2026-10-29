const mongoose = require("mongoose");

const Organization = require("../models/organization");

const ApiError = require("../utils/apiError");


// =====================================================
// HUMANITARIAN RESPONSE (module "humanitarian")
// =====================================================
//
// Duplicate check on distributions: the same person should
// not receive the same service (service type) twice in one
// period. The organization chooses the period:
//
//   day      the same calendar day
//   week     the same calendar week (Monday - Sunday)
//   month    the same calendar month            (default)
//   days     within N days of each other
//   project  once per project
//
// sameProject: only deliveries of the same project count
// (otherwise any project of the organization). A delivery
// that repeats is refused with the list of earlier ones;
// it can still be saved with confirmDuplicates and a reason
// (kept on the delivery, shown in the 3W report).
//
// Cancelled deliveries and people marked Missed do not
// count. Only while the module is on.
//
// =====================================================

const PERIODS = ["day", "week", "month", "days", "project"];

const DEFAULTS = { enabled: true, period: "month", days: 30, sameProject: false };

const OFFSET_MS = 3 * 3600 * 1000;

const CACHE_MS = 15 * 1000;
const cache = new Map();


const clean = (stored = {}) => {
    const value = { ...DEFAULTS, ...(stored || {}) };
    return {
        enabled: value.enabled !== false,
        period: PERIODS.includes(value.period) ? value.period : DEFAULTS.period,
        days: Number(value.days),
        sameProject: Boolean(value.sameProject)
    };
};

const moduleOn = async (organizationId) =>
    (await require("./moduleService").enabledFor(organizationId)).has("humanitarian");


// { duplicateCheck, defaults }
const getSettings = async (organizationId) => {

    const key = String(organizationId);
    const hit = cache.get(key);
    if (hit && hit.at > Date.now() - CACHE_MS) return hit.value;

    const organization = await Organization.findById(organizationId).select("humanitarianSettings").lean();

    const value = {
        duplicateCheck: clean(organization?.humanitarianSettings?.duplicateCheck),
        defaults: clean({})
    };

    cache.set(key, { at: Date.now(), value });

    return value;

};


// data: { duplicateCheck: { enabled, period, days, sameProject } } or { reset: true }
const updateSettings = async (organizationId, data, userId) => {

    const before = await getSettings(organizationId);

    const duplicateCheck = data.reset ? clean({}) : clean({ ...before.duplicateCheck, ...(data.duplicateCheck || {}) });

    if (data.duplicateCheck?.period !== undefined && !PERIODS.includes(data.duplicateCheck.period)) {
        throw new ApiError(`The period must be one of: ${PERIODS.join(", ")}.`, 400);
    }

    if (!Number.isInteger(duplicateCheck.days) || duplicateCheck.days < 1 || duplicateCheck.days > 365) {
        throw new ApiError("The number of days must be a whole number from 1 to 365.", 400);
    }

    await Organization.updateOne(
        { _id: organizationId },
        { $set: { humanitarianSettings: data.reset ? {} : { duplicateCheck } } }
    );

    cache.delete(String(organizationId));

    await require("./auditLogService").createAuditLog({
        organizationId,
        userId,
        action: "HUMANITARIAN_SETTINGS_CHANGED",
        module: "Humanitarian",
        entityType: "Organization",
        entityId: organizationId,
        description: `Duplicate check: ${duplicateCheck.enabled ? `${duplicateCheck.period === "days" ? `within ${duplicateCheck.days} days` : `per ${duplicateCheck.period}`}${duplicateCheck.sameProject ? ", same project only" : ""}` : "off"}${data.reset ? " (back to the defaults)" : ""}.`,
        metadata: { before: before.duplicateCheck, after: duplicateCheck },
        success: true,
        severity: "info"
    });

    return getSettings(organizationId);

};


// ---------------------------------------------------------------- the window

const local = (date) => new Date(new Date(date).getTime() + OFFSET_MS);

// midnight (Addis Ababa) of a local y/m/d
const at = (year, month, day) => new Date(Date.UTC(year, month, day) - OFFSET_MS);

// { $gte, $lt } around the delivery date, or null (project: no date limit)
const windowOf = (rule, deliveryDate) => {

    const date = local(deliveryDate || new Date());
    const y = date.getUTCFullYear();
    const m = date.getUTCMonth();
    const d = date.getUTCDate();

    if (rule.period === "day") return { $gte: at(y, m, d), $lt: at(y, m, d + 1) };

    if (rule.period === "week") {
        const fromMonday = (date.getUTCDay() + 6) % 7;
        return { $gte: at(y, m, d - fromMonday), $lt: at(y, m, d - fromMonday + 7) };
    }

    if (rule.period === "month") return { $gte: at(y, m, 1), $lt: at(y, m + 1, 1) };

    if (rule.period === "days") {
        const base = new Date(deliveryDate || new Date()).getTime();
        const span = rule.days * 24 * 3600 * 1000;
        return { $gt: new Date(base - span), $lt: new Date(base + span) };
    }

    return null;

};

const periodText = (rule) =>
    rule.period === "days" ? `within ${rule.days} days` :
        rule.period === "project" ? "in this project" :
            `in the same ${rule.period}`;


// ---------------------------------------------------------------- the check

const idOf = (value) => String(value?._id || value || "");

// [{ beneficiary, beneficiaryNumber, name, serviceType, deliveryNumber, deliveryId, deliveryDate }]
const findDuplicates = async ({ organizationId, beneficiaryIds = [], items = [], deliveryDate, project = null, excludeDeliveryId = null }) => {

    if (!beneficiaryIds.length || !(await moduleOn(organizationId))) return [];

    const { duplicateCheck: rule } = await getSettings(organizationId);

    if (!rule.enabled) return [];

    const serviceTypes = [...new Set(items.map(item => idOf(item.serviceType)).filter(id => mongoose.isValidObjectId(id)))];

    if (!serviceTypes.length) return [];

    const ServiceDelivery = mongoose.model("ServiceDelivery");
    const ServiceDeliveryBeneficiary = mongoose.model("ServiceDeliveryBeneficiary");

    const sameProject = rule.sameProject || rule.period === "project";

    if (sameProject && !project) return [];

    const window = windowOf(rule, deliveryDate);

    const deliveries =
        await ServiceDelivery.find({
            organization: organizationId,
            isDeleted: { $ne: true },
            status: { $ne: "Cancelled" },
            "items.serviceType": { $in: serviceTypes },
            ...(window ? { deliveryDate: window } : {}),
            ...(sameProject ? { project } : {}),
            ...(excludeDeliveryId ? { _id: { $ne: excludeDeliveryId } } : {})
        })
            .select("deliveryNumber deliveryDate items.serviceType project")
            .populate("items.serviceType", "value")
            .lean();

    if (!deliveries.length) return [];

    const byId = new Map(deliveries.map(delivery => [idOf(delivery._id), delivery]));

    const rows =
        await ServiceDeliveryBeneficiary.find({
            organization: organizationId,
            serviceDelivery: { $in: deliveries.map(delivery => delivery._id) },
            beneficiary: { $in: beneficiaryIds },
            status: { $ne: "Missed" }
        })
            .select("serviceDelivery beneficiary")
            .populate("beneficiary", "beneficiaryNumber firstName middleName lastName")
            .lean();

    const duplicates = [];

    for (const row of rows) {
        const delivery = byId.get(idOf(row.serviceDelivery));
        const shared = (delivery?.items || []).filter(item => serviceTypes.includes(idOf(item.serviceType)));
        for (const item of shared) {
            const person = row.beneficiary || {};
            duplicates.push({
                beneficiary: idOf(person._id),
                beneficiaryNumber: person.beneficiaryNumber || "",
                name: [person.firstName, person.middleName, person.lastName].filter(Boolean).join(" "),
                serviceType: item.serviceType?.value || "",
                deliveryId: idOf(delivery._id),
                deliveryNumber: delivery.deliveryNumber,
                deliveryDate: delivery.deliveryDate
            });
        }
    }

    return duplicates;

};


// Throws 409 DUPLICATE_DELIVERY unless confirmed with a reason.
// Returns { duplicateConfirmed, duplicateReason } for the delivery.
const assertNoDuplicates = async (args, { confirmDuplicates = false, duplicateReason = "" } = {}) => {

    const duplicates = await findDuplicates(args);

    if (!duplicates.length) return { duplicateConfirmed: false, duplicateReason: "" };

    const { duplicateCheck: rule } = await getSettings(args.organizationId);

    if (confirmDuplicates) {
        if (String(duplicateReason || "").trim().length < 3) {
            throw new ApiError("Give the reason for giving the same service again.", 400);
        }
        return { duplicateConfirmed: true, duplicateReason: String(duplicateReason).trim() };
    }

    const people = [...new Set(duplicates.map(item => item.name || item.beneficiaryNumber))];
    const first = duplicates[0];

    throw new ApiError(
        `${people.length} ${people.length === 1 ? "person has" : "people have"} already received the same service ${periodText(rule)}: ` +
        `${first.name || first.beneficiaryNumber} received ${first.serviceType} in ${first.deliveryNumber}${duplicates.length > 1 ? ` (and ${duplicates.length - 1} more)` : ""}. ` +
        "Remove them, or confirm with a reason.",
        409,
        duplicates.map(item => ({ code: "DUPLICATE_DELIVERY", ...item }))
    );

};


module.exports = {
    PERIODS,
    getSettings,
    updateSettings,
    findDuplicates,
    assertNoDuplicates,
    moduleOn
};
