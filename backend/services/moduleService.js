// =====================================================
// AN ORGANIZATION'S MODULES
// =====================================================
//
// Which optional modules are on for an organization
// (config/modules.js). The platform super admin switches
// them; everyone else only sees the result: permissions of
// a module that is off are left out (filterPermissions),
// which hides its menu, pages, actions and reports.
//
// A module that needs another (TOR needs activities) is off
// when that one is. With TOR off, whoever may create
// activities from a TOR creates them directly instead.
//
// =====================================================

const mongoose = require("mongoose");

const Organization = require("../models/organization");
const ApiError = require("../utils/apiError");
const { MODULES, MODULE_KEYS, moduleOfPermission } = require("../config/modules");


// a few seconds of cache: every request asks
const cache = new Map();
const CACHE_MS = 15000;


// the modules that are on, given the organization's switches
const enabledFrom = (switches = {}) => {
    const on = new Set(
        MODULES
            .filter(module => (typeof switches?.[module.key] === "boolean" ? switches[module.key] : module.defaultEnabled !== false))
            .map(module => module.key)
    );
    // a module whose required module is off is off too
    let changed = true;
    while (changed) {
        changed = false;
        for (const module of MODULES) {
            if (on.has(module.key) && (module.requires || []).some(key => !on.has(key))) {
                on.delete(module.key);
                changed = true;
            }
        }
    }
    return on;
};


const switchesOf = async (organizationId) => {
    const key = String(organizationId || "");
    if (!key || !mongoose.isValidObjectId(key)) return null;
    const hit = cache.get(key);
    if (hit && Date.now() - hit.at < CACHE_MS) return hit.switches;
    const organization = await Organization.findById(key).select("modules").lean();
    const switches = organization?.modules || {};
    cache.set(key, { at: Date.now(), switches });
    return switches;
};


// Set of module keys that are on (all, without an organization)
const enabledFor = async (organizationId) => {
    const switches = await switchesOf(organizationId);
    return switches === null ? new Set(MODULE_KEYS) : enabledFrom(switches);
};


// a user's permissions, without those of modules that are off
const filterPermissions = (permissions = [], enabled) => {
    if (!enabled || permissions.includes("*")) return permissions;
    const kept = permissions.filter(permission => {
        const module = moduleOfPermission(permission);
        return !module || enabled.has(module);
    });
    // TOR off: activities are created directly by those who
    // created them from TORs
    if (!enabled.has("tor") && enabled.has("activities")) {
        if (permissions.includes("tor.create_activity") && !kept.includes("activity.create")) kept.push("activity.create");
        if (permissions.includes("tor.update_activity") && !kept.includes("activity.update")) kept.push("activity.update");
    }
    return kept;
};


// ---------------------------------------------------------------- the super admin screen

const recordsOf = async (organizationId, module) =>
    Promise.all((module.records || []).map(async (record) => {
        try {
            const model = mongoose.model(record.model);
            const count = await model.countDocuments({ organization: organizationId, isDeleted: { $ne: true } });
            return { label: record.label, count };
        }
        catch {
            return { label: record.label, count: null };
        }
    }));


const listForOrganization = async (organizationId) => {
    if (!mongoose.isValidObjectId(organizationId)) throw new ApiError("Organization not found.", 404);
    const organization = await Organization.findById(organizationId).select("name modules").lean();
    if (!organization) throw new ApiError("Organization not found.", 404);
    const switches = organization.modules || {};
    const enabled = enabledFrom(switches);
    return {
        organization: { _id: organization._id, name: organization.name },
        modules: await Promise.all(MODULES.map(async (module) => ({
            key: module.key,
            name: module.name,
            group: module.group,
            description: module.description,
            requires: module.requires || [],
            switchedOn: typeof switches[module.key] === "boolean" ? switches[module.key] : module.defaultEnabled !== false,
            enabled: enabled.has(module.key),
            records: await recordsOf(organization._id, module)
        })))
    };
};


// changes: { tor: false, funding: true }
const updateForOrganization = async (organizationId, changes = {}, actorUserId = null) => {

    if (!mongoose.isValidObjectId(organizationId)) throw new ApiError("Organization not found.", 404);
    const organization = await Organization.findById(organizationId);
    if (!organization) throw new ApiError("Organization not found.", 404);

    const next = { ...(organization.modules || {}) };
    const changed = [];
    for (const [key, value] of Object.entries(changes || {})) {
        if (!MODULE_KEYS.includes(key)) throw new ApiError(`Unknown module: ${key}.`, 400);
        if (typeof value !== "boolean") throw new ApiError(`Give true or false for ${key}.`, 400);
        const before = enabledFrom(next).has(key);
        next[key] = value;
        if (before !== value) changed.push({ key, on: value });
    }

    organization.modules = next;
    organization.markModified("modules");
    await organization.save();
    cache.delete(String(organizationId));

    if (changed.length) {
        const names = (on) => changed.filter(item => item.on === on).map(item => MODULES.find(module => module.key === item.key)?.name).join(", ");
        const description = [names(true) && `On: ${names(true)}`, names(false) && `Off: ${names(false)}`].filter(Boolean).join(". ");
        try {
            await require("./auditLogService").createAuditLog({
                organizationId,
                userId: actorUserId,
                action: "MODULES_CHANGED",
                module: "Organization",
                entityType: "Organization",
                entityId: organization._id,
                description,
                metadata: { changes: changed, modules: next },
                success: true,
                severity: "info"
            });
        }
        catch (error) {
            console.error("Module audit failed:", error.message);
        }
        try {
            await require("./systemNotificationService").notifyOrganizationAdmins(
                organizationId,
                "Modules changed",
                `The platform administrator changed your organization's modules. ${description}. Data of a module that is off is kept and comes back when it is switched on.`,
                "organization",
                actorUserId
            );
        }
        catch (error) {
            console.error("Module notification failed:", error.message);
        }
    }

    return listForOrganization(organizationId);

};


module.exports = {
    enabledFor,
    enabledFrom,
    filterPermissions,
    listForOrganization,
    updateForOrganization
};
