// =====================================================
// AN ORGANIZATION'S OWN WORDS
// =====================================================
//
// The organization admin may rename the main terms
// ("Donation" -> "Fund"). Saved on the organization
// (terminology: { donation: { singular, plural } }).
// Screens apply them in the shared components; reports and
// their exports here (titles, labels, column names - never
// the data itself).
//
// =====================================================

const Organization = require("../models/organization");
const ApiError = require("../utils/apiError");
const { TERMS, makeReplacer, makeStatusLabel } = require("../config/terminology");


const MAX_LENGTH = 40;

// a few seconds of cache: every report asks
const cache = new Map();
const CACHE_MS = 15000;


const overridesOf = async (organizationId) => {
    const key = String(organizationId || "");
    const hit = cache.get(key);
    if (hit && Date.now() - hit.at < CACHE_MS) return hit.overrides;
    const organization = key ? await Organization.findById(organizationId).select("terminology").lean() : null;
    const overrides = organization?.terminology || {};
    cache.set(key, { at: Date.now(), overrides });
    return overrides;
};


const getTerms = async (organizationId) => {
    const overrides = await overridesOf(organizationId);
    return TERMS.map(term => ({
        ...term,
        own: overrides[term.key]
            ? { singular: overrides[term.key].singular || "", plural: overrides[term.key].plural || "" }
            : null
    }));
};


// terms: { donation: { singular: "Fund", plural: "Funds" }, beneficiary: null (back to default) }
const updateTerms = async (organizationId, terms = {}) => {

    const organization = await Organization.findById(organizationId);
    if (!organization) throw new ApiError("Organization not found.", 404);

    const next = { ...(organization.terminology || {}) };

    for (const [key, value] of Object.entries(terms || {})) {
        const term = TERMS.find(item => item.key === key);
        if (!term) throw new ApiError(`Unknown term: ${key}.`, 400);
        const singular = String(value?.singular || "").trim();
        const plural = String(value?.plural || "").trim();
        if (!singular && !plural) {
            delete next[key];
            continue;
        }
        if (!singular) throw new ApiError(`Give the singular word for "${term.singular}".`, 400);
        if (singular.length > MAX_LENGTH || plural.length > MAX_LENGTH) throw new ApiError(`"${term.singular}": at most ${MAX_LENGTH} letters.`, 400);
        if (singular === term.singular && (!plural || plural === term.plural)) {
            delete next[key];
            continue;
        }
        next[key] = { singular, plural: term.status ? singular : plural || singular };
    }

    organization.terminology = next;
    organization.markModified("terminology");
    await organization.save();
    cache.delete(String(organizationId));

    return getTerms(organizationId);

};


// replace(text) for words; replace.status(value) for a status label
const replacerFor = async (organizationId) => {
    const overrides = await overridesOf(organizationId);
    const replace = makeReplacer(overrides);
    replace.status = makeStatusLabel(overrides);
    return replace;
};


// the words of a report (not its data - except status labels
// in "status" columns)
const applyToReport = (report, replace) => {
    if (!report || typeof report !== "object") return report;
    const status = replace.status || ((value) => value);
    const label = (item) => (item && typeof item === "object" ? { ...item, ...(item.label ? { label: replace(item.label) } : {}), ...(item.note ? { note: replace(item.note) } : {}), ...(item.title ? { title: replace(item.title) } : {}) } : item);
    const table = (item) => {
        if (!item || typeof item !== "object") return item;
        const statusKeys = (item.columns || []).filter(column => column?.key === "status" || column?.label === "Status").map(column => column.key);
        return {
            ...label(item),
            columns: (item.columns || []).map(label),
            ...(Array.isArray(item.rows) && statusKeys.length
                ? { rows: item.rows.map(row => (row && typeof row === "object" ? { ...row, ...Object.fromEntries(statusKeys.map(key => [key, status(row[key])])) } : row)) }
                : {})
        };
    };
    return {
        ...report,
        title: replace(report.title),
        description: replace(report.description),
        summary: Array.isArray(report.summary) ? report.summary.map(label) : report.summary,
        record: report.record ? { ...report.record, fields: (report.record.fields || []).map(label) } : report.record,
        sections: Array.isArray(report.sections)
            ? report.sections.map(table)
            : report.sections,
        details: report.details ? table(report.details) : report.details
    };
};

const applyToCatalog = (catalog, replace) =>
    (catalog || []).map(item => ({ ...item, title: replace(item.title), description: replace(item.description), group: replace(item.group) }));


module.exports = {
    getTerms,
    updateTerms,
    replacerFor,
    applyToReport,
    applyToCatalog
};
