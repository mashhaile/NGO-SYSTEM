// =====================================================
// REPORT CENTER: SHARED PIECES
// =====================================================
//
// Every report (and every detail report) returns the same
// shape, so one screen and one export handle them all:
//
//   {
//     key, title, description,
//     period:  { label, type, start, end },
//     filters: [ { label, value } ],          what was applied
//     summary: [ { label, value, format, currency?, note? } ],
//     sections:[ { key, title, note?, columns, rows, chart? } ],
//     details: { title, columns, rows, link? }  one row per record
//   }
//
//   column = { key, label, format: "text"|"number"|"money"|"percent"|"date", currency? }
//   chart  = { type: "bar"|"line"|"pie", x: <column key>, series: [<column key>], stacked? }
//            (stacked: the series are parts of one total)
//   link   = { kind: "beneficiary"|"program"|…, idKey: "id" }
//            (the screen opens that record's detail report)
//
// =====================================================

const mongoose = require("mongoose");

const ApiError = require("../../utils/apiError");

// ---------- numbers ----------

const toNumber = (value) => {
    const number = Number(value);
    return Number.isFinite(number) ? number : 0;
};

const round2 = (value) => Math.round(toNumber(value) * 100) / 100;

// "ETB 100.00 + USD 5.00": ETB first, then by name; never added together
const formatTotals = (totals) => {
    const keys = Object.keys(totals || {}).filter(key => toNumber(totals[key]) !== 0)
        .sort((a, b) => (a === "ETB" ? -1 : b === "ETB" ? 1 : a.localeCompare(b)));
    return keys.length
        ? keys.map(key => `${key} ${toNumber(totals[key]).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`).join(" + ")
        : "-";
};

const percent = (part, whole) =>
    toNumber(whole) > 0 ? Math.round((toNumber(part) / toNumber(whole)) * 1000) / 10 : 0;

// ---------- ids and queries ----------

const toId = (value) =>
    value && typeof value === "object" ? String(value._id || value) : value ? String(value) : "";

const objectId = (value) =>
    mongoose.Types.ObjectId.isValid(String(value)) ? new mongoose.Types.ObjectId(String(value)) : null;

// records of this organization that are not deleted
const scope = (organizationId, extra = {}) => ({
    organization: objectId(organizationId),
    isDeleted: { $ne: true },
    ...extra
});

// ---------- people ----------

const fullName = (person) =>
    [person?.firstName, person?.middleName, person?.lastName].filter(Boolean).join(" ") || "Unnamed";

const ageOf = (person, at = new Date()) => {
    if (person?.dateOfBirth) {
        const born = new Date(person.dateOfBirth);
        let age = at.getFullYear() - born.getFullYear();
        const before = at.getMonth() < born.getMonth() || (at.getMonth() === born.getMonth() && at.getDate() < born.getDate());
        if (before) age -= 1;
        return age >= 0 ? age : null;
    }
    return Number.isFinite(Number(person?.age)) && person?.age !== null && person?.age !== "" ? Number(person.age) : null;
};

const AGE_GROUPS = [
    { label: "Under 15", max: 14 },
    { label: "15–17", max: 17 },
    { label: "18–29", max: 29 },
    { label: "30–49", max: 49 },
    { label: "50–64", max: 64 },
    { label: "65 and over", max: Infinity }
];

const ageGroup = (age) =>
    age === null || age === undefined ? "Unknown" : AGE_GROUPS.find(group => age <= group.max).label;

const lookupText = (value) =>
    value && typeof value === "object" ? value.value || value.name || value.label || "" : value || "";

const locationText = (record) =>
    [record?.woreda, record?.zone, record?.region].filter(Boolean).join(", ");

// ---------- grouping ----------

// rows of { [labelKey]: label, ...measures } from items, sorted
const groupRows = (items, keyOf, measures, { labelKey = "label", order = null, sort = "desc" } = {}) => {
    const groups = new Map();
    for (const item of items) {
        const keys = [].concat(keyOf(item)).filter(key => key !== undefined && key !== null && key !== "");
        for (const key of keys.length ? keys : ["Not specified"]) {
            const row = groups.get(key) || { [labelKey]: key, ...Object.fromEntries(Object.keys(measures).map(m => [m, 0])) };
            for (const [name, add] of Object.entries(measures)) row[name] += toNumber(add(item));
            groups.set(key, row);
        }
    }
    let rows = [...groups.values()];
    for (const row of rows) for (const name of Object.keys(measures)) row[name] = round2(row[name]);
    if (order) rows.sort((a, b) => order.indexOf(a[labelKey]) - order.indexOf(b[labelKey]));
    else if (sort === "desc") {
        const first = Object.keys(measures)[0];
        rows.sort((a, b) => b[first] - a[first] || String(a[labelKey]).localeCompare(String(b[labelKey])));
    }
    else if (sort === "label") rows.sort((a, b) => String(a[labelKey]).localeCompare(String(b[labelKey])));
    return rows;
};

// ---------- contract builders ----------

const summaryItem = (label, value, format = "number", extra = {}) => ({ label, value, format, ...extra });

const column = (key, label, format = "text", extra = {}) => ({ key, label, format, ...extra });

const section = (key, title, columns, rows, extra = {}) => ({ key, title, columns, rows, ...extra });

const buildReport = ({ key, title, description, period, filters = [], summary = [], sections = [], details = null, record = null }) => ({
    key,
    title,
    description,
    generatedAt: new Date(),
    period: period ? { label: period.label, type: period.type, start: period.start, end: period.end } : null,
    filters: filters.filter(filter => filter && filter.value),
    record,
    summary,
    sections: sections.filter(Boolean),
    details
});

// ---------- access ----------

const hasPermission = (context, permission) =>
    context?.role === "super_admin" ||
    (context?.permissions || []).includes("*") ||
    (context?.permissions || []).includes(permission);

const assertPermission = (context, permission, what) => {
    if (!hasPermission(context, permission)) {
        throw new ApiError(`Your role cannot view ${what}.`, 403);
    }
};

const notFound = (what) => new ApiError(`${what} not found.`, 404);

module.exports = {
    toNumber,
    round2,
    formatTotals,
    percent,
    toId,
    objectId,
    scope,
    fullName,
    ageOf,
    ageGroup,
    AGE_GROUPS,
    lookupText,
    locationText,
    groupRows,
    summaryItem,
    column,
    section,
    buildReport,
    hasPermission,
    assertPermission,
    notFound
};
