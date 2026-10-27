// =====================================================
// TERMINOLOGY (wording each organization may change)
// =====================================================
//
// The words the system uses for its main things. An
// organization admin may call them otherwise ("Donation" ->
// "Fund", "Organization Admin" -> "Administrator"); screens,
// reports and exports then use the organization's words.
// The system itself keeps these internal names.
//
// Keep in step with frontend/src/utils/terms.js (same
// replacing rules).
//
// =====================================================

const TERMS = [
    // people
    { key: "beneficiary", group: "People", singular: "Beneficiary", plural: "Beneficiaries" },
    { key: "enrollment", group: "People", singular: "Enrollment", plural: "Enrollments" },
    { key: "enterprise", group: "People", singular: "Enterprise", plural: "Enterprises" },
    { key: "enterpriseMember", group: "People", singular: "Enterprise Member", plural: "Enterprise Members" },

    // work
    { key: "program", group: "Work", singular: "Program", plural: "Programs" },
    { key: "project", group: "Work", singular: "Project", plural: "Projects" },
    { key: "phase", group: "Work", singular: "Phase", plural: "Phases" },
    { key: "tor", group: "Work", singular: "Terms of Reference", plural: "Terms of Reference" },
    { key: "activity", group: "Work", singular: "Activity", plural: "Activities" },
    { key: "activityRun", group: "Work", singular: "Activity Run", plural: "Activity Runs" },
    { key: "attendance", group: "Work", singular: "Attendance", plural: "Attendance" },
    { key: "serviceDelivery", group: "Work", singular: "Service Delivery", plural: "Service Deliveries" },

    // money
    { key: "donor", group: "Funding", singular: "Donor", plural: "Donors" },
    { key: "donation", group: "Funding", singular: "Donation", plural: "Donations" },
    { key: "budget", group: "Funding", singular: "Budget", plural: "Budgets" },
    { key: "expense", group: "Funding", singular: "Expense", plural: "Expenses" },

    // roles and people in charge
    { key: "organizationAdmin", group: "Roles", singular: "Organization Admin", plural: "Organization Admins" },
    { key: "financeOfficer", group: "Roles", singular: "Finance Officer", plural: "Finance Officers" },
    { key: "dataEntry", group: "Roles", singular: "Data Entry", plural: "Data Entry" },
    { key: "viewer", group: "Roles", singular: "Viewer", plural: "Viewers" },
    { key: "projectManager", group: "Roles", singular: "Project Manager", plural: "Project Managers" },

    // statuses: only the label shown is renamed (a status box
    // reading exactly "Active"), never words inside sentences;
    // the stored value and its rules stay
    ...[
        "Planned", "Active", "Suspended", "Completed", "Cancelled", "Inactive",
        "Pending", "Dropped",
        "Draft", "Submitted", "Approved", "Returned", "Voided",
        "Pledged", "Received", "Delivered",
        "Present", "Absent", "Late", "Excused",
        "Participated", "Missed", "Referred",
        // M&E indicator progress
        "On track", "At risk", "Off track", "No data", "Not started"
    ].map(word => ({ key: `status${word.replace(/\s+/g, "")}`, group: "Statuses", singular: word, plural: word, status: true }))
];


// =====================================================
// REPLACING
// =====================================================
//
// overrides: { donation: { singular: "Fund", plural: "Funds" } }
//
// Whole words only; plural before singular and longer
// phrases first ("Activity Runs" before "Activity"). The
// case of the text is kept: "donations" -> "funds",
// "DONATIONS" -> "FUNDS", "Donations" -> "Funds".
//
// =====================================================

const escape = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const casedLike = (match, word) =>
    match === match.toUpperCase() && /[A-Z]/.test(match) && match.length > 1 ? word.toUpperCase()
        : match === match.toLowerCase() ? word.toLowerCase()
            : word;

const makeReplacer = (overrides = {}) => {

    const pairs = [];
    for (const term of TERMS) {
        const own = overrides?.[term.key];
        if (!own || term.status) continue;
        const singular = String(own.singular || "").trim();
        const plural = String(own.plural || "").trim() || singular;
        if (plural && plural !== term.plural) pairs.push([term.plural, plural]);
        if (singular && singular !== term.singular) pairs.push([term.singular, singular]);
    }
    if (!pairs.length) return (text) => text;

    // one pass, longer phrases first: each piece of text is
    // replaced once ("Project Manager" -> "Program Lead" is not
    // then changed again by a rule for "Program")
    pairs.sort((a, b) => b[0].length - a[0].length);
    const target = new Map(pairs.map(([from, to]) => [from.toLowerCase(), to]));
    const pattern = new RegExp(`(?<![A-Za-z])(?:${pairs.map(([from]) => escape(from)).join("|")})(?![A-Za-z])`, "gi");

    return (text) => {
        if (typeof text !== "string" || !text) return text;
        return text.replace(pattern, (match) => casedLike(match, target.get(match.toLowerCase()) || match));
    };

};


// a status shown as a label: "Active" -> "Ongoing" (exact
// value only, any case)
const makeStatusLabel = (overrides = {}) => {
    const labels = new Map();
    for (const term of TERMS) {
        const own = String(overrides?.[term.key]?.singular || "").trim();
        if (term.status && own && own !== term.singular) labels.set(term.singular.toLowerCase(), own);
    }
    return (value) =>
        (typeof value === "string" && labels.get(value.trim().toLowerCase())) || value;
};


module.exports = {
    TERMS,
    makeReplacer,
    makeStatusLabel
};
