// =====================================================
// MODULES AN ORGANIZATION CAN HAVE
// =====================================================
//
// The platform super admin switches these on or off per
// organization (Super Admin > Organizations > Modules). A
// module that is off is hidden, never deleted: its menu,
// pages, actions and reports disappear for that
// organization, and come back with all their data when it
// is switched on again.
//
// It works through permissions: a user's permissions that
// belong to a module that is off are left out (see
// moduleService), so the menu, every page, every server
// action and the reports react without code of their own.
//
// The core (beneficiaries, programs, projects, reports,
// settings) is always on.
//
// To add a module (e.g. procurement, M&E): give it a key,
// its permission prefixes and, for an optional module new
// clients only get on request, defaultEnabled: false.
//
//   key           stored on the organization (modules.<key>)
//   permissions   permission prefixes it owns ("tor" -> tor.*)
//   requires      modules it cannot work without
//   records       model + label, to show how much data it holds
//
// =====================================================

const MODULES = [
    {
        key: "enrollments",
        name: "Enrollments",
        group: "People",
        description: "Beneficiaries enrolled in programs, with dates and status.",
        permissions: ["enrollment"],
        records: [{ model: "Enrollment", label: "enrollments" }]
    },
    {
        key: "enterprises",
        name: "Enterprises",
        group: "People",
        description: "Businesses, cooperatives and groups run by beneficiaries, and their members.",
        permissions: ["enterprise"],
        records: [{ model: "Enterprise", label: "enterprises" }, { model: "EnterpriseMember", label: "members" }]
    },
    {
        key: "activities",
        name: "Activities and training",
        group: "Work",
        description: "Activities, activity runs and attendance (people trained, completion, attendance rate).",
        permissions: ["activity", "activity_run", "attendance", "attendance_record"],
        records: [{ model: "Activity", label: "activities" }, { model: "ActivityRun", label: "runs" }, { model: "Attendance", label: "attendance sessions" }]
    },
    {
        key: "tor",
        name: "Terms of Reference",
        group: "Work",
        description: "TORs for activities and trainings, with approval. Off: activities are created directly.",
        permissions: ["tor"],
        requires: ["activities"],
        records: [{ model: "TermsOfReference", label: "TORs" }]
    },
    {
        key: "serviceDelivery",
        name: "Service delivery",
        group: "Work",
        description: "Goods, cash and services given to people, households, groups and institutions.",
        permissions: ["service"],
        records: [{ model: "ServiceDelivery", label: "deliveries" }]
    },
    {
        key: "funding",
        name: "Donors and donations",
        group: "Funding",
        description: "Donors, donations, \"Where did it go\" and donor share links.",
        permissions: ["donor", "donation"],
        records: [{ model: "Donor", label: "donors" }, { model: "Donation", label: "donations" }]
    },
    {
        key: "finance",
        name: "Budgets and expenses",
        group: "Finance",
        description: "Program and project budgets with approval, revisions, and expenses charged to them.",
        permissions: ["budget", "expense"],
        records: [{ model: "Budget", label: "budgets" }, { model: "Expense", label: "expenses" }]
    }
];

const MODULE_KEYS = MODULES.map(module => module.key);

// permission prefix -> module key
const MODULE_OF_PREFIX = Object.fromEntries(
    MODULES.flatMap(module => module.permissions.map(prefix => [prefix, module.key]))
);

const moduleOfPermission = (permission) =>
    MODULE_OF_PREFIX[String(permission || "").split(".")[0]] || null;

module.exports = {
    MODULES,
    MODULE_KEYS,
    moduleOfPermission
};
