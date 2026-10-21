// =====================================================
// BUDGET HELPERS (UI side)
// =====================================================
//
// Mirrors backend/models/Budget.js and budgetService.js.
// The backend always enforces the rules; the UI only shows
// them early.
//
// =====================================================

export const BUDGET_STATUS = {
    DRAFT: "Draft",
    SUBMITTED: "Submitted",
    APPROVED: "Approved",
    RETURNED: "Returned"
};

export const EDITABLE_STATUSES = [
    BUDGET_STATUS.DRAFT,
    BUDGET_STATUS.RETURNED
];

export const BUDGET_CATEGORIES = [
    "Personnel",
    "Training & Workshops",
    "Travel & Per Diem",
    "Direct Beneficiary Support",
    "Supplies & Materials",
    "Equipment",
    "Consultancy & Services",
    "Administration & Overhead",
    "Other"
];

export const CURRENCIES = [
    "ETB",
    "USD",
    "EUR",
    "GBP"
];

export const MAX_YEARS = 10;


export const formatMoney = (value, currency = "ETB") =>
    `${currency} ${Number(value || 0).toLocaleString("en-US", {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
    })}`;


export const levelLabel = (level) =>
    level === "program" ? "Program" : "Project";


// Amount of a given year in [{ fiscalYear, amount }]

export const amountFor = (amounts = [], year) =>
    Number(amounts.find(item => Number(item.fiscalYear) === Number(year))?.amount || 0);


export const sumAmounts = (amounts = []) =>
    amounts.reduce((total, item) => total + Number(item.amount || 0), 0);


export const hasPermission = (user, permission) => {

    const permissions =
        Array.isArray(user?.permissions) ? user.permissions : [];

    return (
        user?.role === "super_admin" ||
        permissions.includes("*") ||
        permissions.includes(permission)
    );

};
