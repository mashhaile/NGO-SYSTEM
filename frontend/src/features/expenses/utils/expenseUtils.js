// =====================================================
// EXPENSE HELPERS (UI side) - mirrors backend/models/Expense.js
// =====================================================

export const EXPENSE_STATUS = {
    DRAFT: "Draft",
    SUBMITTED: "Submitted",
    APPROVED: "Approved",
    RETURNED: "Returned",
    VOIDED: "Voided"
};

export const EDITABLE_STATUSES = [
    EXPENSE_STATUS.DRAFT,
    EXPENSE_STATUS.RETURNED
];

export const PAYMENT_METHODS = [
    "Cash",
    "Bank Transfer",
    "Cheque",
    "Mobile Money",
    "Other"
];

export const formatDate = (value) =>
    value
        ? new Date(value).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })
        : "-";
