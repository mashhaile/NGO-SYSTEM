// =====================================================
// PROCUREMENT HELPERS (UI side)
// mirrors backend/models/Supplier.js and PurchaseRequest.js
// =====================================================

export const SUPPLIER_STATUS = {
    ACTIVE: "Active",
    INACTIVE: "Inactive",
    BLACKLISTED: "Blacklisted"
};

export const SUPPLIER_CATEGORIES = [
    "Goods",
    "Services",
    "Works",
    "Consultancy"
];

export const PURCHASE_REQUEST_STATUS = {
    DRAFT: "Draft",
    SUBMITTED: "Submitted",
    APPROVED: "Approved",
    RETURNED: "Returned",
    REJECTED: "Rejected",
    CANCELLED: "Cancelled"
};

export const EDITABLE_STATUSES = [
    PURCHASE_REQUEST_STATUS.DRAFT,
    PURCHASE_REQUEST_STATUS.RETURNED
];

// common units for request items (free text is allowed too)
export const UNITS = [
    "pcs", "set", "box", "pack", "ream", "kg", "litre", "metre", "pair", "day", "month", "lot"
];

export const roundMoney = (value) =>
    Math.round(Number(value || 0) * 100) / 100;

export const itemTotal = (item) =>
    roundMoney(Number(item.quantity || 0) * Number(item.unitPrice || 0));

export { formatDate } from "../../../utils/date";
