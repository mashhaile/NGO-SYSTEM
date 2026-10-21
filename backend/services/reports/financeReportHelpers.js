const mongoose = require("mongoose");

const ApiError = require("../../utils/apiError");


// =====================================================
// SHARED HELPERS FOR THE FINANCE REPORTS
// =====================================================

const roundMoney = (value) => {
    const number = Number(value);
    return Number.isFinite(number) ? Math.round(number * 100) / 100 : 0;
};

const percent = (part, whole) =>
    whole > 0 ? Math.round((part / whole) * 1000) / 10 : 0;

const toObjectId = (value) =>
    value && mongoose.isValidObjectId(value)
        ? new mongoose.Types.ObjectId(String(value))
        : null;

const organizationObjectId = (context) =>
    toObjectId(context.organizationId);


// Finance figures need budget.read (super admin: "*")

const assertBudgetAccess = (context) => {

    const permissions = context.permissions || [];

    if (
        context.role !== "super_admin" &&
        !permissions.includes("*") &&
        !permissions.includes("budget.read")
    ) {
        throw new ApiError("Your role cannot view finance reports.", 403);
    }

};


// The fiscal year (calendar year) a report is for:
// filters.year, else the start date's year, else this year.

const reportFiscalYear = (filters = {}) => {

    const year = Number(filters.year);

    if (Number.isInteger(year) && year > 1900) {
        return year;
    }

    if (filters.startDate) {
        const start = new Date(filters.startDate);
        if (!Number.isNaN(start.getTime())) {
            return start.getFullYear();
        }
    }

    return new Date().getFullYear();

};


// Share of the fiscal year that has passed (0-100):
// 100 for past years, 0 for future ones.

const yearElapsedPercent = (fiscalYear, now = new Date()) => {

    const start = new Date(fiscalYear, 0, 1).getTime();
    const end = new Date(fiscalYear + 1, 0, 1).getTime();
    const time = now.getTime();

    if (time <= start) return 0;
    if (time >= end) return 100;

    return Math.round(((time - start) / (end - start)) * 1000) / 10;

};


// On track / Underspending / Overspending: spending well
// behind or ahead of how much of the year has passed.

const burnStatus = (percentSpent, percentElapsed) => {

    if (percentSpent > 100) return "Over budget";
    if (percentElapsed === 0) return "Not started";
    if (percentSpent > percentElapsed + 15) return "Spending fast";
    if (percentSpent < percentElapsed - 25) return "Underspending";
    return "On track";

};


module.exports = {
    roundMoney,
    percent,
    toObjectId,
    organizationObjectId,
    assertBudgetAccess,
    reportFiscalYear,
    yearElapsedPercent,
    burnStatus
};
