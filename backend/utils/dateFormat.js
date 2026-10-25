// =====================================================
// DATES AS TEXT: DD/MM/YYYY
// =====================================================
//
// One format for every date the system writes: PDFs, Excel
// and CSV exports, and messages ("runs from 01/01/2026 to
// 31/12/2026"). Same as the screens
// (frontend/src/utils/date.js).
//
// Shown as the calendar day in Addis Ababa (UTC+3, no
// daylight saving). Dates stored at midnight UTC stay on
// their own day.
//
// =====================================================

const ADDIS_OFFSET_MS = 3 * 60 * 60 * 1000;

const two = (number) => String(number).padStart(2, "0");

const inAddis = (value) => {
    if (value === null || value === undefined || value === "") return null;
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) return null;
    return new Date(date.getTime() + ADDIS_OFFSET_MS);
};

// 25/10/2026
const formatDate = (value, fallback = "") => {
    const local = inAddis(value);
    if (!local) return fallback;
    return `${two(local.getUTCDate())}/${two(local.getUTCMonth() + 1)}/${local.getUTCFullYear()}`;
};

// 25/10/2026 14:05
const formatDateTime = (value, fallback = "") => {
    const local = inAddis(value);
    if (!local) return fallback;
    return `${formatDate(value)} ${two(local.getUTCHours())}:${two(local.getUTCMinutes())}`;
};

module.exports = {
    formatDate,
    formatDateTime
};
