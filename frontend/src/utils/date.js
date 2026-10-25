// =====================================================
// DATES ON SCREEN: DD/MM/YYYY
// =====================================================
//
// One format everywhere: lists, detail pages, reports,
// notifications. Same as the server's PDFs and exports
// (backend/utils/dateFormat.js).
//
// Calendar dates (birth date, start date …) are stored at
// midnight UTC or sent as "YYYY-MM-DD": they are shown as
// that day, whatever the computer's time zone. Moments
// (created at, approved at …) are shown in local time.
//
// =====================================================

const two = (number) => String(number).padStart(2, "0");

const toDate = (value) => {
    if (value === null || value === undefined || value === "") return null;
    if (typeof value?.toDate === "function") value = value.toDate(); // dayjs
    const date = value instanceof Date ? value : new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
};

const isCalendarDay = (value, date) =>
    (typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/.test(value)) ||
    (date.getUTCHours() === 0 && date.getUTCMinutes() === 0 && date.getUTCSeconds() === 0 && date.getUTCMilliseconds() === 0);


// 25/10/2026
export const formatDate = (value, fallback = "-") => {
    const date = toDate(value);
    if (!date) return fallback;
    return isCalendarDay(value, date)
        ? `${two(date.getUTCDate())}/${two(date.getUTCMonth() + 1)}/${date.getUTCFullYear()}`
        : `${two(date.getDate())}/${two(date.getMonth() + 1)}/${date.getFullYear()}`;
};


// 25/10/2026 14:05
export const formatDateTime = (value, fallback = "-") => {
    const date = toDate(value);
    if (!date) return fallback;
    return `${two(date.getDate())}/${two(date.getMonth() + 1)}/${date.getFullYear()} ${two(date.getHours())}:${two(date.getMinutes())}`;
};


// The dates a record must fall in, shown under its date field:
// rangeHint("program", start, end) -> "The program runs 01/01/2026 – 31/12/2026."
export const rangeHint = (what, start, end) => {
    if (!start && !end) return "";
    return `The ${what} runs ${start ? formatDate(start) : "…"} – ${end ? formatDate(end) : "no end date"}.`;
};

// "YYYY-MM-DD" of a stored date (for minDate / maxDate)
export const dayOf = (value) => {
    const date = toDate(value);
    if (!date) return undefined;
    return isCalendarDay(value, date)
        ? date.toISOString().slice(0, 10)
        : `${date.getFullYear()}-${two(date.getMonth() + 1)}-${two(date.getDate())}`;
};


// "just now", "5 min ago", "3 h ago", "yesterday", then the date
export const timeAgo = (value) => {
    const date = toDate(value);
    if (!date) return "";
    const minutes = Math.floor((Date.now() - date.getTime()) / 60000);
    if (minutes < 1) return "just now";
    if (minutes < 60) return `${minutes} min ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours} h ago`;
    if (hours < 48) return "yesterday";
    return formatDate(date);
};
