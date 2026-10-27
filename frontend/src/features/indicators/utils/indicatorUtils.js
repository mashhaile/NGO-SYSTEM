// =====================================================
// M&E INDICATORS: SHARED HELPERS
// =====================================================

export const LEVELS = ["Goal", "Outcome", "Output"];

export const FREQUENCIES = ["Annual", "Quarterly", "Monthly"];

export const FREQUENCY_HELP = {
    Annual: "One target per year (2026, 2027 ...).",
    Quarterly: "One target per quarter (2026-Q1, 2026-Q2 ...).",
    Monthly: "One target per month (2026-01, 2026-02 ...)."
};

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// the periods of a frequency between two years: ["2026-Q1", ...]
export const periodsOf = (frequency, fromYear, toYear) => {
    const periods = [];
    for (let year = Number(fromYear); year <= Number(toYear); year += 1) {
        if (frequency === "Annual") periods.push(String(year));
        else if (frequency === "Quarterly") [1, 2, 3, 4].forEach(q => periods.push(`${year}-Q${q}`));
        else for (let month = 1; month <= 12; month += 1) periods.push(`${year}-${String(month).padStart(2, "0")}`);
    }
    return periods;
};

// "2026" -> "FY 2026", "2026-Q2" -> "Q2 2026", "2026-05" -> "May 2026"
export const periodLabel = (period) => {
    const text = String(period || "");
    let match = text.match(/^(\d{4})$/);
    if (match) return `FY ${match[1]}`;
    match = text.match(/^(\d{4})-Q([1-4])$/);
    if (match) return `Q${match[2]} ${match[1]}`;
    match = text.match(/^(\d{4})-(\d{2})$/);
    if (match) return `${MONTHS[Number(match[2]) - 1]} ${match[1]}`;
    return text;
};

export const valueText = (value, unit) =>
    value === null || value === undefined || value === ""
        ? "-"
        : `${Number(value).toLocaleString("en-US", { maximumFractionDigits: 2 })}${unit === "percent" ? "%" : ""}`;

export const percentText = (value) =>
    value === null || value === undefined ? "-" : `${Number(value).toLocaleString("en-US", { maximumFractionDigits: 1 })}%`;

export const nameOf = (item) =>
    item ? [item.programCode || item.projectCode, item.name].filter(Boolean).join(" - ") : "";

export const STATUS_HELP =
    "On track: 90% or more of the target. At risk: 60-89%. Off track: below 60%.";
