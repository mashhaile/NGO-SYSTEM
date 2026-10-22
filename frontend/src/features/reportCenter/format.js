// =====================================================
// VALUES
// =====================================================

const DAY = (value) => {
    if (!value) return "";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    // the calendar day in Addis Ababa
    const local = new Date(date.getTime() + 3 * 3600 * 1000);
    return `${String(local.getUTCDate()).padStart(2, "0")}/${String(local.getUTCMonth() + 1).padStart(2, "0")}/${local.getUTCFullYear()}`;
};

export const formatValue = (value, format, currency) => {
    if (value === null || value === undefined || value === "") return "—";
    if (format === "money") {
        return `${currency ? `${currency} ` : ""}${Number(value).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
    }
    if (format === "number") return Number(value).toLocaleString("en-US", { maximumFractionDigits: 2 });
    if (format === "percent") return `${Number(value).toLocaleString("en-US", { maximumFractionDigits: 1 })}%`;
    if (format === "date") return DAY(value);
    if (Array.isArray(value)) return value.join(", ");
    return String(value);
};


export const isNumeric = (column) => ["money", "number", "percent"].includes(column.format);
