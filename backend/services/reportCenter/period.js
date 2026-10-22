// =====================================================
// REPORT PERIOD
// =====================================================
//
// One way to read the period for every report:
//
//   period=year     &year=2026                FY 2026 (Jan–Dec)
//   period=half     &year=2026&half=1         H1 2026
//   period=quarter  &year=2026&quarter=3      Q3 2026
//   period=month    &year=2026&month=10       October 2026
//   period=custom   &startDate=…&endDate=…    1 Mar 2026 – 30 Jun 2026
//   period=all                                All time
//
// The year is the calendar year (FY 2026 = Jan–Dec 2026).
// Boundaries are midnight in Addis Ababa (UTC+3), the way
// dates are saved: 1 Jan 2026 is 2025-12-31T21:00Z.
//
// =====================================================

const OFFSET_HOURS = 3;

const MONTHS = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
];

// midnight in Addis Ababa on that calendar day, as a Date
const localMidnight = (year, monthIndex, day) =>
    new Date(Date.UTC(year, monthIndex, day) - OFFSET_HOURS * 3600 * 1000);

// "2026-03-01" or a full date → that calendar day in Addis Ababa
const parseDay = (value) => {
    if (!value) return null;
    const text = String(value).slice(0, 10);
    const match = text.match(/^(\d{4})-(\d{2})-(\d{2})$/);
    if (!match) {
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? null : date;
    }
    return localMidnight(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
};

const dayLabel = (date) => {
    const local = new Date(date.getTime() + OFFSET_HOURS * 3600 * 1000);
    return `${local.getUTCDate()} ${MONTHS[local.getUTCMonth()].slice(0, 3)} ${local.getUTCFullYear()}`;
};

const resolvePeriod = (query = {}) => {

    const now = new Date();
    const thisYear = new Date(now.getTime() + OFFSET_HOURS * 3600 * 1000).getUTCFullYear();
    const year = Number(query.year) || thisYear;
    const type = String(query.period || "year").toLowerCase();

    if (type === "all") {
        return { type, year: null, start: null, end: null, label: "All time" };
    }

    if (type === "custom") {
        const start = parseDay(query.startDate);
        const lastDay = parseDay(query.endDate);
        // end is exclusive: the day after the last day
        const end = lastDay ? new Date(lastDay.getTime() + 24 * 3600 * 1000) : null;
        const label =
            start && lastDay ? `${dayLabel(start)} – ${dayLabel(lastDay)}`
                : start ? `From ${dayLabel(start)}`
                    : lastDay ? `Until ${dayLabel(lastDay)}`
                        : "All time";
        return { type, year: null, start, end, label };
    }

    if (type === "month") {
        const month = Math.min(Math.max(Number(query.month) || 1, 1), 12);
        return {
            type, year, month,
            start: localMidnight(year, month - 1, 1),
            end: localMidnight(year, month, 1),
            label: `${MONTHS[month - 1]} ${year}`
        };
    }

    if (type === "quarter") {
        const quarter = Math.min(Math.max(Number(query.quarter) || 1, 1), 4);
        return {
            type, year, quarter,
            start: localMidnight(year, (quarter - 1) * 3, 1),
            end: localMidnight(year, quarter * 3, 1),
            label: `Q${quarter} ${year} (${MONTHS[(quarter - 1) * 3].slice(0, 3)}–${MONTHS[quarter * 3 - 1].slice(0, 3)})`
        };
    }

    if (type === "half") {
        const half = Number(query.half) === 2 ? 2 : 1;
        return {
            type, year, half,
            start: localMidnight(year, (half - 1) * 6, 1),
            end: localMidnight(year, half * 6, 1),
            label: `H${half} ${year} (${half === 1 ? "Jan–Jun" : "Jul–Dec"})`
        };
    }

    return {
        type: "year", year,
        start: localMidnight(year, 0, 1),
        end: localMidnight(year + 1, 0, 1),
        label: `FY ${year} (Jan–Dec)`
    };

};

// Mongo condition for a date field inside the period
const inPeriod = (period) => {
    if (!period || (!period.start && !period.end)) return null;
    const condition = {};
    if (period.start) condition.$gte = period.start;
    if (period.end) condition.$lt = period.end;
    return condition;
};

// "2026-03" month key of a date, in Addis Ababa time
const monthKey = (date) => {
    if (!date) return null;
    const local = new Date(new Date(date).getTime() + OFFSET_HOURS * 3600 * 1000);
    return `${local.getUTCFullYear()}-${String(local.getUTCMonth() + 1).padStart(2, "0")}`;
};

const monthName = (key) => {
    const [year, month] = String(key).split("-");
    return `${MONTHS[Number(month) - 1].slice(0, 3)} ${year}`;
};

module.exports = {
    resolvePeriod,
    inPeriod,
    monthKey,
    monthName,
    parseDay,
    MONTHS
};
