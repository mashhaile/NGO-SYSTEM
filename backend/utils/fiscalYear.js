// =====================================================
// FISCAL YEAR
// =====================================================
//
// The fiscal year is the calendar year: January 1 to
// December 31, labelled "FY 2026".
//
// Days are counted in Addis Ababa time (UTC+3), so an
// expense at 23:30 on December 31 still belongs to the year
// that is ending.
//
// Frontend copy: frontend/src/utils/fiscalYear.js
// (keep the two in sync).
//
// =====================================================

const ADDIS_OFFSET_MS = 3 * 60 * 60 * 1000;

const DAY_MS = 24 * 60 * 60 * 1000;


// Midnight January 1 (Addis Ababa) of the fiscal year

const fiscalYearStart = (fiscalYear) =>
    new Date(Date.UTC(fiscalYear, 0, 1) - ADDIS_OFFSET_MS);


// Exclusive end: the start of the next fiscal year

const fiscalYearEnd = (fiscalYear) =>
    fiscalYearStart(fiscalYear + 1);


const fiscalYearOf = (date) => {

    const time = new Date(date).getTime();

    if (Number.isNaN(time)) {
        return null;
    }

    return new Date(time + ADDIS_OFFSET_MS).getUTCFullYear();

};


const fiscalYearLabel = (fiscalYear) =>
    `FY ${fiscalYear}`;


const formatDate = (date) =>
    new Date(date.getTime() + ADDIS_OFFSET_MS).toISOString().slice(0, 10);


// e.g. { fiscalYear: 2026, label: "FY 2026", start: "2026-01-01", end: "2026-12-31" }

const describeFiscalYear = (fiscalYear) => ({
    fiscalYear,
    label: fiscalYearLabel(fiscalYear),
    start: formatDate(fiscalYearStart(fiscalYear)),
    end: formatDate(new Date(fiscalYearEnd(fiscalYear).getTime() - DAY_MS))
});


const fiscalYearRange = (from, to) => {

    const years = [];

    for (let year = from; year <= to; year++) {
        years.push(year);
    }

    return years;

};


module.exports = {
    fiscalYearOf,
    fiscalYearStart,
    fiscalYearEnd,
    fiscalYearLabel,
    describeFiscalYear,
    fiscalYearRange
};
