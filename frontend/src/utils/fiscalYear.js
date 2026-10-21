// =====================================================
// FISCAL YEAR
// =====================================================
//
// The fiscal year is the calendar year: January 1 to
// December 31, labelled "FY 2026". Days are counted in
// Addis Ababa time (UTC+3).
//
// Backend copy: backend/utils/fiscalYear.js
// (keep the two in sync).
//
// =====================================================

const ADDIS_OFFSET_MS = 3 * 60 * 60 * 1000;


export const fiscalYearOf = (date) => {

    const time = new Date(date).getTime();

    if (Number.isNaN(time)) {
        return null;
    }

    return new Date(time + ADDIS_OFFSET_MS).getUTCFullYear();

};


export const fiscalYearLabel = (fiscalYear) =>
    `FY ${fiscalYear}`;


export const currentFiscalYear = () =>
    fiscalYearOf(new Date());


export const fiscalYearRange = (from, to) => {

    const years = [];

    for (let year = Number(from); year <= Number(to); year++) {
        years.push(year);
    }

    return years;

};
