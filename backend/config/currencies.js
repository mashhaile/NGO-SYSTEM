// =====================================================
// CURRENCIES
// =====================================================
//
// The currencies money can be recorded in (donations,
// budgets, expenses, TORs, service items). One list for
// the whole system: add a currency here and in the
// frontend's CURRENCIES (features/budgets/utils/budgetUtils.js).
//
// ETB is the base (reporting) currency: organization-wide
// totals are in ETB; anything in another currency carries
// its exchange rate to ETB (or to its budget's currency).
//
// =====================================================

const BASE_CURRENCY = "ETB";

const CURRENCIES = [
    { code: "ETB", name: "Ethiopian Birr" },
    { code: "USD", name: "US Dollar" },
    { code: "EUR", name: "Euro" },
    { code: "GBP", name: "British Pound" },
    { code: "CHF", name: "Swiss Franc" }
];

const CURRENCY_CODES = CURRENCIES.map(currency => currency.code);


module.exports = {
    BASE_CURRENCY,
    CURRENCIES,
    CURRENCY_CODES
};
