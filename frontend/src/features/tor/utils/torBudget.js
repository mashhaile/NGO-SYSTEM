// =====================================================
// TOR BUDGET HELPERS
// =====================================================
//
// Shown to the user while editing; the backend
// recalculates line totals and the TOR total on save.
//
// =====================================================

export const emptyBudgetLine = () => ({
    description: "",
    unit: "",
    quantity: 1,
    unitCost: 0
});


export const toNumber = (value) => {

    const number =
        Number(value);

    return Number.isFinite(number)
        ? number
        : 0;

};


export const formatAmount = (value, currency = "ETB") =>
    `${currency || "ETB"} ${toNumber(value).toLocaleString("en-US", {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
    })}`;


export const getBudgetTotal = (lines = []) =>
    lines.reduce(
        (sum, line) =>
            sum +
            toNumber(line.quantity) *
            toNumber(line.unitCost),
        0
    );
