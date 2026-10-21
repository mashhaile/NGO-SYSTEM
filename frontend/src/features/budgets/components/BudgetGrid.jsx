import {
    Box,
    Button,
    IconButton,
    MenuItem,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableFooter,
    TableHead,
    TableRow,
    TextField,
    Tooltip,
    Typography
} from "@mui/material";

import {
    Add,
    DeleteOutlined
} from "@mui/icons-material";

import {
    BUDGET_CATEGORIES,
    formatMoney
} from "../utils/budgetUtils";

import {
    fiscalYearLabel
} from "../../../utils/fiscalYear";


// =====================================================
// BUDGET GRID
// =====================================================
//
// level "program": one row of amounts per fiscal year
// level "project": budget lines (category + description)
//                  x fiscal years, with totals
//
// Amounts are kept as strings while typing; the page
// converts them to numbers when saving. When `available`
// (year -> amount left in the program budget) is given,
// a row shows it and years that go over turn red.
//
// =====================================================

const cellInput = {
    size: "small",
    fullWidth: true,
    variant: "outlined"
};

const moneyInput = {
    ...cellInput,
    type: "number",
    slotProps: {
        htmlInput: {
            min: 0,
            step: "any",
            style: { textAlign: "right" }
        }
    }
};

const toNumber = (value) => {
    const number = Number(value);
    return Number.isFinite(number) ? number : 0;
};

const yearCellSx = { minWidth: 130 };


const BudgetGrid = ({
    level,
    years = [],
    currency = "ETB",
    yearlyAmounts = [],
    lines = [],
    available = null,
    disabled = false,
    onChangeYearly,
    onChangeLines
}) => {

    // ---------------- program level ----------------

    if (level === "program") {

        const total =
            years.reduce((sum, year) => sum + toNumber(yearlyAmounts.find(item => item.fiscalYear === year)?.amount), 0);

        const setYear = (year, value) =>
            onChangeYearly(
                years.map(fiscalYear => ({
                    fiscalYear,
                    amount: fiscalYear === year
                        ? value
                        : (yearlyAmounts.find(item => item.fiscalYear === fiscalYear)?.amount ?? "")
                }))
            );

        return (
            <TableContainer sx={{ border: "1px solid", borderColor: "divider", borderRadius: 2, overflowX: "auto" }}>
                <Table size="small">
                    <TableHead>
                        <TableRow>
                            {years.map(year => (
                                <TableCell key={year} align="right" sx={yearCellSx}>
                                    {fiscalYearLabel(year)}
                                </TableCell>
                            ))}
                            <TableCell align="right" sx={{ minWidth: 150 }}>Total</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        <TableRow>
                            {years.map(year => (
                                <TableCell key={year}>
                                    <TextField
                                        {...moneyInput}
                                        aria-label={`Amount for ${fiscalYearLabel(year)}`}
                                        value={yearlyAmounts.find(item => item.fiscalYear === year)?.amount ?? ""}
                                        disabled={disabled}
                                        onChange={(e) => setYear(year, e.target.value)}
                                    />
                                </TableCell>
                            ))}
                            <TableCell align="right">
                                <Typography sx={{ fontWeight: 700, whiteSpace: "nowrap" }}>
                                    {formatMoney(total, currency)}
                                </Typography>
                            </TableCell>
                        </TableRow>
                    </TableBody>
                </Table>
            </TableContainer>
        );

    }


    // ---------------- project level ----------------

    const lineAmount = (line, year) =>
        line.amounts.find(item => item.fiscalYear === year)?.amount ?? "";

    const updateLine = (index, patch) =>
        onChangeLines(lines.map((line, i) => (i === index ? { ...line, ...patch } : line)));

    const setLineYear = (index, year, value) =>
        updateLine(index, {
            amounts: years.map(fiscalYear => ({
                fiscalYear,
                amount: fiscalYear === year ? value : lineAmount(lines[index], fiscalYear)
            }))
        });

    const addLine = () =>
        onChangeLines([
            ...lines,
            {
                category: BUDGET_CATEGORIES[0],
                description: "",
                amounts: years.map(fiscalYear => ({ fiscalYear, amount: "" }))
            }
        ]);

    const removeLine = (index) =>
        onChangeLines(lines.filter((_, i) => i !== index));

    const lineTotal = (line) =>
        years.reduce((sum, year) => sum + toNumber(lineAmount(line, year)), 0);

    const yearTotal = (year) =>
        lines.reduce((sum, line) => sum + toNumber(lineAmount(line, year)), 0);

    const grandTotal =
        years.reduce((sum, year) => sum + yearTotal(year), 0);

    const isOver = (year) =>
        available && available[year] !== undefined && yearTotal(year) > available[year] + 0.005;


    return (
        <Box>

            <TableContainer sx={{ border: "1px solid", borderColor: "divider", borderRadius: 2, overflowX: "auto" }}>
                <Table size="small">

                    <TableHead>
                        <TableRow>
                            <TableCell sx={{ minWidth: 180 }}>Category</TableCell>
                            <TableCell sx={{ minWidth: 170 }}>Description</TableCell>
                            {years.map(year => (
                                <TableCell key={year} align="right" sx={yearCellSx}>
                                    {fiscalYearLabel(year)}
                                </TableCell>
                            ))}
                            <TableCell align="right" sx={{ minWidth: 140 }}>Line total</TableCell>
                            <TableCell sx={{ width: 48 }} />
                        </TableRow>
                    </TableHead>

                    <TableBody>

                        {lines.length === 0 && (
                            <TableRow>
                                <TableCell colSpan={years.length + 4}>
                                    <Typography variant="body2" sx={{ color: "text.secondary", py: 1 }}>
                                        No budget lines yet. Add a line for each cost category, e.g. Personnel, Training, Supplies.
                                    </Typography>
                                </TableCell>
                            </TableRow>
                        )}

                        {lines.map((line, index) => (
                            <TableRow key={line._id || `new-${index}`}>
                                <TableCell>
                                    <TextField
                                        {...cellInput}
                                        select
                                        aria-label="Category"
                                        value={line.category}
                                        disabled={disabled}
                                        onChange={(e) => updateLine(index, { category: e.target.value })}
                                    >
                                        {BUDGET_CATEGORIES.map(category => (
                                            <MenuItem key={category} value={category}>{category}</MenuItem>
                                        ))}
                                    </TextField>
                                </TableCell>
                                <TableCell>
                                    <TextField
                                        {...cellInput}
                                        placeholder="e.g. Project coordinator salary"
                                        value={line.description}
                                        disabled={disabled}
                                        onChange={(e) => updateLine(index, { description: e.target.value })}
                                    />
                                </TableCell>
                                {years.map(year => (
                                    <TableCell key={year}>
                                        <TextField
                                            {...moneyInput}
                                            aria-label={`${line.category} ${fiscalYearLabel(year)}`}
                                            value={lineAmount(line, year)}
                                            disabled={disabled}
                                            onChange={(e) => setLineYear(index, year, e.target.value)}
                                        />
                                    </TableCell>
                                ))}
                                <TableCell align="right">
                                    <Typography variant="body2" sx={{ fontWeight: 600, whiteSpace: "nowrap" }}>
                                        {formatMoney(lineTotal(line), currency)}
                                    </Typography>
                                </TableCell>
                                <TableCell>
                                    <Tooltip title="Remove line">
                                        <span>
                                            <IconButton
                                                size="small"
                                                color="error"
                                                disabled={disabled}
                                                onClick={() => removeLine(index)}
                                            >
                                                <DeleteOutlined fontSize="small" />
                                            </IconButton>
                                        </span>
                                    </Tooltip>
                                </TableCell>
                            </TableRow>
                        ))}

                    </TableBody>

                    <TableFooter>

                        <TableRow>
                            <TableCell colSpan={2}>
                                <Typography sx={{ fontWeight: 700 }}>Total per year</Typography>
                            </TableCell>
                            {years.map(year => (
                                <TableCell key={year} align="right">
                                    <Typography
                                        sx={{
                                            fontWeight: 700,
                                            whiteSpace: "nowrap",
                                            color: isOver(year) ? "error.main" : "text.primary"
                                        }}
                                    >
                                        {formatMoney(yearTotal(year), currency)}
                                    </Typography>
                                </TableCell>
                            ))}
                            <TableCell align="right">
                                <Typography sx={{ fontWeight: 800, whiteSpace: "nowrap" }}>
                                    {formatMoney(grandTotal, currency)}
                                </Typography>
                            </TableCell>
                            <TableCell />
                        </TableRow>

                        {available && (
                            <TableRow>
                                <TableCell colSpan={2}>
                                    <Typography variant="body2" sx={{ color: "text.secondary" }}>
                                        Available in program budget
                                    </Typography>
                                </TableCell>
                                {years.map(year => (
                                    <TableCell key={year} align="right">
                                        <Typography
                                            variant="body2"
                                            sx={{
                                                whiteSpace: "nowrap",
                                                color: isOver(year) ? "error.main" : "text.secondary",
                                                fontWeight: isOver(year) ? 700 : 400
                                            }}
                                        >
                                            {available[year] === undefined
                                                ? "Not in program budget"
                                                : formatMoney(available[year], currency)}
                                        </Typography>
                                    </TableCell>
                                ))}
                                <TableCell colSpan={2} />
                            </TableRow>
                        )}

                    </TableFooter>

                </Table>
            </TableContainer>

            {!disabled && (
                <Button
                    startIcon={<Add />}
                    onClick={addLine}
                    sx={{ mt: 1.5 }}
                >
                    Add budget line
                </Button>
            )}

        </Box>
    );

};


export default BudgetGrid;
