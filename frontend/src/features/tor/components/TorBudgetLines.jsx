import {
    Box,
    IconButton,
    Stack,
    Table,
    TableBody,
    TableCell,
    TableContainer,
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
    AppButton
} from "../../../components/ui";


import {
    emptyBudgetLine,
    formatAmount,
    getBudgetTotal,
    toNumber
} from "../utils/torBudget";



// =====================================================
// TOR BUDGET LINES
// =====================================================
//
// Editable budget table. Line totals and the grand
// total are shown here for the user; the backend
// recalculates them on save.
//
// =====================================================

const cellInput = {
    size: "small",
    fullWidth: true,
    variant: "outlined"
};


const TorBudgetLines = ({
    lines = [],
    currency = "ETB",
    onChange,
    disabled = false
}) => {

    const updateLine = (index, field, value) =>
        onChange(
            lines.map((line, lineIndex) =>
                lineIndex === index
                    ? {
                        ...line,
                        [field]: value
                    }
                    : line
            )
        );

    const removeLine = (index) =>
        onChange(
            lines.filter(
                (line, lineIndex) =>
                    lineIndex !== index
            )
        );

    const addLine = () =>
        onChange([
            ...lines,
            emptyBudgetLine()
        ]);


    return (

        <Box>

            <TableContainer
                sx={{
                    border: "1px solid",
                    borderColor: "divider",
                    borderRadius: 2
                }}
            >

                <Table size="small">

                    <TableHead>

                        <TableRow>

                            <TableCell sx={{ width: "36%" }}>
                                Description
                            </TableCell>

                            <TableCell sx={{ width: "14%" }}>
                                Unit
                            </TableCell>

                            <TableCell sx={{ width: "12%" }} align="right">
                                Quantity
                            </TableCell>

                            <TableCell sx={{ width: "16%" }} align="right">
                                Unit Cost
                            </TableCell>

                            <TableCell sx={{ width: "16%" }} align="right">
                                Total
                            </TableCell>

                            <TableCell sx={{ width: "6%" }} />

                        </TableRow>

                    </TableHead>


                    <TableBody>

                        {lines.length === 0 && (

                            <TableRow>

                                <TableCell colSpan={6}>

                                    <Typography
                                        variant="body2"
                                        color="text.secondary"
                                        sx={{ py: 1 }}
                                    >
                                        No budget lines yet.
                                    </Typography>

                                </TableCell>

                            </TableRow>

                        )}


                        {lines.map((line, index) => (

                            <TableRow key={line._id || index}>

                                <TableCell>
                                    <TextField
                                        {...cellInput}
                                        placeholder="e.g. Venue hire"
                                        value={line.description}
                                        disabled={disabled}
                                        onChange={(e) =>
                                            updateLine(index, "description", e.target.value)
                                        }
                                    />
                                </TableCell>

                                <TableCell>
                                    <TextField
                                        {...cellInput}
                                        placeholder="day"
                                        value={line.unit}
                                        disabled={disabled}
                                        onChange={(e) =>
                                            updateLine(index, "unit", e.target.value)
                                        }
                                    />
                                </TableCell>

                                <TableCell>
                                    <TextField
                                        {...cellInput}
                                        type="number"
                                        inputProps={{
                                            min: 0,
                                            style: { textAlign: "right" }
                                        }}
                                        value={line.quantity}
                                        disabled={disabled}
                                        onChange={(e) =>
                                            updateLine(index, "quantity", e.target.value)
                                        }
                                    />
                                </TableCell>

                                <TableCell>
                                    <TextField
                                        {...cellInput}
                                        type="number"
                                        inputProps={{
                                            min: 0,
                                            step: "0.01",
                                            style: { textAlign: "right" }
                                        }}
                                        value={line.unitCost}
                                        disabled={disabled}
                                        onChange={(e) =>
                                            updateLine(index, "unitCost", e.target.value)
                                        }
                                    />
                                </TableCell>

                                <TableCell align="right">
                                    {formatAmount(
                                        toNumber(line.quantity) * toNumber(line.unitCost),
                                        currency
                                    )}
                                </TableCell>

                                <TableCell align="center">
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


                        <TableRow>

                            <TableCell colSpan={4} align="right">
                                <Typography fontWeight={700}>
                                    Total Budget
                                </Typography>
                            </TableCell>

                            <TableCell align="right">
                                <Typography fontWeight={700}>
                                    {formatAmount(getBudgetTotal(lines), currency)}
                                </Typography>
                            </TableCell>

                            <TableCell />

                        </TableRow>

                    </TableBody>

                </Table>

            </TableContainer>


            <Stack
                direction="row"
                sx={{ mt: 1.5 }}
            >

                <AppButton
                    variant="outlined"
                    startIcon={<Add />}
                    onClick={addLine}
                    disabled={disabled}
                >
                    Add Budget Line
                </AppButton>

            </Stack>

        </Box>

    );

};


export default TorBudgetLines;
