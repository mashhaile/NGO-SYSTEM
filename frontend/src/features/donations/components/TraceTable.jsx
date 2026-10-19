import {
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Typography
} from "@mui/material";



// =====================================================
// TRACE TABLE
// =====================================================
//
// Small read-only table for the donation trace page.
// columns: [{ key, label, align, render(row) }]
//
// =====================================================

const TraceTable = ({
    columns = [],
    rows = [],
    empty = "Nothing recorded yet.",
    getRowKey = (row, index) => row.id || index
}) => {

    if (!rows.length) {

        return (
            <Typography
                variant="body2"
                color="text.secondary"
            >
                {empty}
            </Typography>
        );

    }


    return (

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
                        {columns.map(column => (
                            <TableCell
                                key={column.key}
                                align={column.align || "left"}
                                sx={{ fontWeight: 700 }}
                            >
                                {column.label}
                            </TableCell>
                        ))}
                    </TableRow>
                </TableHead>

                <TableBody>
                    {rows.map((row, index) => (
                        <TableRow key={getRowKey(row, index)}>
                            {columns.map(column => (
                                <TableCell
                                    key={column.key}
                                    align={column.align || "left"}
                                >
                                    {column.render
                                        ? column.render(row)
                                        : row[column.key] ?? "-"}
                                </TableCell>
                            ))}
                        </TableRow>
                    ))}
                </TableBody>

            </Table>

        </TableContainer>

    );

};


export default TraceTable;
