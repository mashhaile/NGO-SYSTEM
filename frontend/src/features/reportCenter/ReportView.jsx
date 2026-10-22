import {
    Box,
    Paper,
    Stack,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Typography,
    useTheme
} from "@mui/material";

import {
    DataGrid
} from "@mui/x-data-grid";

import {
    ResponsiveContainer,
    BarChart,
    Bar,
    LineChart,
    Line,
    PieChart,
    Pie,
    Cell,
    XAxis,
    YAxis,
    Tooltip,
    Legend,
    CartesianGrid
} from "recharts";

import { useNavigate } from "react-router-dom";

import { linkPath } from "./links";
import { formatValue, isNumeric } from "./format";




// =====================================================
// SUMMARY
// =====================================================

const SummaryCards = ({ items }) => (
    <Box
        sx={{
            display: "grid",
            gridTemplateColumns: { xs: "1fr 1fr", sm: "repeat(3, 1fr)", lg: "repeat(5, 1fr)" },
            gap: 1.5,
            mb: 3
        }}
    >
        {items.map(item => (
            <Paper key={item.label} variant="outlined" sx={{ p: 1.75, borderRadius: 2 }}>
                <Typography variant="caption" sx={{ color: "text.secondary", display: "block", lineHeight: 1.3 }}>
                    {item.label}
                </Typography>
                <Typography variant="h6" sx={{ fontWeight: 700, mt: 0.5, wordBreak: "break-word" }}>
                    {formatValue(item.value, item.format, item.currency)}
                </Typography>
                {item.note && (
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>
                        {item.note}
                    </Typography>
                )}
            </Paper>
        ))}
    </Box>
);


// =====================================================
// RECORD FIELDS (detail reports)
// =====================================================

const RecordFields = ({ fields }) => (
    <Paper variant="outlined" sx={{ p: 2, mb: 3, borderRadius: 2 }}>
        <Box
            sx={{
                display: "grid",
                gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr", md: "repeat(4, 1fr)" },
                gap: 2
            }}
        >
            {fields.map(field => (
                <Box key={field.label}>
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>
                        {field.label}
                    </Typography>
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>
                        {formatValue(field.value, field.format)}
                    </Typography>
                </Box>
            ))}
        </Box>
    </Paper>
);


// =====================================================
// CHART
// =====================================================

const SectionChart = ({ chart, rows, columns }) => {

    const theme = useTheme();

    const colors = [
        theme.palette.primary.main,
        theme.palette.secondary?.main || "#C9A227",
        theme.palette.info?.main || "#2B7BB9",
        theme.palette.warning?.main || "#E08A1E",
        theme.palette.success?.light || "#7BB38E",
        theme.palette.error?.light || "#D9776E"
    ];

    const label = (key) => columns.find(column => column.key === key)?.label || key;

    const data = rows.slice(0, 24);

    if (!data.length) return null;

    return (
        <Box sx={{ width: "100%", height: 260, mb: 2 }}>
            <ResponsiveContainer>
                {chart.type === "pie" ? (
                    <PieChart>
                        <Pie data={data} dataKey={chart.series[0]} nameKey={chart.x} outerRadius={95} label>
                            {data.map((row, index) => <Cell key={index} fill={colors[index % colors.length]} />)}
                        </Pie>
                        <Tooltip formatter={(value) => Number(value).toLocaleString("en-US")} />
                        <Legend />
                    </PieChart>
                ) : chart.type === "line" ? (
                    <LineChart data={data} margin={{ left: 8, right: 16, top: 8 }}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey={chart.x} tick={{ fontSize: 12 }} />
                        <YAxis tick={{ fontSize: 12 }} />
                        <Tooltip formatter={(value) => Number(value).toLocaleString("en-US")} />
                        <Legend />
                        {chart.series.map((key, index) => (
                            <Line key={key} type="monotone" dataKey={key} name={label(key)} stroke={colors[index % colors.length]} strokeWidth={2} />
                        ))}
                    </LineChart>
                ) : (
                    <BarChart data={data} margin={{ left: 8, right: 16, top: 8 }}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey={chart.x} tick={{ fontSize: 12 }} interval={0} />
                        <YAxis tick={{ fontSize: 12 }} />
                        <Tooltip formatter={(value) => Number(value).toLocaleString("en-US")} />
                        <Legend />
                        {chart.series.map((key, index) => (
                            <Bar key={key} dataKey={key} name={label(key)} fill={colors[index % colors.length]} radius={[4, 4, 0, 0]} />
                        ))}
                    </BarChart>
                )}
            </ResponsiveContainer>
        </Box>
    );

};


// =====================================================
// SECTION (a breakdown table)
// =====================================================

const SectionTable = ({ section }) => {

    const navigate = useNavigate();

    return (
        <Paper variant="outlined" sx={{ p: 2, mb: 3, borderRadius: 2 }}>

            <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                {section.title}
            </Typography>

            {section.note && (
                <Typography variant="body2" sx={{ color: "text.secondary", mb: 1 }}>
                    {section.note}
                </Typography>
            )}

            {section.rows.length === 0 ? (
                <Typography variant="body2" sx={{ color: "text.secondary", mt: 1 }}>
                    Nothing in this period.
                </Typography>
            ) : (
                <>
                    {section.chart && section.rows.length > 1 && (
                        <Box sx={{ mt: 1 }}>
                            <SectionChart chart={section.chart} rows={section.rows} columns={section.columns} />
                        </Box>
                    )}

                    <TableContainer sx={{ maxHeight: 420 }}>
                        <Table size="small" stickyHeader>
                            <TableHead>
                                <TableRow>
                                    {section.columns.map(column => (
                                        <TableCell
                                            key={column.key}
                                            align={isNumeric(column) ? "right" : "left"}
                                            sx={{ fontWeight: 700, whiteSpace: "nowrap" }}
                                        >
                                            {column.label}
                                            {column.format === "money" && column.currency ? ` (${column.currency})` : ""}
                                        </TableCell>
                                    ))}
                                </TableRow>
                            </TableHead>
                            <TableBody>
                                {section.rows.map((row, index) => {
                                    const path = linkPath(section.link, row);
                                    return (
                                        <TableRow
                                            key={index}
                                            hover={Boolean(path)}
                                            onClick={path ? () => navigate(path) : undefined}
                                            sx={{ cursor: path ? "pointer" : "default" }}
                                        >
                                            {section.columns.map(column => (
                                                <TableCell key={column.key} align={isNumeric(column) ? "right" : "left"}>
                                                    {formatValue(row[column.key], column.format)}
                                                </TableCell>
                                            ))}
                                        </TableRow>
                                    );
                                })}
                                {section.total && (
                                    <TableRow>
                                        {section.columns.map((column, index) => (
                                            <TableCell
                                                key={column.key}
                                                align={isNumeric(column) ? "right" : "left"}
                                                sx={{ fontWeight: 700 }}
                                            >
                                                {index === 0 ? "Total" : formatValue(section.total[column.key], column.format)}
                                            </TableCell>
                                        ))}
                                    </TableRow>
                                )}
                            </TableBody>
                        </Table>
                    </TableContainer>
                </>
            )}

        </Paper>
    );

};


// =====================================================
// DETAILS (one row per record, opens its detail report)
// =====================================================

const DetailsGrid = ({ details }) => {

    const navigate = useNavigate();

    const columns =
        details.columns.map(column => ({
            field: column.key,
            headerName: column.label + (column.format === "money" && column.currency ? ` (${column.currency})` : ""),
            flex: isNumeric(column) ? 0.7 : column.key === "name" || column.key === "title" ? 1.3 : 1,
            minWidth: isNumeric(column) ? 110 : 140,
            type: isNumeric(column) ? "number" : "string",
            align: isNumeric(column) ? "right" : "left",
            headerAlign: isNumeric(column) ? "right" : "left",
            valueFormatter: (value) => formatValue(value, column.format)
        }));

    const rows = details.rows.map((row, index) => ({ _rowId: row.id || index, ...row }));

    return (
        <Paper variant="outlined" sx={{ p: 2, borderRadius: 2 }}>

            <Stack direction="row" sx={{ justifyContent: "space-between", alignItems: "baseline", mb: 1 }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                    {details.title} ({details.rows.length})
                </Typography>
                {details.link && (
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>
                        Click a row to open its full report
                    </Typography>
                )}
            </Stack>

            <Box sx={{ width: "100%" }}>
                <DataGrid
                    rows={rows}
                    columns={columns}
                    getRowId={(row) => row._rowId}
                    density="compact"
                    autoHeight
                    disableRowSelectionOnClick
                    pageSizeOptions={[25, 50, 100]}
                    initialState={{ pagination: { paginationModel: { pageSize: 25 } } }}
                    showToolbar
                    slotProps={{ toolbar: { showQuickFilter: true, quickFilterProps: { debounceMs: 300 } } }}
                    onRowClick={(params) => {
                        const path = linkPath(details.link, params.row);
                        if (path) navigate(path);
                    }}
                    sx={{ border: 0, "& .MuiDataGrid-row": { cursor: details.link ? "pointer" : "default" } }}
                />
            </Box>

        </Paper>
    );

};


// =====================================================
// THE REPORT
// =====================================================

const ReportView = ({ report }) => {

    if (!report) return null;

    return (
        <Box>

            {report.record?.fields?.length > 0 && <RecordFields fields={report.record.fields} />}

            {report.summary?.length > 0 && <SummaryCards items={report.summary} />}

            {report.sections.map(section => <SectionTable key={section.key} section={section} />)}

            {report.details && <DetailsGrid details={report.details} />}

        </Box>
    );

};

export default ReportView;
