import {
    Box,
    Paper,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Typography
} from "@mui/material";


// =====================================================
// ALLOCATION OVERVIEW
// =====================================================
//
// What a delivery gave to whom and what is left, from the
// server's one calculation (delivery.allocationSummary):
// the same figures the save rules and the reports use.
// Quantities stay in their own unit (144 packs stay packs;
// sacks given out in kg are counted in kg); a training is
// "3 sessions, 4 participants", never 12 sessions.
//
// =====================================================

const money = (value) =>
    `ETB ${Number(value || 0).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

const Figure = ({ label, value, note }) => (
    <Box>
        <Typography variant="caption" sx={{ color: "text.secondary" }}>
            {label}
        </Typography>
        <Typography variant="body1" sx={{ fontWeight: 700 }}>
            {value}
        </Typography>
        {note && (
            <Typography variant="caption" sx={{ color: "text.secondary" }}>
                {note}
            </Typography>
        )}
    </Box>
);

const list = (entries) =>
    entries?.length ? entries.map(entry => entry.text).join(" + ") : "Nothing";


const AllocationOverview = ({ summary }) => {

    if (!summary) return null;

    const whole = summary.recipient !== "people";

    return (
        <Paper variant="outlined" sx={{ p: 2.5, borderRadius: 2 }}>

            <Typography variant="h6" sx={{ fontWeight: 700 }}>
                Allocation
            </Typography>
            <Typography variant="body2" sx={{ color: "text.secondary", mb: 2 }}>
                What was given to whom and what is left.
            </Typography>

            {/* ---------- value ---------- */}
            <Box
                sx={{
                    display: "grid",
                    gridTemplateColumns: { xs: "1fr 1fr", md: "repeat(4, 1fr)" },
                    gap: 2,
                    mb: 2.5
                }}
            >
                <Figure label="Delivery cost" value={money(summary.cost)} />

                {whole ? (
                    <Figure
                        label={`To the ${String(summary.recipient).toLowerCase()} as a whole`}
                        value={money(summary.toRecipientAsWhole)}
                        note="Not split among people"
                    />
                ) : (
                    <>
                        <Figure label="Given to people (own shares)" value={money(summary.allocatedValue)} />
                        <Figure
                            label="Shared equally"
                            value={money(summary.sharedEqually)}
                            note={summary.peopleWithoutShare ? `${summary.peopleWithoutShare} people without a share of their own, ${money(summary.equalShare)} each` : "Everyone has their own share"}
                        />
                        <Figure
                            label="Not given to anyone"
                            value={money(summary.unallocatedValue)}
                            note={summary.unallocatedValue > 0 ? "Stock left or cash not shared out" : undefined}
                        />
                    </>
                )}
            </Box>

            {/* ---------- quantities ---------- */}
            <Box
                sx={{
                    display: "grid",
                    gridTemplateColumns: { xs: "1fr", md: "repeat(3, 1fr)" },
                    gap: 2,
                    mb: 2.5
                }}
            >
                <Figure label="Goods given out" value={list(summary.allocatedQuantities)} />
                <Figure label="Goods left" value={whole ? "—" : list(summary.remainingQuantities)} />
                <Figure
                    label="Training and services taken part in"
                    value={summary.participation?.length ? summary.participation.map(entry => `${entry.item}: ${entry.text}`).join("; ") : "None"}
                />
            </Box>

            {/* ---------- per item ---------- */}
            <TableContainer>
                <Table size="small">
                    <TableHead>
                        <TableRow>
                            <TableCell sx={{ fontWeight: 700 }}>Item</TableCell>
                            <TableCell sx={{ fontWeight: 700 }}>Delivered</TableCell>
                            <TableCell sx={{ fontWeight: 700 }}>Given out</TableCell>
                            <TableCell sx={{ fontWeight: 700 }}>Left</TableCell>
                            <TableCell align="right" sx={{ fontWeight: 700 }}>Cost</TableCell>
                            <TableCell align="right" sx={{ fontWeight: 700 }}>Value given</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {summary.items.map(item => (
                            [
                                <TableRow key={item.itemId}>
                                    <TableCell sx={{ fontWeight: 600 }}>
                                        {item.name}
                                        <Typography variant="caption" sx={{ display: "block", color: "text.secondary" }}>
                                            {item.money ? "Money" : item.behavior === "PARTICIPATION" ? "Everyone takes part" : "Shared out"}
                                        </Typography>
                                    </TableCell>
                                    <TableCell>{item.deliveredText}</TableCell>
                                    <TableCell>{item.allocatedText}</TableCell>
                                    <TableCell>{item.remainingText}</TableCell>
                                    <TableCell align="right">{money(item.cost)}</TableCell>
                                    <TableCell align="right">{money(item.allocatedValue)}</TableCell>
                                </TableRow>,
                                ...item.details.map(detail => (
                                    <TableRow key={`${item.itemId}-${detail.detailId}`}>
                                        <TableCell sx={{ pl: 4, color: "text.secondary" }}>{detail.name}</TableCell>
                                        <TableCell>{detail.deliveredText}</TableCell>
                                        <TableCell>{detail.allocatedText}</TableCell>
                                        <TableCell sx={{ color: detail.over > 0 ? "error.main" : undefined }}>
                                            {detail.over > 0 ? `Over by ${detail.over} ${detail.unit}` : detail.remainingText}
                                        </TableCell>
                                        <TableCell align="right">{money(detail.cost)}</TableCell>
                                        <TableCell align="right">{money(detail.allocatedValue)}</TableCell>
                                    </TableRow>
                                ))
                            ]
                        ))}
                    </TableBody>
                </Table>
            </TableContainer>

        </Paper>
    );

};

export default AllocationOverview;
