import {
    Box,
    Typography,
    Stack,
    Divider
} from "@mui/material";

import {
    BarChart,
    Bar,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
    Cell,
    LabelList
} from "recharts";


const COLORS = [
    "#2563eb",
    "#16a34a",
    "#f59e0b",
    "#dc2626",
    "#7c3aed",
    "#0891b2",
    "#db2777",
    "#65a30d",
    "#ea580c",
    "#4f46e5"
];


const BeneficiaryByProgram = ({
    data = []
}) => {

    const chartData = Array.isArray(data)

        ? data.map((item, index) => ({

            ...item,

            programName:
                item.programName ||
                "Unnamed Program",

            male:
                Number(
                    item.male || 0
                ),

            female:
                Number(
                    item.female || 0
                ),

            beneficiaries:
                Number(
                    item.beneficiaries || 0
                ),

            target:
                Number(
                    item.target || 0
                ),

            color:
                COLORS[
                    index % COLORS.length
                ]

        }))

        : [];


    // ==========================================
    // EMPTY STATE
    // ==========================================

    if (!chartData.length) {

        return (

            <Box
                sx={{
                    height: 360,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center"
                }}
            >

                <Typography
                    color="text.secondary"
                >
                    No program beneficiary data available.
                </Typography>

            </Box>

        );

    }


    return (

        <Box
            sx={{
                width: "100%"
            }}
        >

            {/* =====================================
                CHART
            ===================================== */}

            <Box
                sx={{
                    width: "100%",
                    height: {
                        xs: 380,
                        md: 430
                    }
                }}
            >

                <ResponsiveContainer
                    width="100%"
                    height="100%"
                >

                    <BarChart
                        data={chartData}

                        margin={{
                            top: 30,
                            right: 20,
                            left: 0,
                            bottom: 70
                        }}

                        barCategoryGap="28%"
                    >

                        <CartesianGrid
                            strokeDasharray="3 3"
                            vertical={false}
                            stroke="#e5e7eb"
                        />


                        <XAxis
                            dataKey="programName"

                            tick={{
                                fontSize: 12,
                                fill: "#64748b"
                            }}

                            axisLine={false}
                            tickLine={false}

                            angle={-30}

                            textAnchor="end"

                            interval={0}
                        />


                        <YAxis
                            allowDecimals={false}

                            axisLine={false}
                            tickLine={false}

                            tick={{
                                fontSize: 12,
                                fill: "#64748b"
                            }}
                        />


                        {/* =================================
                            TOOLTIP
                        ================================= */}

                        <Tooltip
                            cursor={{
                                fill:
                                    "rgba(15,23,42,0.04)"
                            }}

                            contentStyle={{
                                borderRadius: 12,

                                border:
                                    "1px solid #e5e7eb",

                                boxShadow:
                                    "0 8px 25px rgba(15,23,42,.10)"
                            }}

                            formatter={(
                                value,
                                name
                            ) => {

                                if (
                                    name ===
                                    "beneficiaries"
                                ) {

                                    return [
                                        value,
                                        "Beneficiaries"
                                    ];

                                }

                                if (
                                    name ===
                                    "target"
                                ) {

                                    return [
                                        value,
                                        "Target"
                                    ];

                                }

                                return [
                                    value,
                                    name
                                ];

                            }}
                        />


                        {/* =================================
                            TARGET
                        ================================= */}

                        <Bar
                            dataKey="target"

                            name="target"

                            fill="#e2e8f0"

                            radius={[
                                6,
                                6,
                                0,
                                0
                            ]}

                            barSize={34}
                        />


                        {/* =================================
                            BENEFICIARIES
                        ================================= */}

                        <Bar
                            dataKey="beneficiaries"

                            name="beneficiaries"

                            radius={[
                                6,
                                6,
                                0,
                                0
                            ]}

                            barSize={34}
                        >

                            {chartData.map(
                                (
                                    entry,
                                    index
                                ) => (

                                    <Cell
                                        key={
                                            entry.programId ||
                                            index
                                        }

                                        fill={
                                            entry.color
                                        }
                                    />

                                )
                            )}


                            <LabelList
                                dataKey="beneficiaries"

                                position="top"

                                style={{
                                    fontSize: 13,
                                    fontWeight: 700,
                                    fill: "#0f172a"
                                }}
                            />

                        </Bar>

                    </BarChart>

                </ResponsiveContainer>

            </Box>


            {/* =====================================
                PROGRAM DETAILS
            ===================================== */}

            <Box
                sx={{
                    mt: 2,

                    display: "grid",

                    gridTemplateColumns: {
                        xs: "1fr",
                        sm: "repeat(2, 1fr)",
                        lg: "repeat(3, 1fr)"
                    },

                    gap: 1.5
                }}
            >

                {chartData.map(
                    (
                        program,
                        index
                    ) => (

                        <Box
                            key={
                                program.programId ||
                                index
                            }

                            sx={{
                                p: 1.75,

                                borderRadius: 2.5,

                                border:
                                    "1px solid #e5e7eb",

                                background:
                                    "#ffffff",

                                transition:
                                    "all .2s ease",

                                "&:hover": {
                                    borderColor:
                                        program.color,

                                    boxShadow:
                                        "0 6px 20px rgba(15,23,42,.06)"
                                }
                            }}
                        >

                            {/* =================================
                                PROGRAM NAME
                            ================================= */}

                            <Stack
                                direction="row"
                                spacing={1}
                                sx={{ alignItems: "center",
                                    mb: 1.5
                                }}
                            >

                                <Box
                                    sx={{
                                        width: 10,
                                        height: 10,

                                        borderRadius:
                                            "50%",

                                        background:
                                            program.color,

                                        flexShrink: 0
                                    }}
                                />


                                <Typography
                                    variant="body2"
                                    fontWeight={700}
                                    noWrap
                                    sx={{
                                        overflow:
                                            "hidden",

                                        textOverflow:
                                            "ellipsis"
                                    }}
                                >
                                    {
                                        program.programName
                                    }
                                </Typography>

                            </Stack>


                            {/* =================================
                                GENDER + TOTAL
                            ================================= */}

                            <Stack
                                direction="row"
                                spacing={2}
                                sx={{
                                    mb: 1.5
                                }}
                            >

                                {/* MALE */}

                                <Box>

                                    <Typography
                                        variant="caption"
                                        color="text.secondary"
                                    >
                                        Male
                                    </Typography>

                                    <Typography
                                        sx={{
                                            fontSize:
                                                "1.15rem",

                                            fontWeight:
                                                800,

                                            color:
                                                "#2563eb"
                                        }}
                                    >
                                        {
                                            program.male
                                        }
                                    </Typography>

                                </Box>


                                {/* FEMALE */}

                                <Box>

                                    <Typography
                                        variant="caption"
                                        color="text.secondary"
                                    >
                                        Female
                                    </Typography>

                                    <Typography
                                        sx={{
                                            fontSize:
                                                "1.15rem",

                                            fontWeight:
                                                800,

                                            color:
                                                "#db2777"
                                        }}
                                    >
                                        {
                                            program.female
                                        }
                                    </Typography>

                                </Box>


                                {/* TOTAL */}

                                <Box>

                                    <Typography
                                        variant="caption"
                                        color="text.secondary"
                                    >
                                        Total
                                    </Typography>

                                    <Typography
                                        sx={{
                                            fontSize:
                                                "1.15rem",

                                            fontWeight:
                                                800,

                                            color:
                                                program.color
                                        }}
                                    >
                                        {
                                            program.beneficiaries
                                        }
                                    </Typography>

                                </Box>

                            </Stack>


                            <Divider
                                sx={{
                                    mb: 1.2
                                }}
                            />


                            {/* =================================
                                TARGET
                            ================================= */}

                            <Stack sx={{ justifyContent: "space-between", alignItems: "center" }}
                                direction="row"
                            >

                                <Typography
                                    variant="caption"
                                    color="text.secondary"
                                >
                                    Target
                                </Typography>


                                <Typography
                                    variant="body2"
                                    fontWeight={800}
                                >
                                    {
                                        program.target
                                    }
                                </Typography>

                            </Stack>


                            {/* =================================
                                PERFORMANCE
                            ================================= */}

                            <Stack
                                direction="row"
                                sx={{ justifyContent: "space-between", alignItems: "center",
                                    mt: 0.5
                                }}
                            >

                                <Typography
                                    variant="caption"
                                    color="text.secondary"
                                >
                                    Achievement
                                </Typography>


                                <Typography
                                    variant="caption"
                                    fontWeight={800}
                                    sx={{
                                        color:
                                            program.color
                                    }}
                                >
                                    {
                                        program.target > 0
                                            ? `${Math.min(
                                                100,
                                                Math.round(
                                                    (
                                                        program.beneficiaries /
                                                        program.target
                                                    ) * 100
                                                )
                                            )}%`
                                            : "0%"
                                    }
                                </Typography>

                            </Stack>

                        </Box>

                    )
                )}

            </Box>

        </Box>

    );

};


export default BeneficiaryByProgram;