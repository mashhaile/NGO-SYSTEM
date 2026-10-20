import {
    Box,
    Typography,
    Stack
} from "@mui/material";

import {
    PieChart,
    Pie,
    Cell,
    ResponsiveContainer,
    Tooltip
} from "recharts";


const GenderChart = ({ data = {} }) => {

    const male =
        Number(data.male || 0);

    const female =
        Number(data.female || 0);

    const total =
        Number(
            data.total ||
            male + female
        );


    const malePercentage =
        total > 0
            ? Math.round((male / total) * 100)
            : 0;


    const femalePercentage =
        total > 0
            ? Math.round((female / total) * 100)
            : 0;


    const chartData = [

        {
            name: "Male",
            value: male
        },

        {
            name: "Female",
            value: female
        }

    ];


    const COLORS = [
        "#2563eb",
        "#db2777"
    ];


    return (
        <Box
            sx={{
                width: "100%"
            }}
        >

            <Stack sx={{ alignItems: "center" }}
                direction={{
                    xs: "column",
                    md: "row"
                }}
                spacing={4}
            >


                {/* ============================
                    DONUT CHART
                ============================ */}

                <Box
                    sx={{
                        width: {
                            xs: "100%",
                            md: 300
                        },

                        height: 280,

                        position: "relative"
                    }}
                >

                    <ResponsiveContainer
                        width="100%"
                        height="100%"
                    >

                        <PieChart>

                            <Pie
                                data={chartData}
                                dataKey="value"
                                nameKey="name"
                                cx="50%"
                                cy="50%"
                                innerRadius={75}
                                outerRadius={105}
                                paddingAngle={4}
                                stroke="none"
                            >

                                {chartData.map(
                                    (entry, index) => (

                                        <Cell
                                            key={
                                                entry.name
                                            }
                                            fill={
                                                COLORS[index]
                                            }
                                        />

                                    )
                                )}

                            </Pie>


                            <Tooltip
                                formatter={(
                                    value,
                                    name
                                ) => [
                                    `${value} beneficiaries`,
                                    name
                                ]}
                            />

                        </PieChart>

                    </ResponsiveContainer>


                    {/* CENTER */}

                    <Box
                        sx={{
                            position:
                                "absolute",

                            inset: 0,

                            display:
                                "flex",

                            flexDirection:
                                "column",

                            alignItems:
                                "center",

                            justifyContent:
                                "center",

                            pointerEvents:
                                "none"
                        }}
                    >

                        <Typography
                            variant="h4"
                            sx={{
                                fontWeight: 800
                            }}
                        >
                            {total}
                        </Typography>


                        <Typography
                            variant="body2"
                            sx={{
                                color: "text.secondary"
                            }}
                        >
                            Beneficiaries
                        </Typography>

                    </Box>

                </Box>


                {/* ============================
                    STATISTICS
                ============================ */}

                <Stack
                    spacing={2}
                    sx={{
                        flex: 1,
                        width: "100%"
                    }}
                >


                    {/* MALE */}

                    <Box
                        sx={{
                            p: 2,
                            borderRadius: 3,
                            background:
                                "#eff6ff",
                            border:
                                "1px solid #dbeafe"
                        }}
                    >

                        <Stack sx={{ justifyContent: "space-between", alignItems: "center" }}
                            direction="row"
                        >

                            <Stack sx={{ alignItems: "center" }}
                                direction="row"
                                spacing={1.5}
                            >

                                <Box
                                    sx={{
                                        width: 12,
                                        height: 12,
                                        borderRadius:
                                            "50%",
                                        background:
                                            "#2563eb"
                                    }}
                                />

                                <Typography
                                    sx={{
                                        fontWeight: 700
                                    }}
                                >
                                    Male
                                </Typography>

                            </Stack>


                            <Typography
                                variant="h6"
                                sx={{
                                    fontWeight: 800
                                }}
                            >
                                {male}
                            </Typography>

                        </Stack>


                        <Typography
                            variant="body2"
                            sx={{
                                color: "text.secondary",
                                mt: 0.5
                            }}>
                            {malePercentage}% of beneficiaries
                        </Typography>

                    </Box>


                    {/* FEMALE */}

                    <Box
                        sx={{
                            p: 2,
                            borderRadius: 3,
                            background:
                                "#fdf2f8",
                            border:
                                "1px solid #fbcfe8"
                        }}
                    >

                        <Stack sx={{ justifyContent: "space-between", alignItems: "center" }}
                            direction="row"
                        >

                            <Stack sx={{ alignItems: "center" }}
                                direction="row"
                                spacing={1.5}
                            >

                                <Box
                                    sx={{
                                        width: 12,
                                        height: 12,
                                        borderRadius:
                                            "50%",
                                        background:
                                            "#db2777"
                                    }}
                                />

                                <Typography
                                    sx={{
                                        fontWeight: 700
                                    }}
                                >
                                    Female
                                </Typography>

                            </Stack>


                            <Typography
                                variant="h6"
                                sx={{
                                    fontWeight: 800
                                }}
                            >
                                {female}
                            </Typography>

                        </Stack>


                        <Typography
                            variant="body2"
                            sx={{
                                color: "text.secondary",
                                mt: 0.5
                            }}>
                            {femalePercentage}% of beneficiaries
                        </Typography>

                    </Box>


                </Stack>

            </Stack>

        </Box>
    );

};


export default GenderChart;