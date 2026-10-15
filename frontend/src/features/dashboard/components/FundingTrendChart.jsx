import {
    Box,
    Typography
} from "@mui/material";

import {
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer
} from "recharts";


const FundingTrendChart = ({
    data = []
}) => {


    const chartData =
        Array.isArray(data)
            ? data.map((item) => ({
                ...item,

                amount:
                    Number(
                        item.amount || 0
                    )
            }))
            : [];


    // ==========================================
    // EMPTY STATE
    // ==========================================

    if (!chartData.length) {

        return (

            <Box
                sx={{
                    height: 300,

                    display: "flex",

                    alignItems:
                        "center",

                    justifyContent:
                        "center",

                    textAlign: "center"
                }}
            >

                <Box>

                    <Typography
                        fontWeight={700}
                        color="text.secondary"
                    >
                        No funding data available
                    </Typography>

                    <Typography
                        variant="body2"
                        color="text.disabled"
                        sx={{
                            mt: 0.5
                        }}
                    >
                        Funding trends will appear here.
                    </Typography>

                </Box>

            </Box>

        );

    }


    // ==========================================
    // FORMAT NUMBER
    // ==========================================

    const formatAmount = (
        value
    ) => {

        if (
            typeof value !==
            "number"
        ) {

            return value;

        }

        return new Intl.NumberFormat(
            "en-US",
            {
                maximumFractionDigits: 0
            }
        ).format(value);

    };


    return (

        <ResponsiveContainer
            width="100%"
            height={300}
        >

            <LineChart
                data={chartData}

                margin={{
                    top: 15,
                    right: 15,
                    left: -15,
                    bottom: 5
                }}
            >

                {/* =================================
                    GRID
                ================================= */}

                <CartesianGrid
                    strokeDasharray="3 3"
                    vertical={false}
                    stroke="#e2e8f0"
                />


                {/* =================================
                    X AXIS
                ================================= */}

                <XAxis
                    dataKey="month"

                    axisLine={false}

                    tickLine={false}

                    tick={{
                        fontSize: 11,
                        fill: "#64748b"
                    }}

                    dy={8}
                />


                {/* =================================
                    Y AXIS
                ================================= */}

                <YAxis
                    axisLine={false}

                    tickLine={false}

                    tick={{
                        fontSize: 11,
                        fill: "#64748b"
                    }}

                    tickFormatter={(
                        value
                    ) => {

                        if (
                            value >=
                            1000000
                        ) {

                            return `${(
                                value /
                                1000000
                            ).toFixed(1)}M`;

                        }

                        if (
                            value >=
                            1000
                        ) {

                            return `${(
                                value /
                                1000
                            ).toFixed(0)}K`;

                        }

                        return value;

                    }}
                />


                {/* =================================
                    TOOLTIP
                ================================= */}

                <Tooltip
                    cursor={{
                        stroke:
                            "#86b99a",

                        strokeWidth: 1,

                        strokeDasharray:
                            "4 4"
                    }}

                    contentStyle={{
                        borderRadius: 12,

                        border:
                            "1px solid #e2e8f0",

                        backgroundColor:
                            "#ffffff",

                        boxShadow:
                            "0 10px 30px rgba(15,23,42,0.10)"
                    }}

                    labelStyle={{
                        color:
                            "#0f172a",

                        fontWeight: 700,

                        marginBottom: 5
                    }}

                    formatter={(
                        value
                    ) => [
                        formatAmount(
                            Number(value)
                        ),
                        "Funding"
                    ]}
                />


                {/* =================================
                    FUNDING LINE
                ================================= */}

                <Line
                    type="monotone"

                    dataKey="amount"

                    stroke="#166534"

                    strokeWidth={3}

                    dot={{
                        r: 4,

                        fill:
                            "#ffffff",

                        stroke:
                            "#166534",

                        strokeWidth: 2
                    }}

                    activeDot={{
                        r: 6,

                        fill:
                            "#166534",

                        stroke:
                            "#ffffff",

                        strokeWidth: 2
                    }}

                    connectNulls

                />

            </LineChart>

        </ResponsiveContainer>

    );

};


export default FundingTrendChart;