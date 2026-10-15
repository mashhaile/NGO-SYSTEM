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


const ServiceTrendChart = ({
    data = []
}) => {

    const chartData =
        Array.isArray(data)
            ? data.map((item) => ({
                ...item,

                month:
                    item.month ||
                    "",

                services:
                    Number(
                        item.services || 0
                    )
            }))
            : [];


    if (!chartData.length) {

        return (

            <Box
                sx={{
                    height: 300,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center"
                }}
            >

                <Typography
                    color="text.secondary"
                >
                    No service delivery data
                    available.
                </Typography>

            </Box>

        );

    }


    return (

        <Box
            sx={{
                width: "100%",
                height: 300
            }}
        >

            <ResponsiveContainer
                width="100%"
                height="100%"
            >

                <LineChart
                    data={chartData}
                    margin={{
                        top: 10,
                        right: 10,
                        left: -10,
                        bottom: 5
                    }}
                >

                    <CartesianGrid
                        strokeDasharray="3 3"
                        vertical={false}
                        stroke="#e5e7eb"
                    />


                    <XAxis
                        dataKey="month"
                        axisLine={false}
                        tickLine={false}
                        tick={{
                            fontSize: 12,
                            fill: "#64748b"
                        }}
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


                    <Tooltip
                        cursor={{
                            stroke:
                                "#15803d",
                            strokeWidth: 1,
                            strokeDasharray:
                                "4 4"
                        }}

                        contentStyle={{
                            borderRadius: 12,
                            border:
                                "1px solid #e5e7eb",
                            background:
                                "#ffffff",
                            boxShadow:
                                "0 8px 25px rgba(15,23,42,.10)"
                        }}

                        labelStyle={{
                            fontWeight: 700,
                            color: "#0f172a"
                        }}

                        formatter={(
                            value
                        ) => [
                            value,
                            "Services"
                        ]}
                    />


                    <Line
                        type="monotone"
                        dataKey="services"
                        name="Services"

                        stroke="#15803d"

                        strokeWidth={3}

                        dot={{
                            r: 4,
                            fill: "#15803d",
                            strokeWidth: 2,
                            stroke:
                                "#ffffff"
                        }}

                        activeDot={{
                            r: 6
                        }}

                        connectNulls
                    />

                </LineChart>

            </ResponsiveContainer>

        </Box>

    );

};


export default ServiceTrendChart;
