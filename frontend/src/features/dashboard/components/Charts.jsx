import {
    Box,
    Paper,
    Typography,
    Stack
} from "@mui/material";

import {
    AccountBalance,
    VolunteerActivism
} from "@mui/icons-material";

import FundingTrendChart
    from "./FundingTrendChart";

import ServiceTrendChart
    from "./ServiceTrendChart";


const Charts = ({
    fundingTrend = [],
    serviceTrend = []
}) => {


    const cardSx = {
        height: "100%",

        p: {
            xs: 2,
            sm: 2.5,
            md: 3
        },

        borderRadius: 4,

        border:
            "1px solid #e2e8f0",

        backgroundColor:
            "#ffffff",

        boxShadow:
            "0 6px 24px rgba(15,23,42,0.05)",

        transition:
            "all .2s ease",

        "&:hover": {
            boxShadow:
                "0 10px 30px rgba(15,23,42,0.08)"
        }
    };


    const iconBoxSx = {
        width: 42,

        height: 42,

        borderRadius: 2.5,

        display: "flex",

        alignItems: "center",

        justifyContent: "center",

        backgroundColor:
            "#e8f3eb",

        color:
            "#166534",

        flexShrink: 0
    };


    return (

        <Box
            sx={{
                display: "grid",

                gridTemplateColumns: {
                    xs: "1fr",
                    lg: "1fr 1fr"
                },

                gap: {
                    xs: 2,
                    md: 3
                }
            }}
        >

            {/* =================================================
                FUNDING
            ================================================= */}

            <Paper
                elevation={0}
                sx={cardSx}
            >

                <Stack
                    direction="row"
                    spacing={1.5}
                    sx={{ alignItems: "center",
                        mb: 3
                    }}
                >

                    <Box
                        sx={iconBoxSx}
                    >

                        <AccountBalance />

                    </Box>


                    <Box>

                        <Typography
                            variant="h6"
                            fontWeight={800}
                            sx={{
                                color:
                                    "#0f172a",

                                lineHeight: 1.2
                            }}
                        >
                            Funding Trend
                        </Typography>


                        <Typography
                            variant="body2"
                            color="text.secondary"
                            sx={{
                                mt: 0.4
                            }}
                        >
                            Funding performance over time
                        </Typography>

                    </Box>

                </Stack>


                <FundingTrendChart
                    data={
                        fundingTrend
                    }
                />

            </Paper>


            {/* =================================================
                SERVICE DELIVERY
            ================================================= */}

            <Paper
                elevation={0}
                sx={cardSx}
            >

                <Stack
                    direction="row"
                    spacing={1.5}
                    sx={{ alignItems: "center",
                        mb: 3
                    }}
                >

                    <Box
                        sx={iconBoxSx}
                    >

                        <VolunteerActivism />

                    </Box>


                    <Box>

                        <Typography
                            variant="h6"
                            fontWeight={800}
                            sx={{
                                color:
                                    "#0f172a",

                                lineHeight: 1.2
                            }}
                        >
                            Service Delivery
                        </Typography>


                        <Typography
                            variant="body2"
                            color="text.secondary"
                            sx={{
                                mt: 0.4
                            }}
                        >
                            Service delivery performance
                        </Typography>

                    </Box>

                </Stack>


                <ServiceTrendChart
                    data={
                        serviceTrend
                    }
                />

            </Paper>

        </Box>

    );

};


export default Charts;