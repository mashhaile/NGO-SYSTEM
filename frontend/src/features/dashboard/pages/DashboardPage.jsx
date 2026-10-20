import {
    useEffect
} from "react";

import {
    useDispatch,
    useSelector
} from "react-redux";

import {
    Box,
    Typography,
    Grid,
    Paper,
    CircularProgress,
    Alert,
    Stack,
    Divider
} from "@mui/material";

import {
    AccountBalance,
    VolunteerActivism,
    PeopleAlt,
    TrendingUp,
    Insights,
    Groups
} from "@mui/icons-material";

import {
    getDashboardThunk
} from "../store";

import SummaryCards
    from "../components/SummaryCards";

import FundingTrendChart
    from "../components/FundingTrendChart";

import ServiceTrendChart
    from "../components/ServiceTrendChart";

import GenderChart
    from "../components/GenderChart";

import BeneficiaryByProgram
    from "../components/BeneficiaryByProgram";

import RecentActivity
    from "../components/RecentActivity";


const DashboardPage = () => {

    const dispatch =
        useDispatch();


    const {
        data,
        loading,
        error
    } = useSelector(
        state => state.dashboard
    );


    useEffect(() => {

        dispatch(
            getDashboardThunk()
        );

    }, [dispatch]);


    /* ======================================================
       LOADING
    ====================================================== */

    if (loading) {

        return (

            <Box
                sx={{
                    minHeight: "60vh",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center"
                }}
            >

                <Stack
                    spacing={2}
                    alignItems="center"
                >

                    <CircularProgress
                        size={40}
                        thickness={4}
                        color="success"
                    />

                    <Typography
                        variant="body2"
                        color="text.secondary"
                    >
                        Loading dashboard...
                    </Typography>

                </Stack>

            </Box>

        );

    }


    /* ======================================================
       ERROR
    ====================================================== */

    if (error) {

        return (

            <Box
                sx={{
                    width: "100%",
                    py: 2
                }}
            >

                <Alert
                    severity="error"
                    sx={{
                        borderRadius: 3
                    }}
                >

                    {error}

                </Alert>

            </Box>

        );

    }


    if (!data) {
        return null;
    }


    /* ======================================================
       DATA
    ====================================================== */

    const summary =
        data.summary || {};

    const charts =
        data.charts || {};

    const gender =
        data.genderDistribution || {
            male: 0,
            female: 0,
            total: 0
        };

    const beneficiariesByProgram =
        Array.isArray(
            charts.beneficiariesByProgram
        )
            ? charts.beneficiariesByProgram
            : [];


    /* ======================================================
       SHARED CARD STYLE
    ====================================================== */

    const cardSx = {

        height: "100%",

        // Lets charts shrink with their column instead of
        // stretching the page wider.

        minWidth: 0,

        borderRadius: 3,

        border:
            "1px solid",

        borderColor:
            "divider",

        backgroundColor:
            "background.paper",

        boxShadow:
            "0 4px 18px rgba(15, 23, 42, 0.045)",

        transition:
            "box-shadow 0.2s ease, transform 0.2s ease",

        "&:hover": {

            boxShadow:
                "0 8px 28px rgba(15, 23, 42, 0.07)"

        }

    };


    /* ======================================================
       SECTION HEADER
    ====================================================== */

    const SectionHeader = ({
        icon,
        title,
        subtitle
    }) => {

        return (

            <Stack
                direction="row"
                spacing={1.5}
                alignItems="center"
                sx={{
                    mb: 2.5
                }}
            >

                <Box
                    sx={{

                        width: 42,

                        height: 42,

                        borderRadius: 2.5,

                        display: "flex",

                        alignItems: "center",

                        justifyContent: "center",

                        backgroundColor:
                            "#f0fdf4",

                        color:
                            "primary.main",

                        flexShrink: 0

                    }}
                >

                    {icon}

                </Box>


                <Box
                    sx={{
                        minWidth: 0
                    }}
                >

                    <Typography
                        variant="h6"
                        sx={{
                            fontWeight: 800,
                            color:
                                "text.primary",
                            lineHeight: 1.2
                        }}
                    >

                        {title}

                    </Typography>


                    {subtitle && (

                        <Typography
                            variant="body2"
                            color="text.secondary"
                            sx={{
                                mt: 0.45
                            }}
                        >

                            {subtitle}

                        </Typography>

                    )}

                </Box>

            </Stack>

        );

    };


    /* ======================================================
       CHART HEADER
    ====================================================== */

    const ChartHeader = ({
        icon,
        title,
        subtitle
    }) => {

        return (

            <Stack
                direction="row"
                spacing={1.5}
                alignItems="center"
                sx={{
                    mb: 2.5
                }}
            >

                <Box
                    sx={{

                        width: 40,

                        height: 40,

                        borderRadius: 2.5,

                        display: "flex",

                        alignItems: "center",

                        justifyContent: "center",

                        backgroundColor:
                            "#f0fdf4",

                        color:
                            "primary.main"

                    }}
                >

                    {icon}

                </Box>


                <Box>

                    <Typography
                        fontWeight={800}
                    >

                        {title}

                    </Typography>


                    <Typography
                        variant="caption"
                        color="text.secondary"
                    >

                        {subtitle}

                    </Typography>

                </Box>

            </Stack>

        );

    };


    return (

        <Box
            sx={{

                width: "100%",

                pb: {
                    xs: 4,
                    md: 6
                }

            }}
        >

            {/* ==================================================
                DASHBOARD HEADER
            ================================================== */}

            <Box
                sx={{
                    mb: {
                        xs: 3,
                        md: 4
                    }
                }}
            >

                <Typography
                    sx={{

                        fontSize: {
                            xs: "1.65rem",
                            sm: "1.9rem",
                            md: "2.15rem"
                        },

                        fontWeight: 800,

                        color:
                            "text.primary",

                        letterSpacing:
                            "-0.025em",

                        lineHeight: 1.2

                    }}
                >

                    {data.title ||
                        "Organization Dashboard"}

                </Typography>


                <Typography
                    color="text.secondary"
                    sx={{

                        mt: 0.8,

                        maxWidth: 720,

                        lineHeight: 1.6

                    }}
                >

                    Monitor your organization's
                    programs, beneficiaries,
                    funding, services and impact
                    from one place.

                </Typography>

            </Box>


            {/* ==================================================
                SUMMARY CARDS
            ================================================== */}

            <Box
                sx={{
                    mb: {
                        xs: 4,
                        md: 5
                    }
                }}
            >

                <SummaryCards
                    summary={summary}
                />

            </Box>


            {/* ==================================================
                BENEFICIARY ANALYTICS
            ================================================== */}

            <Box
                sx={{
                    mb: {
                        xs: 4,
                        md: 5
                    }
                }}
            >

                <SectionHeader

                    icon={
                        <PeopleAlt
                            fontSize="small"
                        />
                    }

                    title="Beneficiary Analytics"

                    subtitle={
                        "Understand your beneficiary population and program reach."
                    }

                />


                <Grid
                    container
                    spacing={3}
                    alignItems="stretch"
                >

                    {/* ==========================================
                        GENDER
                    ========================================== */}

                    <Grid
                        size={{ xs: 12 }}
                        sx={{ minWidth: 0 }}
                    >

                        <Paper
                            elevation={0}
                            sx={{
                                ...cardSx,
                                p: {
                                    xs: 2,
                                    md: 3
                                }
                            }}
                        >

                            <ChartHeader

                                icon={
                                    <Groups
                                        fontSize="small"
                                    />
                                }

                                title="Gender Distribution"

                                subtitle={
                                    "Male and female beneficiaries"
                                }

                            />

                            <Divider
                                sx={{
                                    mb: 2
                                }}
                            />

                            <GenderChart
                                data={gender}
                            />

                        </Paper>

                    </Grid>


                    {/* ==========================================
                        PROGRAM REACH
                    ========================================== */}

                    <Grid
                        size={{ xs: 12 }}
                        sx={{ minWidth: 0 }}
                    >

                        <Paper
                            elevation={0}
                            sx={{
                                ...cardSx,
                                p: {
                                    xs: 2,
                                    md: 3
                                }
                            }}
                        >

                            <ChartHeader

                                icon={
                                    <TrendingUp
                                        fontSize="small"
                                    />
                                }

                                title="Beneficiaries by Program"

                                subtitle={
                                    "Program reach compared with target"
                                }

                            />

                            <Divider
                                sx={{
                                    mb: 2
                                }}
                            />

                            <BeneficiaryByProgram
                                data={
                                    beneficiariesByProgram
                                }
                            />

                        </Paper>

                    </Grid>

                </Grid>

            </Box>


            {/* ==================================================
                PROGRAM PERFORMANCE
            ================================================== */}

            <Box
                sx={{
                    mb: {
                        xs: 4,
                        md: 5
                    }
                }}
            >

                <SectionHeader

                    icon={
                        <Insights
                            fontSize="small"
                        />
                    }

                    title="Program Performance"

                    subtitle={
                        "Track financial support and service delivery over time."
                    }

                />


                <Grid
                    container
                    spacing={3}
                >

                    {/* ==========================================
                        FUNDING
                    ========================================== */}

                    <Grid
                        size={{ xs: 12, lg: 6 }}
                        sx={{ minWidth: 0 }}
                    >

                        <Paper
                            elevation={0}
                            sx={{
                                ...cardSx,
                                p: {
                                    xs: 2,
                                    md: 3
                                }
                            }}
                        >

                            <ChartHeader

                                icon={
                                    <AccountBalance
                                        fontSize="small"
                                    />
                                }

                                title="Funding Trend"

                                subtitle={
                                    "Financial support over time"
                                }

                            />

                            <Divider
                                sx={{
                                    mb: 2
                                }}
                            />

                            <FundingTrendChart
                                data={
                                    charts.fundingTrend ||
                                    []
                                }
                            />

                        </Paper>

                    </Grid>


                    {/* ==========================================
                        SERVICES
                    ========================================== */}

                    <Grid
                        size={{ xs: 12, lg: 6 }}
                        sx={{ minWidth: 0 }}
                    >

                        <Paper
                            elevation={0}
                            sx={{
                                ...cardSx,
                                p: {
                                    xs: 2,
                                    md: 3
                                }
                            }}
                        >

                            <ChartHeader

                                icon={
                                    <VolunteerActivism
                                        fontSize="small"
                                    />
                                }

                                title="Service Delivery"

                                subtitle={
                                    "Services delivered over time"
                                }

                            />

                            <Divider
                                sx={{
                                    mb: 2
                                }}
                            />

                            <ServiceTrendChart
                                data={
                                    charts.serviceTrend ||
                                    []
                                }
                            />

                        </Paper>

                    </Grid>

                </Grid>

            </Box>


            {/* ==================================================
                RECENT ACTIVITY
            ================================================== */}

            <Box>

                <SectionHeader

                    icon={
                        <PeopleAlt
                            fontSize="small"
                        />
                    }

                    title="Recent Activity"

                    subtitle={
                        "Latest beneficiary activity in your organization."
                    }

                />


                <Paper
                    elevation={0}
                    sx={{
                        ...cardSx
                    }}
                >

                    <RecentActivity
                        activities={
                            data.recentActivity ||
                            []
                        }
                    />

                </Paper>

            </Box>

        </Box>

    );

};


export default DashboardPage;