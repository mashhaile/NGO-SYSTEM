import {
    useEffect,
    useState
} from "react";


import {
    Box,
    Typography,
    Paper,
    Grid,
    CircularProgress,
    Alert,
    Chip,
    Divider,
    LinearProgress
} from "@mui/material";


import {
    Business,
    CheckCircle,
    Block,
    People,
    Group,
    VolunteerActivism,
    Assignment,
    Subscriptions,
    Warning,
    TrendingUp
} from "@mui/icons-material";


import {
    getPlatformAnalyticsService
} from "../services/superAdminAnalyticsService";
import { formatDateTime } from "../../../utils/date";


// =====================================================
// STAT CARD
// =====================================================

const StatCard = ({
    title,
    value,
    subtitle,
    icon,
    iconColor = "primary",
    trend
}) => {

    const iconBackgrounds = {

        primary: "#EEF4FF",
        success: "#ECFDF3",
        warning: "#FFF7E6",
        error: "#FEF2F2",
        info: "#EFF8FF",
        secondary: "#F5F3FF"

    };


    const iconColors = {

        primary: "#2563EB",
        success: "#16A34A",
        warning: "#D97706",
        error: "#DC2626",
        info: "#0284C7",
        secondary: "#7C3AED"

    };


    return (

        <Paper
            elevation={0}
            sx={{
                height: "100%",
                p: 2.5,
                border: "1px solid #E5E7EB",
                borderRadius: 3,
                backgroundColor: "#FFFFFF",
                transition: "all 0.2s ease",
                "&:hover": {
                    transform: "translateY(-2px)",
                    boxShadow: "0 8px 24px rgba(15, 23, 42, 0.08)"
                }
            }}
        >

            <Box
                sx={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "flex-start"
                }}
            >

                <Box>

                    <Typography
                        variant="body2"
                        sx={{
                            color: "#64748B",
                            fontWeight: 500,
                            mb: 1
                        }}
                    >
                        {title}
                    </Typography>


                    <Typography
                        variant="h4"
                        sx={{
                            fontWeight: 800,
                            color: "#0F172A",
                            lineHeight: 1.1
                        }}
                    >
                        {value ?? 0}
                    </Typography>


                    {
                        subtitle && (

                            <Typography
                                variant="caption"
                                sx={{
                                    display: "block",
                                    mt: 1,
                                    color: "#94A3B8"
                                }}
                            >
                                {subtitle}
                            </Typography>

                        )
                    }


                    {
                        trend && (

                            <Typography
                                variant="caption"
                                sx={{
                                    display: "block",
                                    mt: 1,
                                    color: "#16A34A",
                                    fontWeight: 600
                                }}
                            >
                                {trend}
                            </Typography>

                        )
                    }

                </Box>


                <Box
                    sx={{
                        width: 48,
                        height: 48,
                        borderRadius: 2.5,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        backgroundColor:
                            iconBackgrounds[iconColor] ||
                            iconBackgrounds.primary,
                        color:
                            iconColors[iconColor] ||
                            iconColors.primary
                    }}
                >

                    {icon}

                </Box>

            </Box>

        </Paper>

    );

};


// =====================================================
// SECTION HEADER
// =====================================================

const SectionHeader = ({
    title,
    subtitle,
    icon
}) => {

    return (

        <Box
            sx={{
                display: "flex",
                alignItems: "center",
                gap: 1.5,
                mb: 2.5
            }}
        >

            {
                icon && (

                    <Box
                        sx={{
                            width: 36,
                            height: 36,
                            borderRadius: 2,
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            backgroundColor: "#F1F5F9",
                            color: "#475569"
                        }}
                    >
                        {icon}
                    </Box>

                )
            }


            <Box>

                <Typography
                    variant="h6"
                    sx={{
                        fontWeight: 750,
                        color: "#0F172A"
                    }}
                >
                    {title}
                </Typography>


                {
                    subtitle && (

                        <Typography
                            variant="caption"
                            sx={{
                                color: "#94A3B8"
                            }}
                        >
                            {subtitle}
                        </Typography>

                    )
                }

            </Box>

        </Box>

    );

};


// =====================================================
// STATUS CHIP
// =====================================================

const StatusChip = ({
    status
}) => {

    const normalized =
        String(status || "unknown")
            .toLowerCase();


    const colorMap = {

        active: "success",
        suspended: "warning",
        inactive: "default",
        deleted: "error",
        cancelled: "error",
        expired: "error",
        pending: "warning",
        trial: "info",
        none: "default"

    };


    return (

        <Chip
            size="small"
            label={
                normalized
                    .charAt(0)
                    .toUpperCase() +
                normalized.slice(1)
            }
            color={
                colorMap[normalized] ||
                "default"
            }
            sx={{
                fontWeight: 600
            }}
        />

    );

};


// =====================================================
// HELPER
// =====================================================

const formatStatus = (
    value
) => {

    if (!value) {

        return "Unknown";

    }


    const text =
        String(value);


    return (
        text.charAt(0).toUpperCase() +
        text.slice(1)
    );

};


// =====================================================
// PAGE
// =====================================================

const SuperAdminDashboardPage = () => {

    const [
        analytics,
        setAnalytics
    ] = useState(null);


    const [
        loading,
        setLoading
    ] = useState(true);


    const [
        error,
        setError
    ] = useState("");


    // =================================================
    // LOAD ANALYTICS
    // =================================================

    useEffect(() => {

        const loadAnalytics = async () => {

            try {

                setLoading(true);

                setError("");


                const response =
                    await getPlatformAnalyticsService();


                const data =
                    response?.data?.data ||
                    response?.data ||
                    response;


                setAnalytics(
                    data
                );

            }

            catch (err) {

                console.error(
                    "SUPER ADMIN ANALYTICS ERROR:",
                    err
                );


                setError(
                    err?.response?.data?.message ||
                    err?.message ||
                    "Failed to load platform analytics."
                );

            }

            finally {

                setLoading(false);

            }

        };


        loadAnalytics();

    }, []);


    // =================================================
    // LOADING
    // =================================================

    if (loading) {

        return (
            <Box
                sx={{
                    minHeight: "60vh",
                    display: "flex",
                    flexDirection: "column",
                    alignItems: "center",
                    justifyContent: "center",
                    gap: 2
                }}
            >

                <CircularProgress
                    size={38}
                />

                <Typography
                    variant="body2"
                    sx={{
                        color: "text.secondary"
                    }}
                >
                    Loading platform analytics...
                </Typography>

            </Box>
        );

    }


    // =================================================
    // ERROR
    // =================================================

    if (error) {

        return (

            <Box
                sx={{
                    p: {
                        xs: 2,
                        md: 3
                    }
                }}
            >

                <Alert
                    severity="error"
                    sx={{
                        borderRadius: 2
                    }}
                >
                    {error}
                </Alert>

            </Box>

        );

    }


    // =================================================
    // SAFE DATA
    // =================================================

    const organizations =
        analytics?.organizations || {};


    const subscriptions =
        analytics?.subscriptions || {};


    const platformHealth =
        analytics?.platformHealth || {};


    const topOrganizations =
        Array.isArray(
            analytics?.topOrganizations
        )
            ? analytics.topOrganizations
            : [];


    const recentActivities =
        Array.isArray(
            analytics?.recentActivities
        )
            ? analytics.recentActivities
            : [];


    const totalOrganizations =
        organizations.total || 0;


    const activeOrganizations =
        organizations.active || 0;


    const organizationPercentage =
        totalOrganizations > 0
            ? Math.round(
                (
                    activeOrganizations /
                    totalOrganizations
                ) * 100
            )
            : 0;


    // =================================================
    // RENDER
    // =================================================

    return (
        <Box
            sx={{
                minHeight: "100%",
                backgroundColor: "#F8FAFC",
                p: {
                    xs: 2,
                    sm: 2.5,
                    md: 3
                }
            }}
        >

            {/* =========================================
                HEADER
            ========================================= */}

            <Box
                sx={{
                    mb: 3
                }}
            >

                <Typography
                    variant="h4"
                    sx={{
                        fontWeight: 800,
                        color: "#0F172A",
                        letterSpacing: "-0.5px"
                    }}
                >
                    Super Admin Dashboard
                </Typography>


                <Typography
                    sx={{
                        mt: 0.5,
                        color: "#64748B"
                    }}
                >
                    Monitor your entire NGO SaaS platform
                    from one place.
                </Typography>

            </Box>

            {/* =========================================
                ORGANIZATION OVERVIEW
            ========================================= */}

            <Box
                sx={{
                    mb: 3
                }}
            >

                <SectionHeader
                    title="Organization Overview"
                    subtitle="Platform organization status"
                    icon={
                        <Business
                            fontSize="small"
                        />
                    }
                />


                <Grid
                    container
                    spacing={2}
                >

                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}
                    >

                        <StatCard
                            title="Organizations"
                            value={
                                organizations.total
                            }
                            subtitle="Total organizations"
                            icon={
                                <Business />
                            }
                            iconColor="primary"
                        />

                    </Grid>


                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}
                    >

                        <StatCard
                            title="Active"
                            value={
                                organizations.active
                            }
                            subtitle="Currently active"
                            icon={
                                <CheckCircle />
                            }
                            iconColor="success"
                        />

                    </Grid>
                    
<Grid
    size={{ xs: 12, sm: 6, md: 3 }}
>

    <StatCard
        title="Inactive"
        value={
            organizations.inactive
        }
        subtitle="Currently inactive"
        icon={
            <Block />
        }
        iconColor="secondary"
    />

</Grid>



                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}
                    >

                        <StatCard
                            title="Suspended"
                            value={
                                organizations.suspended
                            }
                            subtitle="Require attention"
                            icon={
                                <Warning />
                            }
                            iconColor="warning"
                        />

                    </Grid>


                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}
                    >

                        <StatCard
                            title="Deleted"
                            value={
                                organizations.deleted
                            }
                            subtitle="Deleted organizations"
                            icon={
                                <Block />
                            }
                            iconColor="error"
                        />

                    </Grid>

                </Grid>

            </Box>

            {/* =========================================
                PLATFORM OVERVIEW
            ========================================= */}

            <Box
                sx={{
                    mb: 3
                }}
            >

                <SectionHeader
                    title="Platform Overview"
                    subtitle="Key platform-wide metrics"
                />


                <Grid
                    container
                    spacing={2}
                >

                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}
                    >

                        <StatCard
                            title="Users"
                            value={
                                analytics?.users
                            }
                            subtitle="Platform users"
                            icon={
                                <People />
                            }
                            iconColor="primary"
                        />

                    </Grid>


                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}
                    >

                        <StatCard
                            title="Beneficiaries"
                            value={
                                analytics?.beneficiaries
                            }
                            subtitle="People served"
                            icon={
                                <Group />
                            }
                            iconColor="info"
                        />

                    </Grid>


                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}
                    >

                        <StatCard
                            title="Donors"
                            value={
                                analytics?.donors
                            }
                            subtitle="Registered donors"
                            icon={
                                <VolunteerActivism />
                            }
                            iconColor="success"
                        />

                    </Grid>


                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}
                    >

                        <StatCard
                            title="Programs"
                            value={
                                analytics?.programs
                            }
                            subtitle="Active platform programs"
                            icon={
                                <Assignment />
                            }
                            iconColor="secondary"
                        />

                    </Grid>

                </Grid>

            </Box>

            {/* =========================================
                SUBSCRIPTIONS
            ========================================= */}

            <Box
                sx={{
                    mb: 3
                }}
            >

                <SectionHeader
                    title="Subscription Overview"
                    subtitle="Monitor platform subscription health"
                    icon={
                        <Subscriptions
                            fontSize="small"
                        />
                    }
                />


                <Grid
                    container
                    spacing={2}
                >

                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}
                    >

                        <StatCard
                            title="Active"
                            value={
                                subscriptions.active
                            }
                            subtitle="Active subscriptions"
                            icon={
                                <CheckCircle />
                            }
                            iconColor="success"
                        />

                    </Grid>


                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}
                    >

                        <StatCard
                            title="Expired"
                            value={
                                subscriptions.expired
                            }
                            subtitle="Expired subscriptions"
                            icon={
                                <Warning />
                            }
                            iconColor="error"
                        />

                    </Grid>


                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}
                    >

                        <StatCard
                            title="Pending"
                            value={
                                subscriptions.pending
                            }
                            subtitle="Pending subscriptions"
                            icon={
                                <Subscriptions />
                            }
                            iconColor="warning"
                        />

                    </Grid>


                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}
                    >

                        <StatCard
                            title="No Subscription"
                            value={
                                platformHealth
                                    .organizationsWithoutSubscription
                            }
                            subtitle="Organizations without plan"
                            icon={
                                <Warning />
                            }
                            iconColor="warning"
                        />

                    </Grid>

                </Grid>

            </Box>

            {/* =========================================
                MAIN CONTENT
            ========================================= */}

            <Grid
                container
                spacing={3}
            >

                {/* =====================================
                    TOP ORGANIZATIONS
                ===================================== */}

                <Grid
                    size={{ xs: 12, lg: 8 }}
                >

                    <Paper
                        elevation={0}
                        sx={{
                            p: 3,
                            borderRadius: 3,
                            border: "1px solid #E5E7EB",
                            backgroundColor: "#FFFFFF"
                        }}
                    >

                        <SectionHeader
                            title="Top Organizations"
                            subtitle="Organizations with the highest beneficiary activity"
                            icon={
                                <TrendingUp
                                    fontSize="small"
                                />
                            }
                        />


                        {
                            topOrganizations.length === 0

                                ? (

                                    <Typography
                                        sx={{
                                            color: "text.secondary"
                                        }}
                                    >
                                        No organization data available.
                                    </Typography>

                                )

                                : (

                                    <Box>

                                        {
                                            topOrganizations.map(
                                                (
                                                    organization,
                                                    index
                                                ) => (

                                                    <Box
                                                        key={
                                                            organization?.id ||
                                                            index
                                                        }
                                                        sx={{
                                                            py: 1.75,
                                                            borderBottom:
                                                                index <
                                                                topOrganizations.length - 1
                                                                    ? "1px solid #E5E7EB"
                                                                    : "none"
                                                        }}
                                                    >

                                                        <Box
                                                            sx={{
                                                                display: "flex",
                                                                justifyContent: "space-between",
                                                                alignItems: "center",
                                                                gap: 2
                                                            }}
                                                        >

                                                            <Box
                                                                sx={{
                                                                    minWidth: 0
                                                                }}
                                                            >

                                                                <Box
                                                                    sx={{
                                                                        display: "flex",
                                                                        alignItems: "center",
                                                                        gap: 1
                                                                    }}
                                                                >

                                                                    <Box
                                                                        sx={{
                                                                            width: 30,
                                                                            height: 30,
                                                                            borderRadius: 1.5,
                                                                            backgroundColor: "#F1F5F9",
                                                                            display: "flex",
                                                                            alignItems: "center",
                                                                            justifyContent: "center",
                                                                            fontSize: 13,
                                                                            fontWeight: 700,
                                                                            color: "#475569"
                                                                        }}
                                                                    >
                                                                        {index + 1}
                                                                    </Box>


                                                                    <Typography
                                                                        sx={{
                                                                            fontWeight: 700,
                                                                            color: "#0F172A"
                                                                        }}
                                                                    >
                                                                        {
                                                                            organization?.name ||
                                                                            "Unnamed Organization"
                                                                        }
                                                                    </Typography>

                                                                </Box>


                                                                <Typography
                                                                    variant="caption"
                                                                    sx={{
                                                                        display: "block",
                                                                        mt: 0.75,
                                                                        ml: 5,
                                                                        color: "#64748B"
                                                                    }}
                                                                >

                                                                    Users:{" "}
                                                                    {
                                                                        organization?.users ||
                                                                        0
                                                                    }

                                                                    {"  •  "}

                                                                    Beneficiaries:{" "}
                                                                    {
                                                                        organization?.beneficiaries ||
                                                                        0
                                                                    }

                                                                </Typography>

                                                            </Box>


                                                            <Box
                                                                sx={{
                                                                    display: "flex",
                                                                    alignItems: "center",
                                                                    gap: 1,
                                                                    flexShrink: 0
                                                                }}
                                                            >

                                                                <StatusChip
                                                                    status={
                                                                        organization?.organizationStatus
                                                                    }
                                                                />


                                                                <Chip
                                                                    size="small"
                                                                    variant="outlined"
                                                                    label={
                                                                        formatStatus(
                                                                            organization?.subscriptionStatus
                                                                        )
                                                                    }
                                                                    sx={{
                                                                        fontWeight: 600,
                                                                        borderColor: "#CBD5E1",
                                                                        color: "#475569"
                                                                    }}
                                                                />

                                                            </Box>

                                                        </Box>

                                                    </Box>

                                                )
                                            )
                                        }

                                    </Box>

                                )
                        }

                    </Paper>

                </Grid>


                {/* =====================================
                    PLATFORM HEALTH
                ===================================== */}

                <Grid
                    size={{ xs: 12, lg: 4 }}
                >

                    <Paper
                        elevation={0}
                        sx={{
                            p: 3,
                            borderRadius: 3,
                            border: "1px solid #E5E7EB",
                            backgroundColor: "#FFFFFF"
                        }}
                    >

                        <SectionHeader
                            title="Platform Health"
                            subtitle="Current platform status"
                        />


                        <Box
                            sx={{
                                mb: 2
                            }}
                        >

                            <Box
                                sx={{
                                    display: "flex",
                                    justifyContent: "space-between",
                                    mb: 1
                                }}
                            >

                                <Typography
                                    variant="body2"
                                    sx={{
                                        color: "#475569",
                                        fontWeight: 600
                                    }}
                                >
                                    Active Organizations
                                </Typography>


                                <Typography
                                    variant="body2"
                                    sx={{
                                        fontWeight: 700,
                                        color: "#0F172A"
                                    }}
                                >
                                    {organizationPercentage}%
                                </Typography>

                            </Box>


                            <LinearProgress
                                variant="determinate"
                                value={
                                    organizationPercentage
                                }
                                sx={{
                                    height: 7,
                                    borderRadius: 10,
                                    backgroundColor: "#E2E8F0",
                                    "& .MuiLinearProgress-bar": {
                                        borderRadius: 10
                                    }
                                }}
                            />

                        </Box>


                        <Divider
                            sx={{
                                my: 2
                            }}
                        />


                        <Box
                            sx={{
                                display: "flex",
                                justifyContent: "space-between",
                                py: 1
                            }}
                        >

                            <Typography
                                sx={{
                                    color: "text.secondary"
                                }}
                            >
                                Active subscriptions
                            </Typography>


                            <Typography
                                sx={{
                                    fontWeight: 700
                                }}
                            >
                                {
                                    platformHealth
                                        .activeSubscriptions ||
                                    0
                                }
                            </Typography>

                        </Box>


                        <Box
                            sx={{
                                display: "flex",
                                justifyContent: "space-between",
                                py: 1
                            }}
                        >

                            <Typography
                                sx={{
                                    color: "text.secondary"
                                }}
                            >
                                Expired subscriptions
                            </Typography>


                            <Typography
                                sx={{
                                    fontWeight: 700,
                                    color:
                                        platformHealth.expiredSubscriptions > 0
                                            ? "#DC2626"
                                            : "#0F172A"
                                }}
                            >
                                {
                                    platformHealth
                                        .expiredSubscriptions ||
                                    0
                                }
                            </Typography>

                        </Box>


                        <Box
                            sx={{
                                display: "flex",
                                justifyContent: "space-between",
                                py: 1
                            }}
                        >

                            <Typography
                                sx={{
                                    color: "text.secondary"
                                }}
                            >
                                Without subscription
                            </Typography>


                            <Typography
                                sx={{
                                    fontWeight: 700,
                                    color:
                                        platformHealth
                                            .organizationsWithoutSubscription > 0
                                            ? "#D97706"
                                            : "#0F172A"
                                }}
                            >
                                {
                                    platformHealth
                                        .organizationsWithoutSubscription ||
                                    0
                                }
                            </Typography>

                        </Box>

                    </Paper>

                </Grid>


                {/* =====================================
                    RECENT ACTIVITIES
                ===================================== */}

                <Grid
                    size={{ xs: 12 }}
                >

                    <Paper
                        elevation={0}
                        sx={{
                            p: 3,
                            borderRadius: 3,
                            border: "1px solid #E5E7EB",
                            backgroundColor: "#FFFFFF"
                        }}
                    >

                        <SectionHeader
                            title="Recent Activities"
                            subtitle="Latest platform activity"
                        />


                        {
                            recentActivities.length === 0

                                ? (

                                    <Typography
                                        sx={{
                                            color: "text.secondary"
                                        }}
                                    >
                                        No recent activities found.
                                    </Typography>

                                )

                                : (

                                    <Box>

                                        {
                                            recentActivities.map(
                                                (
                                                    activity,
                                                    index
                                                ) => (

                                                    <Box
                                                        key={
                                                            activity?._id ||
                                                            activity?.id ||
                                                            index
                                                        }
                                                        sx={{
                                                            display: "flex",
                                                            alignItems: "center",
                                                            gap: 2,
                                                            py: 1.5,
                                                            borderBottom:
                                                                index <
                                                                recentActivities.length - 1
                                                                    ? "1px solid #E5E7EB"
                                                                    : "none"
                                                        }}
                                                    >

                                                        <Box
                                                            sx={{
                                                                width: 34,
                                                                height: 34,
                                                                borderRadius: "50%",
                                                                backgroundColor: "#EFF6FF",
                                                                color: "#2563EB",
                                                                display: "flex",
                                                                alignItems: "center",
                                                                justifyContent: "center",
                                                                flexShrink: 0
                                                            }}
                                                        >

                                                            <TrendingUp
                                                                fontSize="small"
                                                            />

                                                        </Box>


                                                        <Box
                                                            sx={{
                                                                flex: 1,
                                                                minWidth: 0
                                                            }}
                                                        >

                                                            <Typography
                                                                sx={{
                                                                    fontWeight: 600,
                                                                    color: "#334155"
                                                                }}
                                                            >
                                                                {
                                                                    activity?.action ||
                                                                    activity?.description ||
                                                                    "Platform activity"
                                                                }
                                                            </Typography>


                                                            <Typography
                                                                variant="caption"
                                                                sx={{
                                                                    color: "#94A3B8"
                                                                }}
                                                            >
                                                                {
                                                                    activity?.createdAt
                                                                        ? formatDateTime(activity.createdAt)
                                                                        : "—"
                                                                }
                                                            </Typography>

                                                        </Box>

                                                    </Box>

                                                )
                                            )
                                        }

                                    </Box>

                                )
                        }

                    </Paper>

                </Grid>

            </Grid>

        </Box>
    );

};


export default SuperAdminDashboardPage;
