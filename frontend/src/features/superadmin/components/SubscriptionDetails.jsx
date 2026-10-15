import {
    Box,
    Typography,
    Paper,
    Grid,
    Chip,
    Divider
} from "@mui/material";


// =====================================================
// COMPONENT
// =====================================================

const SubscriptionDetails = ({
    subscription,
    usage
}) => {

    // =================================================
    // NO SUBSCRIPTION
    // =================================================

    if (!subscription) {

        return (

            <Paper
                sx={{
                    p: 3,
                    mb: 3
                }}
            >

                <Typography
                    variant="h6"
                    sx={{
                        fontWeight: 700,
                        mb: 1
                    }}
                >
                    Subscription
                </Typography>


                <Typography
                    color="text.secondary"
                >
                    This organization does not have an active
                    subscription.
                </Typography>

            </Paper>

        );

    }


    // =================================================
    // HELPERS
    // =================================================

    const planName =
        subscription?.planSnapshot?.name ||
        subscription?.plan?.name ||
        "Unknown";


    const status =
        subscription?.status ||
        "unknown";


    const normalizedStatus =
        String(status).toLowerCase();


    const formatDate = (
        value
    ) => {

        if (!value) {

            return "—";

        }


        const date =
            new Date(value);


        if (
            Number.isNaN(
                date.getTime()
            )
        ) {

            return "—";

        }


        return date.toLocaleDateString(
            undefined,
            {
                year: "numeric",
                month: "short",
                day: "numeric"
            }
        );

    };


    const getEndDateDisplay = () => {

        // =============================================
        // TRIALING
        // =============================================

        if (
            normalizedStatus ===
            "trialing"
        ) {

            return (
                formatDate(
                    subscription?.trialEndDate
                )
            );

        }


        // =============================================
        // LIFETIME
        // =============================================

        if (
            !subscription?.endDate
        ) {

            return "Lifetime";

        }


        // =============================================
        // NORMAL SUBSCRIPTION
        // =============================================

        return (
            formatDate(
                subscription.endDate
            )
        );

    };


    const formatUsageName = (
        value
    ) => {

        return String(value)
            .replace(
                /([A-Z])/g,
                " $1"
            )
            .replace(
                /^./,
                letter =>
                    letter.toUpperCase()
            );

    };


    const getStatusColor = (
        value
    ) => {

        switch (
            String(value).toLowerCase()
        ) {

            case "active":
                return "success";

            case "trial":
            case "trialing":
                return "info";

            case "cancelled":
                return "error";

            case "suspended":
                return "warning";

            case "expired":
                return "error";

            default:
                return "default";

        }

    };


    // =================================================
    // RENDER
    // =================================================

    return (

        <Paper
            sx={{
                p: 3,
                mb: 3
            }}
        >

            {/* =========================================
                HEADER
            ========================================= */}

            <Typography
                variant="h6"
                sx={{
                    fontWeight: 700,
                    mb: 2
                }}
            >
                Subscription Details
            </Typography>


            {/* =========================================
                SUBSCRIPTION INFORMATION
            ========================================= */}

            <Grid
                container
                spacing={3}
            >

                <Grid
                    item
                    xs={12}
                    sm={6}
                    md={3}
                >

                    <Typography
                        variant="body2"
                        color="text.secondary"
                    >
                        Plan
                    </Typography>


                    <Typography
                        sx={{
                            fontWeight: 700
                        }}
                    >
                        {planName}
                    </Typography>

                </Grid>


                <Grid
                    item
                    xs={12}
                    sm={6}
                    md={3}
                >

                    <Typography
                        variant="body2"
                        color="text.secondary"
                    >
                        Status
                    </Typography>


                    <Chip
                        size="small"
                        label={status}
                        color={
                            getStatusColor(
                                status
                            )
                        }
                    />

                </Grid>


                <Grid
                    item
                    xs={12}
                    sm={6}
                    md={3}
                >

                    <Typography
                        variant="body2"
                        color="text.secondary"
                    >
                        Start Date
                    </Typography>


                    <Typography
                        sx={{
                            fontWeight: 600
                        }}
                    >
                        {
                            formatDate(
                                subscription.startDate
                            )
                        }
                    </Typography>

                </Grid>


                <Grid
                    item
                    xs={12}
                    sm={6}
                    md={3}
                >

                    <Typography
                        variant="body2"
                        color="text.secondary"
                    >
                        {
                            normalizedStatus ===
                            "trialing"
                                ? "Trial End Date"
                                : "End Date"
                        }
                    </Typography>


                    <Typography
                        sx={{
                            fontWeight: 600
                        }}
                    >
                        {
                            getEndDateDisplay()
                        }
                    </Typography>

                </Grid>

            </Grid>


            {/* =========================================
                PLAN LIMITS
            ========================================= */}

            {
                subscription?.planSnapshot?.limits && (

                    <>

                        <Divider
                            sx={{
                                my: 3
                            }}
                        />


                        <Typography
                            variant="h6"
                            sx={{
                                fontWeight: 700,
                                mb: 2
                            }}
                        >
                            Plan Limits
                        </Typography>


                        <Grid
                            container
                            spacing={2}
                        >

                            {
                                Object.entries(
                                    subscription
                                        .planSnapshot
                                        .limits
                                ).map(
                                    ([key, value]) => (

                                        <Grid
                                            item
                                            xs={12}
                                            sm={6}
                                            md={4}
                                            lg={3}
                                            key={key}
                                        >

                                            <Paper
                                                variant="outlined"
                                                sx={{
                                                    p: 2
                                                }}
                                            >

                                                <Typography
                                                    variant="body2"
                                                    color="text.secondary"
                                                >
                                                    {
                                                        formatUsageName(
                                                            key
                                                        )
                                                    }
                                                </Typography>


                                                <Typography
                                                    variant="h6"
                                                    sx={{
                                                        fontWeight: 700
                                                    }}
                                                >

                                                    {
                                                        value === -1
                                                            ? "Unlimited"
                                                            : value
                                                    }

                                                </Typography>

                                            </Paper>

                                        </Grid>

                                    )
                                )
                            }

                        </Grid>

                    </>

                )
            }


            {/* =========================================
                CURRENT USAGE
            ========================================= */}

            {
                usage && (

                    <>

                        <Divider
                            sx={{
                                my: 3
                            }}
                        />


                        <Typography
                            variant="h6"
                            sx={{
                                fontWeight: 700,
                                mb: 2
                            }}
                        >
                            Current Usage
                        </Typography>


                        <Grid
                            container
                            spacing={2}
                        >

                            {
                                Object.entries(
                                    usage
                                ).map(
                                    ([key, item]) => (

                                        <Grid
                                            item
                                            xs={12}
                                            sm={6}
                                            md={4}
                                            lg={3}
                                            key={key}
                                        >

                                            <Paper
                                                variant="outlined"
                                                sx={{
                                                    p: 2
                                                }}
                                            >

                                                <Typography
                                                    variant="body2"
                                                    color="text.secondary"
                                                >
                                                    {
                                                        formatUsageName(
                                                            key
                                                        )
                                                    }
                                                </Typography>


                                                <Typography
                                                    variant="h6"
                                                    sx={{
                                                        fontWeight: 700
                                                    }}
                                                >

                                                    {
                                                        item.used
                                                    }

                                                    {" / "}

                                                    {
                                                        item.unlimited
                                                            ? "Unlimited"
                                                            : item.limit
                                                    }

                                                </Typography>


                                                <Typography
                                                    variant="caption"
                                                    color="text.secondary"
                                                >

                                                    Remaining:{" "}

                                                    {
                                                        item.unlimited
                                                            ? "Unlimited"
                                                            : item.remaining
                                                    }

                                                </Typography>


                                                {
                                                    item.exceeded && (

                                                        <Box
                                                            sx={{
                                                                mt: 1
                                                            }}
                                                        >

                                                            <Chip
                                                                size="small"
                                                                color="error"
                                                                label="Limit exceeded"
                                                            />

                                                        </Box>

                                                    )
                                                }

                                            </Paper>

                                        </Grid>

                                    )
                                )
                            }

                        </Grid>

                    </>

                )
            }

        </Paper>

    );

};


export default SubscriptionDetails;
