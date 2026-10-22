import {
    Grid,
    Card,
    CardContent,
    Typography,
    Box
} from "@mui/material";

import {
    PeopleAlt,
    AccountBalance,
    VolunteerActivism,
    Business,
    Handshake,
    Payments
} from "@mui/icons-material";


// Received funding in other currencies, e.g. "+ EUR 15,000"
// (never added to the ETB figure)
const otherCurrencies = (byCurrency = {}) =>
    Object.entries(byCurrency)
        .filter(([currency, amount]) => currency !== "ETB" && amount)
        .map(([currency, amount]) => `+ ${currency} ${new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 }).format(amount)}`)
        .join("  ");

const SummaryCards = ({
    summary = {}
}) => {


    const cards = [

        {
            title: "Beneficiaries",
            value:
                summary.totalBeneficiaries || 0,
            icon: PeopleAlt,
            accent: "#166534",
            background: "#f0fdf4"
        },

        {
            title: "Programs",
            value:
                summary.totalPrograms || 0,
            icon: Business,
            accent: "#15803d",
            background: "#f0fdf4"
        },

        {
            title: "Donors",
            value:
                summary.totalDonors || 0,
            icon: Handshake,
            accent: "#047857",
            background: "#ecfdf5"
        },

        {
            title: "Total Funding (received)",
            value:
                summary.totalFunding || 0,
            prefix: "ETB ",
            caption:
                otherCurrencies(summary.fundingByCurrency),
            icon: AccountBalance,
            accent: "#065f46",
            background: "#ecfdf5"
        },

        {
            title: "Services",
            value:
                summary.totalServices || 0,
            icon: VolunteerActivism,
            accent: "#0f766e",
            background: "#f0fdfa"
        },

        {
            title: "Service Value",
            value:
                summary.totalServiceValue || 0,
            icon: Payments,
            accent: "#166534",
            background: "#f0fdf4"
        }

    ];


    const formatValue = (
        value
    ) => {

        if (
            typeof value === "number"
        ) {

            // Short form for big numbers so they fit the
            // card (60,000,000 -> 60M); exact value on hover.

            return new Intl.NumberFormat(
                "en-US",
                Math.abs(value) >= 100000
                    ? {
                        notation: "compact",
                        maximumFractionDigits: 2
                    }
                    : {
                        maximumFractionDigits: 2
                    }
            ).format(value);

        }


        return value ?? 0;

    };


    return (

        <Grid
            container
            spacing={{
                xs: 2,
                sm: 2.5,
                md: 2.5
            }}
        >

            {
                cards.map(
                    (card) => {

                        const Icon =
                            card.icon;


                        return (

                            <Grid
                                size={{ xs: 12, sm: 6, md: 4, lg: 2 }}
                                sx={{ minWidth: 0 }}
                                key={
                                    card.title
                                }
                            >

                                <Card
                                    elevation={0}
                                    sx={{
                                        height: "100%",
                                        minHeight: 150,

                                        borderRadius: 3,

                                        border:
                                            "1px solid",

                                        borderColor:
                                            "rgba(15, 23, 42, 0.08)",

                                        backgroundColor:
                                            "#ffffff",

                                        transition:
                                            "transform .2s ease, box-shadow .2s ease, border-color .2s ease",

                                        "&:hover":
                                            {
                                                transform:
                                                    "translateY(-3px)",

                                                borderColor:
                                                    card.accent,

                                                boxShadow:
                                                    "0 12px 28px rgba(15, 23, 42, 0.08)"
                                            }
                                    }}
                                >

                                    <CardContent
                                        sx={{
                                            p: {
                                                xs: 2,
                                                sm: 2.5
                                            },

                                            "&:last-child":
                                                {
                                                    pb: {
                                                        xs: 2,
                                                        sm: 2.5
                                                    }
                                                }
                                        }}
                                    >

                                        {/* =========================
                                            ICON
                                        ========================= */}

                                        <Box
                                            sx={{
                                                width: 44,
                                                height: 44,

                                                borderRadius: 2.5,

                                                display:
                                                    "flex",

                                                alignItems:
                                                    "center",

                                                justifyContent:
                                                    "center",

                                                backgroundColor:
                                                    card.background,

                                                color:
                                                    card.accent
                                            }}
                                        >

                                            <Icon
                                                sx={{
                                                    fontSize: 23
                                                }}
                                            />

                                        </Box>


                                        {/* =========================
                                            TITLE
                                        ========================= */}

                                        <Typography
                                            sx={{
                                                mt: 2,

                                                color:
                                                    "text.secondary",

                                                fontSize:
                                                    "0.78rem",

                                                fontWeight: 600,

                                                lineHeight: 1.3
                                            }}
                                        >

                                            {
                                                card.title
                                            }

                                        </Typography>


                                        {/* =========================
                                            VALUE
                                        ========================= */}

                                        <Typography
                                            sx={{
                                                mt: 0.5,

                                                fontSize: {
                                                    xs: "1.45rem",
                                                    sm: "1.55rem"
                                                },

                                                fontWeight: 800,

                                                color:
                                                    "#0f172a",

                                                letterSpacing:
                                                    "-0.02em",

                                                lineHeight: 1.2,

                                                whiteSpace:
                                                    "nowrap",

                                                overflow:
                                                    "hidden",

                                                textOverflow:
                                                    "ellipsis"
                                            }}
                                            title={
                                                typeof card.value === "number"
                                                    ? new Intl.NumberFormat("en-US").format(card.value)
                                                    : undefined
                                            }
                                        >

                                            {card.prefix && (
                                                <Box component="span" sx={{ fontSize: "0.7em", fontWeight: 700, mr: 0.5 }}>
                                                    {card.prefix.trim()}
                                                </Box>
                                            )}

                                            {
                                                formatValue(
                                                    card.value
                                                )
                                            }

                                        </Typography>

                                        {card.caption && (
                                            <Typography
                                                variant="caption"
                                                sx={{ color: "text.secondary", display: "block", mt: 0.25 }}
                                            >
                                                {card.caption}
                                            </Typography>
                                        )}


                                        {/* =========================
                                            ACCENT LINE
                                        ========================= */}

                                        <Box
                                            sx={{
                                                mt: 1.5,

                                                width: 28,
                                                height: 3,

                                                borderRadius: 10,

                                                backgroundColor:
                                                    card.accent
                                            }}
                                        />

                                    </CardContent>

                                </Card>

                            </Grid>

                        );

                    }
                )
            }

        </Grid>

    );

};


export default SummaryCards;