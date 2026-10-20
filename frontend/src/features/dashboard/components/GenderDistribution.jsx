import {
    Box,
    Typography,
    Stack
} from "@mui/material";

import {
    PeopleAlt,
    Male,
    Female
} from "@mui/icons-material";


const GenderDistribution = ({
    data = {}
}) => {

    const male =
        Number(data.male || 0);

    const female =
        Number(data.female || 0);

    const other =
        Number(data.other || 0);

    const calculatedTotal =
        male + female + other;

    const total =
        Number(data.total) ||
        calculatedTotal;


    const getPercentage = (value) => {

        if (!total) {
            return 0;
        }

        return Math.round(
            (value / total) * 100
        );

    };


    const items = [

        {
            label: "Male",
            value: male,
            percentage:
                getPercentage(male),
            color: "#2563eb",
            background: "#eff6ff",
            icon: Male
        },

        {
            label: "Female",
            value: female,
            percentage:
                getPercentage(female),
            color: "#db2777",
            background: "#fdf2f8",
            icon: Female
        },

        {
            label: "Other",
            value: other,
            percentage:
                getPercentage(other),
            color: "#7c3aed",
            background: "#f5f3ff",
            icon: PeopleAlt
        }

    ];


    return (
        <Box
            sx={{
                width: "100%"
            }}
        >

            {/* =========================================
                TOTAL
            ========================================= */}

            <Box
                sx={{
                    p: 2.5,
                    mb: 3,
                    borderRadius: 3,

                    background:
                        "linear-gradient(135deg, #f0fdf4, #ecfdf5)",

                    border:
                        "1px solid #dcfce7"
                }}
            >

                <Typography
                    variant="body2"
                    sx={{
                        color: "text.secondary"
                    }}
                >
                    Total Beneficiaries
                </Typography>


                <Typography
                    sx={{
                        mt: 0.5,
                        fontSize: {
                            xs: "1.8rem",
                            md: "2rem"
                        },
                        fontWeight: 800,
                        color: "#14532d",
                        lineHeight: 1.2
                    }}
                >
                    {total.toLocaleString()}
                </Typography>

            </Box>

            {/* =========================================
                GENDER BREAKDOWN
            ========================================= */}

            <Stack
                spacing={2.2}
            >

                {items.map((item) => {

                    const Icon =
                        item.icon;

                    return (
                        <Box
                            key={item.label}
                        >

                            <Stack
                                direction="row"
                                sx={{ alignItems: "center", justifyContent: "space-between",
                                    mb: 1
                                }}
                            >

                                {/* LABEL */}

                                <Stack sx={{ alignItems: "center" }}
                                    direction="row"
                                    spacing={1.2}
                                >

                                    <Box
                                        sx={{
                                            width: 34,
                                            height: 34,

                                            borderRadius: 2,

                                            display:
                                                "flex",

                                            alignItems:
                                                "center",

                                            justifyContent:
                                                "center",

                                            background:
                                                item.background,

                                            color:
                                                item.color,

                                            flexShrink: 0
                                        }}
                                    >

                                        <Icon
                                            fontSize="small"
                                        />

                                    </Box>


                                    <Typography
                                        sx={{
                                            fontWeight: 600
                                        }}
                                    >
                                        {item.label}
                                    </Typography>

                                </Stack>


                                {/* VALUE */}

                                <Stack sx={{ alignItems: "center" }}
                                    direction="row"
                                    spacing={1}
                                >

                                    <Typography
                                        sx={{
                                            fontWeight: 800
                                        }}
                                    >
                                        {
                                            item.value.toLocaleString()
                                        }
                                    </Typography>


                                    <Typography
                                        variant="body2"
                                        sx={{
                                            color: "text.secondary"
                                        }}
                                    >
                                        {
                                            item.percentage
                                        }%
                                    </Typography>

                                </Stack>

                            </Stack>

                            {/* PROGRESS */}

                            <Box
                                sx={{
                                    height: 7,

                                    borderRadius: 10,

                                    background:
                                        "#f1f5f9",

                                    overflow:
                                        "hidden"
                                }}
                            >

                                <Box
                                    sx={{
                                        height: "100%",

                                        width:
                                            `${item.percentage}%`,

                                        background:
                                            item.color,

                                        borderRadius:
                                            10,

                                        transition:
                                            "width .5s ease"
                                    }}
                                />

                            </Box>

                        </Box>
                    );

                })}

            </Stack>

            {/* =========================================
                EMPTY STATE
            ========================================= */}

            {!total && (

                <Typography
                    variant="body2"
                    sx={{
                        color: "text.secondary",
                        mt: 3,
                        textAlign: "center"
                    }}>
                    No beneficiary gender data
                    available yet.
                </Typography>

            )}

        </Box>
    );

};


export default GenderDistribution;
