import {
    Paper,
    Typography,
    Stack,
    Box,
    Divider
} from "@mui/material";

import {
    PersonAdd,
    VolunteerActivism,
    Payments,
    Business,
    EventNote
} from "@mui/icons-material";
import { formatDateTime } from "../../../utils/date";


// "2026-10-19T16:56:29Z" -> "Oct 19, 2026, 4:56 PM"

const formatTime = formatDateTime;


const RecentActivity = ({
    activities = []
}) => {


    const getActivity = (
        type
    ) => {

        switch (type) {

            case "beneficiary":
                return {
                    icon: PersonAdd,
                    color: "#2563eb",
                    background: "#eff6ff"
                };

            case "service":
                return {
                    icon: VolunteerActivism,
                    color: "#15803d",
                    background: "#f0fdf4"
                };

            case "funding":
                return {
                    icon: Payments,
                    color: "#059669",
                    background: "#ecfdf5"
                };

            case "program":
                return {
                    icon: Business,
                    color: "#7c3aed",
                    background: "#f5f3ff"
                };

            default:
                return {
                    icon: EventNote,
                    color: "#64748b",
                    background: "#f8fafc"
                };

        }

    };


    return (
        <Paper
            elevation={0}
            sx={{
                p: {
                    xs: 2,
                    sm: 3
                },

                borderRadius: 4,

                border:
                    "1px solid #e5e7eb",

                background:
                    "#ffffff",

                boxShadow:
                    "0 8px 30px rgba(15,23,42,.05)"
            }}
        >

            {/* =========================================
                HEADER
            ========================================= */}

            <Box
                sx={{
                    mb: 2
                }}
            >

                <Typography
                    variant="h6"
                    sx={{
                        fontWeight: 800,
                        color: "#0f172a"
                    }}>
                    Recent Activity
                </Typography>


                <Typography
                    variant="body2"
                    sx={{
                        color: "text.secondary",
                        mt: 0.5
                    }}>
                    Latest activity across
                    your organization
                </Typography>

            </Box>

            {/* =========================================
                EMPTY STATE
            ========================================= */}

            {!activities.length ? (

                <Box
                    sx={{
                        py: 6,
                        textAlign: "center"
                    }}
                >

                    <Box
                        sx={{
                            width: 52,
                            height: 52,
                            mx: "auto",
                            mb: 1.5,
                            borderRadius: 3,

                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",

                            background:
                                "#f0fdf4",

                            color:
                                "#15803d"
                        }}
                    >

                        <EventNote />

                    </Box>


                    <Typography
                        sx={{
                            fontWeight: 700
                        }}
                    >
                        No recent activity
                    </Typography>


                    <Typography
                        variant="body2"
                        sx={{
                            color: "text.secondary",
                            mt: 0.5
                        }}>
                        Activity will appear
                        here as your organization
                        starts using the platform.
                    </Typography>

                </Box>

            ) : (

                /* =========================================
                    ACTIVITY LIST
                ========================================= */

                <Stack>

                    {activities.map(
                        (
                            activity,
                            index
                        ) => {

                            const config =
                                getActivity(
                                    activity.type
                                );

                            const Icon =
                                config.icon;


                            return (
                                <Box
                                    key={
                                        activity._id ||
                                        activity.id ||
                                        index
                                    }
                                >

                                    <Stack
                                        direction="row"
                                        spacing={2}
                                        sx={{ alignItems: "center",
                                            py: 1.8
                                        }}
                                    >

                                        {/* ICON */}

                                        <Box
                                            sx={{
                                                width: 44,
                                                height: 44,
                                                borderRadius: 3,

                                                display:
                                                    "flex",

                                                alignItems:
                                                    "center",

                                                justifyContent:
                                                    "center",

                                                background:
                                                    config.background,

                                                color:
                                                    config.color,

                                                flexShrink: 0
                                            }}
                                        >

                                            <Icon
                                                fontSize="small"
                                            />

                                        </Box>


                                        {/* CONTENT */}

                                        <Box
                                            sx={{
                                                flex: 1,
                                                minWidth: 0
                                            }}
                                        >

                                            <Typography
                                                noWrap
                                                sx={{
                                                    fontWeight: 700,

                                                    overflow:
                                                        "hidden",

                                                    textOverflow:
                                                        "ellipsis"
                                                }}>
                                                {
                                                    activity.title ||
                                                    "Activity"
                                                }
                                            </Typography>


                                            {activity.description && (

                                                <Typography
                                                    variant="body2"
                                                    sx={{
                                                        color: "text.secondary",
                                                        mt: 0.25,

                                                        overflow:
                                                            "hidden",

                                                        textOverflow:
                                                            "ellipsis",

                                                        whiteSpace:
                                                            {
                                                                xs: "normal",
                                                                sm: "nowrap"
                                                            }
                                                    }}>
                                                    {
                                                        activity.description
                                                    }
                                                </Typography>

                                            )}

                                        </Box>


                                        {/* TIME */}

                                        {activity.time && (

                                            <Typography
                                                variant="caption"
                                                sx={{
                                                    color: "text.secondary",
                                                    flexShrink: 0,

                                                    whiteSpace:
                                                        "nowrap"
                                                }}>
                                                {
                                                    formatTime(activity.time)
                                                }
                                            </Typography>

                                        )}

                                    </Stack>

                                    {index <
                                        activities.length - 1 && (

                                        <Divider />

                                    )}

                                </Box>
                            );

                        }
                    )}

                </Stack>

            )}

        </Paper>
    );

};


export default RecentActivity;

