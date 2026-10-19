import {
    Chip
} from "@mui/material";


const STATUS_STYLES = {
    active: {
        bgcolor: "success.light",
        color: "success.dark"
    },

    completed: {
        bgcolor: "success.light",
        color: "success.dark"
    },

    pending: {
        bgcolor: "warning.light",
        color: "warning.dark"
    },
    planned: {
        bgcolor: "warning.light",
        color: "warning.dark"
    },
    submitted: {
        bgcolor: "info.light",
        color: "info.dark"
    },
    approved: {
        bgcolor: "success.light",
        color: "success.dark"
    },
    returned: {
        bgcolor: "warning.light",
        color: "warning.dark"
    },
    revoked: {
        bgcolor: "error.light",
        color: "error.dark"
    },
    expired: {
        bgcolor: "action.hover",
        color: "text.secondary"
    },
    draft: {
        bgcolor: "action.hover",
        color: "text.secondary"
    },
    ongoing: {
        bgcolor: "info.light",
        color: "info.dark"
    },

    dropped: {
        bgcolor: "warning.light",
        color: "warning.dark"
    },

    inactive: {
        bgcolor: "action.hover",
        color: "text.secondary"
    },

    cancelled: {
        bgcolor: "error.light",
        color: "error.dark"
    },

    canceled: {
        bgcolor: "error.light",
        color: "error.dark"
    },

    rejected: {
        bgcolor: "error.light",
        color: "error.dark"
    }
};


const StatusChip = ({
    status,
    size = "small"
}) => {

    const normalized =
        String(status || "")
            .trim()
            .toLowerCase();


    const style =
        STATUS_STYLES[normalized] || {
            bgcolor: "action.hover",
            color: "text.secondary"
        };


    return (
        <Chip
            label={
                status || "Unknown"
            }

            size={size}

            sx={{
                height: 28,
                borderRadius: 1.5,

                bgcolor: style.bgcolor,
                color: style.color,

                fontWeight: 700,
                fontSize: "0.75rem",

                border: "1px solid",
                borderColor: "divider",

                "& .MuiChip-label": {
                    px: 1.25
                }
            }}
        />
    );
};


export default StatusChip;