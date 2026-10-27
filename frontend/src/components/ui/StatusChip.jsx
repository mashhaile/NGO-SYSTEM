import {
    Chip
} from "@mui/material";

import { useStatusLabel } from "../../utils/terms";


const STATUS_STYLES = {
    active: {
        bgcolor: "success.light",
        color: "success.dark"
    },

    completed: {
        bgcolor: "success.light",
        color: "success.dark"
    },

    received: {
        bgcolor: "success.light",
        color: "success.dark"
    },

    delivered: {
        bgcolor: "success.light",
        color: "success.dark"
    },

    pending: {
        bgcolor: "warning.light",
        color: "warning.dark"
    },
    pledged: {
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
    },

    voided: {
        bgcolor: "action.hover",
        color: "text.secondary"
    },

    // M&E indicator progress
    "on track": {
        bgcolor: "success.light",
        color: "success.dark"
    },

    "at risk": {
        bgcolor: "warning.light",
        color: "warning.dark"
    },

    "off track": {
        bgcolor: "error.light",
        color: "error.dark"
    },

    "no data": {
        bgcolor: "action.hover",
        color: "text.secondary"
    },

    "not started": {
        bgcolor: "action.hover",
        color: "text.secondary"
    },

    // paused work: nothing new until it is Active again
    suspended: {
        bgcolor: "warning.light",
        color: "warning.dark"
    },

    // attendance and delivery results
    present: {
        bgcolor: "success.light",
        color: "success.dark"
    },

    participated: {
        bgcolor: "success.light",
        color: "success.dark"
    },

    late: {
        bgcolor: "warning.light",
        color: "warning.dark"
    },

    excused: {
        bgcolor: "warning.light",
        color: "warning.dark"
    },

    referred: {
        bgcolor: "warning.light",
        color: "warning.dark"
    },

    absent: {
        bgcolor: "error.light",
        color: "error.dark"
    },

    missed: {
        bgcolor: "error.light",
        color: "error.dark"
    },

    // accounts and plans (lowercase values)
    trialing: {
        bgcolor: "info.light",
        color: "info.dark"
    },

    trial: {
        bgcolor: "info.light",
        color: "info.dark"
    },

    past_due: {
        bgcolor: "warning.light",
        color: "warning.dark"
    }
};


const StatusChip = ({
    status,
    size = "small"
}) => {

    // the organization's label (Settings > Wording)
    const statusLabel = useStatusLabel();

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
                status
                    ? String(statusLabel(status))
                        .replace(/_/g, " ")
                        .replace(/^\w/, char => char.toUpperCase())
                    : "Unknown"
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
                borderColor: "transparent",

                "& .MuiChip-label": {
                    px: 1.25
                }
            }}
        />
    );
};


export default StatusChip;