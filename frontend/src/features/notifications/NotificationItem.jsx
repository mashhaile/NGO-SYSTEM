import { Box, Tooltip, Typography } from "@mui/material";

import { formatDateTime, timeAgo } from "../../utils/date";

const GREEN = "#166048";


// One notification: unread ones are marked with a dot and
// a light green background. Clicking opens it.
const NotificationItem = ({ note, onOpen, dense = false }) => (
    <Box
        onClick={() => onOpen(note)}
        sx={{
            display: "flex",
            gap: 1.25,
            px: 2,
            py: dense ? 1.25 : 1.5,
            cursor: "pointer",
            bgcolor: note.isRead ? "transparent" : "#f0fdf4",
            "&:hover": { bgcolor: "action.hover" }
        }}
    >
        <Box
            sx={{
                width: 8,
                height: 8,
                mt: 0.9,
                flexShrink: 0,
                borderRadius: "50%",
                bgcolor: note.isRead ? "transparent" : GREEN
            }}
        />
        <Box sx={{ minWidth: 0, flex: 1 }}>
            <Typography sx={{ fontWeight: note.isRead ? 500 : 700, fontSize: "0.9rem" }}>
                {note.title}
            </Typography>
            <Typography
                variant="body2"
                color="text.secondary"
                sx={dense ? { display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" } : {}}
            >
                {note.message}
            </Typography>
            <Tooltip title={formatDateTime(note.createdAt)}>
                <Typography variant="caption" color="text.secondary">
                    {dense ? timeAgo(note.createdAt) : formatDateTime(note.createdAt)}
                </Typography>
            </Tooltip>
        </Box>
    </Box>
);

export default NotificationItem;
