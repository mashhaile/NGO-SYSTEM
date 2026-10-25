import { useState } from "react";
import { useNavigate } from "react-router-dom";

import {
    Badge,
    Box,
    Button,
    CircularProgress,
    Divider,
    IconButton,
    Popover,
    Stack,
    Tooltip,
    Typography
} from "@mui/material";

import {
    Notifications,
    NotificationsNone
} from "@mui/icons-material";

import NotificationItem from "../../features/notifications/NotificationItem";
import {
    getNotifications,
    listOf,
    markAllRead,
    useOpenNotification,
    useUnreadCount
} from "../../features/notifications/notificationHooks";


// =====================================================
// NOTIFICATION BELL
// =====================================================
//
// The user's own notifications: approvals waiting for them,
// decisions on what they submitted, security notices. The
// red number is the unread ones. Clicking one marks it read
// and opens the page it is about.
//
// =====================================================

const GREEN = "#166048";


const NotificationBell = () => {

    const navigate = useNavigate();

    const [unread, refresh, setUnread] = useUnreadCount();
    const [anchor, setAnchor] = useState(null);
    const [notes, setNotes] = useState([]);
    const [loading, setLoading] = useState(false);

    const load = async () => {
        setLoading(true);
        try {
            const data = await getNotifications({ limit: 10 });
            setNotes(listOf(data));
            setUnread(Number(data.unread) || 0);
        }
        catch {
            setNotes([]);
        }
        finally {
            setLoading(false);
        }
    };

    const open = (event) => {
        setAnchor(event.currentTarget);
        load();
    };

    const close = () => setAnchor(null);

    const openNote = useOpenNotification((note) => {
        setNotes(previous => previous.map(item => item._id === note._id ? { ...item, isRead: true } : item));
        setUnread(previous => Math.max(0, previous - 1));
    });

    const markAll = async () => {
        try {
            await markAllRead();
            setNotes(previous => previous.map(item => ({ ...item, isRead: true })));
            setUnread(0);
        }
        catch {
            refresh();
        }
    };

    return (
        <>
            <Tooltip title="Notifications">
                <IconButton
                    onClick={open}
                    aria-label={unread ? `${unread} unread notifications` : "Notifications"}
                    sx={{
                        width: 42,
                        height: 42,
                        borderRadius: 2,
                        color: unread ? GREEN : "text.secondary",
                        "&:hover": { backgroundColor: "#f0fdf4", color: GREEN }
                    }}
                >
                    <Badge badgeContent={unread} color="error" max={99}>
                        {unread ? <Notifications /> : <NotificationsNone />}
                    </Badge>
                </IconButton>
            </Tooltip>

            <Popover
                open={Boolean(anchor)}
                anchorEl={anchor}
                onClose={close}
                anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
                transformOrigin={{ vertical: "top", horizontal: "right" }}
                slotProps={{ paper: { sx: { width: 380, maxWidth: "calc(100vw - 32px)", borderRadius: 2, mt: 1 } } }}
            >
                <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between", px: 2, py: 1.5 }}>
                    <Typography sx={{ fontWeight: 700 }}>Notifications</Typography>
                    <Button size="small" onClick={markAll} disabled={!unread} sx={{ color: GREEN, textTransform: "none" }}>
                        Mark all as read
                    </Button>
                </Stack>
                <Divider />

                <Box sx={{ maxHeight: 420, overflowY: "auto" }}>
                    {loading && !notes.length
                        ? (
                            <Box sx={{ py: 4, textAlign: "center" }}><CircularProgress size={24} /></Box>
                        )
                        : notes.length
                            ? notes.map(note => (
                                <NotificationItem
                                    key={note._id}
                                    note={note}
                                    dense
                                    onOpen={(item) => { close(); openNote(item); }}
                                />
                            ))
                            : (
                                <Typography color="text.secondary" sx={{ px: 2, py: 4, textAlign: "center" }}>
                                    No notifications yet. Approvals waiting for you and decisions on what you submitted will show here.
                                </Typography>
                            )}
                </Box>

                <Divider />
                <Button
                    fullWidth
                    onClick={() => { close(); navigate("/notifications"); }}
                    sx={{ py: 1.25, color: GREEN, textTransform: "none", fontWeight: 600 }}
                >
                    See all notifications
                </Button>
            </Popover>
        </>
    );

};

export default NotificationBell;
