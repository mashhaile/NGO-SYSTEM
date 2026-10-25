import { useCallback, useEffect, useState } from "react";

import {
    Box,
    Divider,
    Stack,
    ToggleButton,
    ToggleButtonGroup,
    Typography
} from "@mui/material";

import { DoneAll } from "@mui/icons-material";

import {
    AppButton,
    ErrorState,
    LoadingState,
    PageCard,
    PageContainer,
    PageHeader
} from "../../components/ui";

import { getApiErrorMessage } from "../../utils/apiError";

import NotificationItem from "./NotificationItem";
import {
    getNotifications,
    listOf,
    markAllRead,
    useOpenNotification
} from "./notificationHooks";


// =====================================================
// MY NOTIFICATIONS
// =====================================================
//
// Everything the bell has shown, newest first, 20 at a
// time. "Unread" shows only what is still to be seen.
//
// =====================================================

const PAGE_SIZE = 20;


const NotificationsPage = () => {

    const [show, setShow] = useState("all");
    const [notes, setNotes] = useState([]);
    const [page, setPage] = useState(1);
    const [pages, setPages] = useState(1);
    const [unread, setUnread] = useState(0);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    const load = useCallback(async (nextPage, filter) => {
        setLoading(true);
        setError("");
        try {
            const data = await getNotifications({ page: nextPage, limit: PAGE_SIZE, ...(filter === "unread" ? { unread: true } : {}) });
            setNotes(previous => nextPage === 1 ? listOf(data) : [...previous, ...listOf(data)]);
            setPage(nextPage);
            setPages(Number(data.pages) || 1);
            setUnread(Number(data.unread) || 0);
        }
        catch (loadError) {
            setError(getApiErrorMessage(loadError, "The notifications could not be loaded."));
        }
        finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        const timer = setTimeout(() => load(1, show), 0);
        return () => clearTimeout(timer);
    }, [load, show]);

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
        catch (markError) {
            setError(getApiErrorMessage(markError, "Could not mark the notifications as read."));
        }
    };

    return (
        <PageContainer>

            <PageHeader
                title="Notifications"
                subtitle="What waits for your approval, decisions on what you submitted, and security notices."
                secondaryAction={unread ? markAll : undefined}
                secondaryActionLabel="Mark all as read"
                secondaryActionIcon={<DoneAll />}
            />

            <PageCard>
                <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between", mb: 1.5 }}>
                    <ToggleButtonGroup
                        size="small"
                        exclusive
                        value={show}
                        onChange={(_, value) => value && setShow(value)}
                    >
                        <ToggleButton value="all">All</ToggleButton>
                        <ToggleButton value="unread">Unread ({unread})</ToggleButton>
                    </ToggleButtonGroup>
                </Stack>

                {error && <ErrorState message={error} />}

                {!error && loading && !notes.length && <LoadingState message="Loading notifications..." />}

                {!error && !loading && !notes.length && (
                    <Typography color="text.secondary" sx={{ py: 4, textAlign: "center" }}>
                        {show === "unread" ? "Nothing unread." : "No notifications yet."}
                    </Typography>
                )}

                {notes.length > 0 && (
                    <Box sx={{ border: "1px solid", borderColor: "divider", borderRadius: 2, overflow: "hidden" }}>
                        {notes.map((note, index) => (
                            <Box key={note._id}>
                                {index > 0 && <Divider />}
                                <NotificationItem note={note} onOpen={openNote} />
                            </Box>
                        ))}
                    </Box>
                )}

                {page < pages && (
                    <Stack sx={{ alignItems: "center", mt: 2 }}>
                        <AppButton variant="text" onClick={() => load(page + 1, show)} loading={loading}>
                            Show more
                        </AppButton>
                    </Stack>
                )}
            </PageCard>

        </PageContainer>
    );

};

export default NotificationsPage;
