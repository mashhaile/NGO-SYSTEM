import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import axiosClient from "../../services/axiosClient";


// =====================================================
// NOTIFICATIONS: SHARED BY THE BELL AND THE PAGE
// =====================================================

const CHECK_EVERY_MS = 60000;

export const listOf = (data) =>
    Array.isArray(data) ? data : data?.notifications || data?.items || [];


// the unread number, checked every minute and when the
// window comes back into focus
export const useUnreadCount = () => {

    const [unread, setUnread] = useState(0);

    const refresh = useCallback(async () => {
        try {
            const response = await axiosClient.get("/notifications/unread-count");
            setUnread(Number(response.data?.data?.unread) || 0);
        }
        catch {
            // keep the last number
        }
    }, []);

    useEffect(() => {
        // first check after the page has drawn
        const first = setTimeout(refresh, 0);
        const timer = setInterval(refresh, CHECK_EVERY_MS);
        window.addEventListener("focus", refresh);
        return () => {
            clearTimeout(first);
            clearInterval(timer);
            window.removeEventListener("focus", refresh);
        };
    }, [refresh]);

    return [unread, refresh, setUnread];

};


// mark read (once) and go to the page it is about
export const useOpenNotification = (onRead) => {
    const navigate = useNavigate();
    return useCallback(async (note) => {
        if (!note.isRead) {
            try {
                await axiosClient.patch(`/notifications/${note._id}/read`);
                onRead?.(note);
            }
            catch {
                // opening the page matters more
            }
        }
        if (note.link) navigate(note.link);
    }, [navigate, onRead]);
};


export const markAllRead = () =>
    axiosClient.patch("/notifications/read-all");

export const getNotifications = (params) =>
    axiosClient.get("/notifications", { params }).then(response => response.data?.data || {});
