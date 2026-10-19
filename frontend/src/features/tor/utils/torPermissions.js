// =====================================================
// TOR PERMISSIONS + STATUS RULES (UI side)
// =====================================================
//
// Mirrors backend/services/torService.js. The backend
// always enforces these; the UI only hides actions
// that would be refused.
//
// =====================================================

export const TOR_STATUS = {
    DRAFT: "Draft",
    SUBMITTED: "Submitted",
    APPROVED: "Approved",
    RETURNED: "Returned"
};


export const EDITABLE_STATUSES = [
    TOR_STATUS.DRAFT,
    TOR_STATUS.RETURNED
];


export const hasPermission = (user, permission) => {

    const permissions =
        Array.isArray(user?.permissions)
            ? user.permissions
            : [];

    return (
        permissions.includes("*") ||
        permissions.includes(permission)
    );

};


export const getTorActions = (user, tor) => {

    const status =
        tor?.status;

    const editable =
        EDITABLE_STATUSES.includes(status);

    return {
        canEdit:
            editable &&
            hasPermission(user, "tor.update"),

        canSubmit:
            editable &&
            hasPermission(user, "tor.update"),

        canDelete:
            editable &&
            hasPermission(user, "tor.delete"),

        canReview:
            status === TOR_STATUS.SUBMITTED &&
            hasPermission(user, "tor.approve"),

        // The activity comes after the TOR is approved.
        // tor.create_activity only allows this route, not
        // creating activities directly.

        canCreateActivity:
            status === TOR_STATUS.APPROVED &&
            !tor?.activity &&
            hasPermission(user, "tor.create_activity"),

        canLinkActivity:
            (!tor?.activity || editable) &&
            hasPermission(user, "tor.update")
    };

};
