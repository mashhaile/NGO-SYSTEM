// =====================================================
// BUDGET APPROVAL: WHO APPROVES, NOTIFICATIONS, AUDIT
// =====================================================
//
// Approvers are the organization's active users whose role
// can approve budgets (budget.approve: organization admins
// and finance officers). When a budget or a revision is
// submitted they are notified (not the person who
// submitted it); when it is approved or returned, the
// person who submitted it is. Every step is written to the
// audit log as well as to the budget's own history.
//
// Notifications and the audit log never stop the budget
// action itself: a failure is logged and ignored.
//
// =====================================================

const User = require("../models/user");
const rolePermissions = require("../constants/rolepermissions");
const notificationService = require("./notificationService");
const auditLogService = require("./auditLogService");


const approverRoles = () =>
    Object.entries(rolePermissions)
        .filter(([role, permissions]) => role !== "super_admin" && (permissions.includes("budget.approve") || permissions.includes("*")))
        .map(([role]) => role);

const userName = (user) =>
    user?.name || [user?.firstName, user?.lastName].filter(Boolean).join(" ") || user?.email || "";


// The people who can approve budgets in this organization
// (built-in roles with budget.approve, and custom roles with it)
const getApprovers = async (organizationId) =>
    (await require("./roleService").usersWithPermission(organizationId, "budget.approve"))
        .map(user => ({ id: String(user._id), name: userName(user), role: user.role }));


const safely = async (what, work) => {
    try {
        await work();
    }
    catch (error) {
        console.error(`Budget ${what} failed:`, error.message);
    }
};


const label = (budget) => `${budget.budgetCode} ${budget.name}`.trim();


// A budget or revision now waits for approval
const submitted = async ({ budget, organizationId, userId, revision = false }) => {

    await safely("notification", async () => {
        const approvers = await getApprovers(organizationId);
        for (const approver of approvers.filter(item => item.id !== String(userId))) {
            await notificationService.createNotification({
                organization: organizationId,
                user: approver.id,
                type: "organization",
                title: revision ? "Budget revision waiting for approval" : "Budget waiting for approval",
                message: revision
                    ? `Revision v${(budget.version || 1) + 1} of ${label(budget)} was submitted: ${budget.revision?.reason || ""}`.trim()
                    : `${label(budget)} was submitted for approval.`,
                createdBy: userId
            });
        }
    });

    await audit({ budget, organizationId, userId, action: revision ? "BUDGET_REVISION_SUBMITTED" : "BUDGET_SUBMITTED", comment: revision ? budget.revision?.reason : "" });

};


// A budget or revision was approved or returned
const decided = async ({ budget, organizationId, userId, approved, revision = false, comment = "", submittedBy }) => {

    await safely("notification", async () => {
        const to = submittedBy || (revision ? null : budget.submittedBy);
        if (!to || String(to) === String(userId)) return;
        const what = revision ? `The revision of ${label(budget)}` : label(budget);
        await notificationService.createNotification({
            organization: organizationId,
            user: to,
            type: "organization",
            title: approved ? (revision ? "Budget revision approved" : "Budget approved") : (revision ? "Budget revision returned" : "Budget returned"),
            message: approved ? `${what} was approved.` : `${what} was returned: ${comment}`,
            createdBy: userId
        });
    });

    await audit({
        budget,
        organizationId,
        userId,
        action: `${revision ? "BUDGET_REVISION" : "BUDGET"}_${approved ? "APPROVED" : "RETURNED"}`,
        comment
    });

};


const audit = ({ budget, organizationId, userId, action, comment = "" }) =>
    safely("audit log", () =>
        auditLogService.createAuditLog({
            organizationId,
            userId,
            action,
            module: "Budget",
            entityType: "Budget",
            entityId: budget._id,
            description: `${label(budget)}${comment ? `: ${comment}` : ""}`,
            metadata: { budgetCode: budget.budgetCode, level: budget.level, version: budget.version, status: budget.status, revisionStatus: budget.revision?.status || null },
            success: true,
            severity: "info"
        })
    );


module.exports = {
    getApprovers,
    submitted,
    decided,
    audit
};
