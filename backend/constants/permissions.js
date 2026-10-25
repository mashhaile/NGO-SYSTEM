const PERMISSIONS = {

    // =====================================================
    // ORGANIZATION
    // =====================================================

    ORGANIZATION_READ:
        "organization.read",

    ORGANIZATION_UPDATE:
        "organization.update",

    ORGANIZATION_DELETE:
        "organization.delete",

    // custom roles of the organization
    ROLE_MANAGE:
        "role.manage",


    // =====================================================
    // PLAN MANAGEMENT
    // =====================================================

    PLAN_CREATE:
        "plan.create",

    PLAN_READ:
        "plan.read",

    PLAN_UPDATE:
        "plan.update",


    // =====================================================
    // BENEFICIARIES
    // =====================================================

    BENEFICIARY_CREATE:
        "beneficiary.create",

    BENEFICIARY_READ:
        "beneficiary.read",

    BENEFICIARY_UPDATE:
        "beneficiary.update",

    BENEFICIARY_DELETE:
        "beneficiary.delete",


    // =====================================================
    // ENTERPRISE
    // =====================================================

    ENTERPRISE_CREATE:
        "enterprise.create",

    ENTERPRISE_READ:
        "enterprise.read",

    ENTERPRISE_UPDATE:
        "enterprise.update",

    ENTERPRISE_DELETE:
        "enterprise.delete",


    // =====================================================
    // DONORS
    // =====================================================

    DONOR_CREATE:
        "donor.create",

    DONOR_READ:
        "donor.read",

    DONOR_UPDATE:
        "donor.update",

    DONOR_DELETE:
        "donor.delete",


    // =====================================================
    // DONATIONS
    // =====================================================

    DONATION_CREATE:
        "donation.create",

    DONATION_READ:
        "donation.read",

    DONATION_UPDATE:
        "donation.update",

    DONATION_DELETE:
        "donation.delete",


    // =====================================================
    // USERS
    // =====================================================

    USER_CREATE:
        "user.create",

    USER_READ:
        "user.read",

    USER_UPDATE:
        "user.update",

    USER_DELETE:
        "user.delete",


    // =====================================================
    // ROLE ASSIGNMENT
    // =====================================================

    USER_ASSIGN_DATA_ENTRY:
        "user.assign_data_entry",

    USER_ASSIGN_VIEWER:
        "user.assign_viewer",

    USER_ASSIGN_FINANCE:
        "user.assign_finance",

    USER_ASSIGN_ORG_ADMIN:
        "user.assign_org_admin",


    // =====================================================
    // PROGRAMS
    // =====================================================

    PROGRAM_CREATE:
        "program.create",

    PROGRAM_READ:
        "program.read",

    PROGRAM_UPDATE:
        "program.update",

    PROGRAM_DELETE:
        "program.delete",


    // =====================================================
    // PROJECTS
    // =====================================================

    PROJECT_CREATE:
        "project.create",

    PROJECT_READ:
        "project.read",

    PROJECT_UPDATE:
        "project.update",

    PROJECT_DELETE:
        "project.delete",


    // =====================================================
    // SERVICES
    // =====================================================

    SERVICE_CREATE:
        "service.create",

    SERVICE_READ:
        "service.read",

    SERVICE_UPDATE:
        "service.update",

    SERVICE_DELETE:
        "service.delete",


    // =====================================================
    // ENROLLMENTS
    // =====================================================

    ENROLLMENT_CREATE:
        "enrollment.create",

    ENROLLMENT_READ:
        "enrollment.read",

    ENROLLMENT_UPDATE:
        "enrollment.update",

    ENROLLMENT_DELETE:
        "enrollment.delete",


    // =====================================================
    // ACTIVITIES
    // =====================================================

    ACTIVITY_CREATE:
        "activity.create",

    ACTIVITY_READ:
        "activity.read",

    ACTIVITY_UPDATE:
        "activity.update",

    ACTIVITY_DELETE:
        "activity.delete",


    // =====================================================
    // ACTIVITY RUNS
    // =====================================================

    ACTIVITY_RUN_CREATE:
        "activity_run.create",

    ACTIVITY_RUN_READ:
        "activity_run.read",

    ACTIVITY_RUN_UPDATE:
        "activity_run.update",

    ACTIVITY_RUN_DELETE:
        "activity_run.delete",


    // =====================================================
    // TERMS OF REFERENCE (TOR)
    // =====================================================

    TOR_CREATE:
        "tor.create",

    TOR_READ:
        "tor.read",

    TOR_UPDATE:
        "tor.update",

    TOR_DELETE:
        "tor.delete",

    // Approve or return submitted TORs

    TOR_APPROVE:
        "tor.approve",

    // Create the activity from an APPROVED TOR only.
    // Narrower than activity.create: it does not allow
    // creating activities directly.

    TOR_CREATE_ACTIVITY:
        "tor.create_activity",

    // Create / revoke donor share links (data leaves
    // the organization: admin only).

    DONOR_SHARE:
        "donor.share",

    // Rename / retype the activity linked to a TOR.
    // Narrower than activity.update: only name and type,
    // only for activities linked to a TOR.

    TOR_UPDATE_ACTIVITY:
        "tor.update_activity",


    // =====================================================
    // ATTENDANCE
    // =====================================================

    ATTENDANCE_CREATE:
        "attendance.create",

    ATTENDANCE_READ:
        "attendance.read",

    ATTENDANCE_UPDATE:
        "attendance.update",

    ATTENDANCE_DELETE:
        "attendance.delete",


    // =====================================================
    // ATTENDANCE RECORDS
    // =====================================================

    ATTENDANCE_RECORD_CREATE:
        "attendance_record.create",

    ATTENDANCE_RECORD_READ:
        "attendance_record.read",

    ATTENDANCE_RECORD_UPDATE:
        "attendance_record.update",

    ATTENDANCE_RECORD_DELETE:
        "attendance_record.delete",


    // =====================================================
    // AUDIT LOGS
    // =====================================================

    AUDIT_LOG_READ:
        "organization.audit.read",


    // =====================================================
    // NOTIFICATIONS
    // =====================================================

    NOTIFICATION_READ:
        "notification.read",


    // =====================================================
    // LOOKUP MANAGEMENT
    // =====================================================

    LOOKUP_CREATE:
        "lookup.create",

    LOOKUP_READ:
        "lookup.read",

    LOOKUP_UPDATE:
        "lookup.update",

    LOOKUP_DELETE:
        "lookup.delete",


    // =====================================================
    // CUSTOM FIELDS
    // =====================================================

    CUSTOMFIELD_CREATE:
        "customfield.create",

    CUSTOMFIELD_READ:
        "customfield.read",

    CUSTOMFIELD_UPDATE:
        "customfield.update",

    CUSTOMFIELD_DELETE:
        "customfield.delete",


    // =====================================================
    // REPORTS
    // =====================================================

    REPORT_READ:
        "report.read",


    // =====================================================
    // BUDGETS (master budget: program / project, by
    // fiscal year = calendar year)
    // =====================================================

    BUDGET_CREATE:
        "budget.create",

    BUDGET_READ:
        "budget.read",

    BUDGET_UPDATE:
        "budget.update",

    BUDGET_DELETE:
        "budget.delete",

    // Approve or return submitted budgets

    BUDGET_APPROVE:
        "budget.approve",


    // =====================================================
    // EXPENSES (charged to project budget lines)
    // =====================================================

    EXPENSE_CREATE:
        "expense.create",

    EXPENSE_READ:
        "expense.read",

    EXPENSE_UPDATE:
        "expense.update",

    EXPENSE_DELETE:
        "expense.delete",

    // Approve / return / void
    EXPENSE_APPROVE:
        "expense.approve"

};


module.exports = PERMISSIONS;
