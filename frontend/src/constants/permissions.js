const PERMISSIONS = {

    // ================================
    // Organization
    // ================================

    ORGANIZATION_READ: "organization.read",
    ORGANIZATION_UPDATE: "organization.update",


    // ================================
    // Beneficiaries
    // ================================

    BENEFICIARY_CREATE: "beneficiary.create",
    BENEFICIARY_READ: "beneficiary.read",
    BENEFICIARY_UPDATE: "beneficiary.update",
    BENEFICIARY_DELETE: "beneficiary.delete",


    // ================================
    // Donors
    // ================================

    DONOR_CREATE: "donor.create",
    DONOR_READ: "donor.read",
    DONOR_UPDATE: "donor.update",
    DONOR_DELETE: "donor.delete",


    // ================================
    // Donations
    // ================================

    DONATION_CREATE: "donation.create",
    DONATION_READ: "donation.read",
    DONATION_UPDATE: "donation.update",
    DONATION_DELETE: "donation.delete",


    // ================================
    // Users
    // ================================

    USER_CREATE: "user.create",
    USER_READ: "user.read",
    USER_UPDATE: "user.update",
    USER_DELETE: "user.delete",

    USER_ASSIGN_DATA_ENTRY: "user.assign_data_entry",
    USER_ASSIGN_VIEWER: "user.assign_viewer",
    USER_ASSIGN_ORG_ADMIN: "user.assign_org_admin",


    // ================================
    // Programs
    // ================================

    PROGRAM_CREATE: "program.create",
    PROGRAM_READ: "program.read",
    PROGRAM_UPDATE: "program.update",
    PROGRAM_DELETE: "program.delete",


    // ================================
    // Services
    // ================================

    SERVICE_CREATE: "service.create",
    SERVICE_READ: "service.read",
    SERVICE_UPDATE: "service.update",
    SERVICE_DELETE: "service.delete",


    // ================================
    // Enrollments
    // ================================

    ENROLLMENT_CREATE: "enrollment.create",
    ENROLLMENT_READ: "enrollment.read",
    ENROLLMENT_UPDATE: "enrollment.update",
    ENROLLMENT_DELETE: "enrollment.delete",


    // ================================
    // Activities
    // ================================

    ACTIVITY_CREATE: "activity.create",
    ACTIVITY_READ: "activity.read",
    ACTIVITY_UPDATE: "activity.update",
    ACTIVITY_DELETE: "activity.delete",


    // ================================
    // Activity Runs
    // ================================

    ACTIVITY_RUN_CREATE: "activity_run.create",
    ACTIVITY_RUN_READ: "activity_run.read",
    ACTIVITY_RUN_UPDATE: "activity_run.update",
    ACTIVITY_RUN_DELETE: "activity_run.delete",

    // Terms of Reference
    TOR_CREATE: "tor.create",
    TOR_READ: "tor.read",
    TOR_UPDATE: "tor.update",
    TOR_DELETE: "tor.delete",
    TOR_APPROVE: "tor.approve",
    TOR_CREATE_ACTIVITY: "tor.create_activity",


    // ================================
    // Attendance
    // ================================

    ATTENDANCE_CREATE: "attendance.create",
    ATTENDANCE_READ: "attendance.read",
    ATTENDANCE_UPDATE: "attendance.update",
    ATTENDANCE_DELETE: "attendance.delete",


    // ================================
    // Attendance Records
    // ================================

    ATTENDANCE_RECORD_CREATE: "attendance_record.create",
    ATTENDANCE_RECORD_READ: "attendance_record.read",
    ATTENDANCE_RECORD_UPDATE: "attendance_record.update",
    ATTENDANCE_RECORD_DELETE: "attendance_record.delete",


    // ================================
    // Audit Logs
    // ================================

    AUDIT_LOG_READ: "organization.audit.read",


    // ================================
    // Notifications
    // ================================

    NOTIFICATION_READ: "notification.read",


    // ================================
    // Lookup Management
    // ================================

    LOOKUP_CREATE: "lookup.create",
    LOOKUP_READ: "lookup.read",
    LOOKUP_UPDATE: "lookup.update",
    LOOKUP_DELETE: "lookup.delete",


    // ================================
    // Custom Fields
    // ================================

    CUSTOMFIELD_CREATE: "customfield.create",
    CUSTOMFIELD_READ: "customfield.read",
    CUSTOMFIELD_UPDATE: "customfield.update",
    CUSTOMFIELD_DELETE: "customfield.delete"

};

export default PERMISSIONS;