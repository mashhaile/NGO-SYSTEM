// =====================================================
// USER ROLES
// =====================================================

const ROLES = {

    SUPER_ADMIN:
        "super_admin",

    ORG_ADMIN:
        "organization_admin",

    DATA_ENTRY:
        "data_entry",

    VIEWER:
        "viewer"

};



// =====================================================
// SaaS PLAN CODES
//
// Actual plan configuration is stored in Plan.
//
// All plans have access to all platform modules.
// Differences between plans are primarily resource
// limits and advanced platform features.
// =====================================================

const PLAN_CODES = {

    FREE:
        "FREE",

    STARTER:
        "STARTER",

    PROFESSIONAL:
        "PRO",

    ENTERPRISE:
        "ENTERPRISE"

};



// =====================================================
// ORGANIZATION LIFECYCLE
//
// Independent from subscription lifecycle.
// =====================================================

const ORGANIZATION_STATUS = {

    TRIAL:
        "trial",

    ACTIVE:
        "active",

    SUSPENDED:
        "suspended",

    INACTIVE:
        "inactive"

};



// =====================================================
// SUBSCRIPTION LIFECYCLE
// =====================================================

const SUBSCRIPTION_STATUS = {

    TRIALING:
        "trialing",

    ACTIVE:
        "active",

    EXPIRED:
        "expired",

    CANCELLED:
        "cancelled",

    PENDING:
        "pending"

};


// =====================================================
// BILLING CYCLES
// =====================================================

const BILLING_CYCLES = {

    MONTHLY:
        "monthly",

    YEARLY:
        "yearly",

    LIFETIME:
        "lifetime"

};



// =====================================================
// PAYMENT STATUS
// =====================================================

const PAYMENT_STATUS = {

    PAID:
        "paid",

    UNPAID:
        "unpaid",

    FAILED:
        "failed",

    REFUNDED:
        "refunded"

};



// =====================================================
// PAYMENT METHODS
// =====================================================

const PAYMENT_METHODS = {

    MANUAL:
        "manual",

    BANK_TRANSFER:
        "bank_transfer",

    CARD:
        "card",

    MOBILE_MONEY:
        "mobile_money",

    OTHER:
        "other"

};



// =====================================================
// AVAILABLE PLATFORM MODULES
//
// ALL PLANS CAN ACCESS ALL MODULES.
//
// Plan limits determine how much an organization
// can use each resource.
// =====================================================

const MODULES = {

    BENEFICIARIES:
        "beneficiaries",

    DONORS:
        "donors",

    PROGRAMS:
        "programs",

    ENROLLMENTS:
        "enrollments",

    DONATIONS:
        "donations",

    SERVICE_DELIVERY:
        "service_delivery",

    TRAININGS:
        "trainings",

    INVENTORY:
        "inventory",

    HR:
        "hr",

    ACCOUNTING:
        "accounting",

    GIS:
        "gis"

};



// =====================================================
// AUDIT LOG ACTIONS
// =====================================================

const AUDIT_ACTIONS = {

    // -------------------------------------------------
    // Authentication
    // -------------------------------------------------

    USER_LOGIN:
        "USER_LOGIN",


    // -------------------------------------------------
    // Users
    // -------------------------------------------------

    USER_CREATED:
        "USER_CREATED",

    USER_UPDATED:
        "USER_UPDATED",

    USER_DELETED:
        "USER_DELETED",


    // -------------------------------------------------
    // Organizations
    // -------------------------------------------------

    ORGANIZATION_CREATED:
        "ORGANIZATION_CREATED",

    ORGANIZATION_ACTIVATED:
        "ORGANIZATION_ACTIVATED",

    ORGANIZATION_SUSPENDED:
        "ORGANIZATION_SUSPENDED",

    ORGANIZATION_DEACTIVATED:
        "ORGANIZATION_DEACTIVATED",

    ORGANIZATION_RESTORED:
        "ORGANIZATION_RESTORED",

    ORGANIZATION_DELETED:
        "ORGANIZATION_DELETED",


    // -------------------------------------------------
    // Subscriptions
    // -------------------------------------------------

    SUBSCRIPTION_CREATED:
        "SUBSCRIPTION_CREATED",

    SUBSCRIPTION_RENEWED:
        "SUBSCRIPTION_RENEWED",

    SUBSCRIPTION_CANCELLED:
        "SUBSCRIPTION_CANCELLED",

    SUBSCRIPTION_EXPIRED:
        "SUBSCRIPTION_EXPIRED",

    SUBSCRIPTION_SUSPENDED:
        "SUBSCRIPTION_SUSPENDED",

    PLAN_CHANGED:
        "PLAN_CHANGED",


    // -------------------------------------------------
    // Payments
    // -------------------------------------------------

    PAYMENT_CREATED:
        "PAYMENT_CREATED",

    PAYMENT_COMPLETED:
        "PAYMENT_COMPLETED",

    PAYMENT_FAILED:
        "PAYMENT_FAILED",

    PAYMENT_REFUNDED:
        "PAYMENT_REFUNDED",


    // -------------------------------------------------
    // Beneficiaries
    // -------------------------------------------------

    BENEFICIARY_CREATED:
        "BENEFICIARY_CREATED",

    BENEFICIARY_UPDATED:
        "BENEFICIARY_UPDATED",

    BENEFICIARY_DELETED:
        "BENEFICIARY_DELETED",


    // -------------------------------------------------
    // Donations
    // -------------------------------------------------

    DONATION_CREATED:
        "DONATION_CREATED",

    DONATION_UPDATED:
        "DONATION_UPDATED",


    // -------------------------------------------------
    // Reporting
    // -------------------------------------------------

    REPORT_EXPORTED:
        "REPORT_EXPORTED"

};



// =====================================================
// USER ACCOUNT STATUS
// =====================================================

const USER_STATUS = {

    ACTIVE:
        "active",

    INACTIVE:
        "inactive",

    SUSPENDED:
        "suspended"

};



// =====================================================
// EXPORT FORMATS
// =====================================================

const EXPORT_FORMATS = {

    JSON:
        "json",

    EXCEL:
        "excel",

    CSV:
        "csv",

    PDF:
        "pdf"

};



// =====================================================
// EXPORT
// =====================================================

module.exports = {

    ROLES,

    PLAN_CODES,

    ORGANIZATION_STATUS,

    SUBSCRIPTION_STATUS,

    BILLING_CYCLES,

    PAYMENT_STATUS,

    PAYMENT_METHODS,

    MODULES,

    USER_STATUS,

    EXPORT_FORMATS,

    AUDIT_ACTIONS

};