const express =
    require("express");


const router =
    express.Router();


const authMiddleware =
    require("../middleware/authMiddleware");


const requireRole =
    require("../middleware/roleMiddleware");


const subscriptionMiddleware =
    require("../middleware/subscriptionMiddleware");


const validate =
    require("../middleware/validate");


const {

    assignSubscription,

    changePlan,

    renewSubscription,

    cancelSubscription,

    getOrganizationSubscription,

    getOrganizationSubscriptionUsage,

    getCurrentSubscription,

    getSubscriptionSummaryController,

    getFeatures,

    getLimits,

    getUsage

} =
    require("../controllers/subscriptionController");


const {

    createSubscriptionSchema,

    changePlanSchema,

    renewSubscriptionSchema,

    cancelSubscriptionSchema

} =
    require("../validators/subscriptionValidator");


// =====================================================
// SUPER ADMIN
// SUBSCRIPTION MANAGEMENT
// =====================================================


// =====================================================
// GET ORGANIZATION SUBSCRIPTION
// =====================================================

router.get(

    "/organization/:organizationId",

    authMiddleware,

    requireRole("super_admin"),

    getOrganizationSubscription

);


// =====================================================
// GET ORGANIZATION SUBSCRIPTION USAGE
// =====================================================

router.get(

    "/organization/:organizationId/usage",

    authMiddleware,

    requireRole("super_admin"),

    getOrganizationSubscriptionUsage

);


// =====================================================
// ASSIGN SUBSCRIPTION
// =====================================================

router.post(

    "/assign",

    authMiddleware,

    requireRole("super_admin"),

    validate(
        createSubscriptionSchema
    ),

    assignSubscription

);


// =====================================================
// CHANGE ORGANIZATION PLAN
// =====================================================

router.put(

    "/change/:organizationId",

    authMiddleware,

    requireRole("super_admin"),

    validate(
        changePlanSchema
    ),

    changePlan

);


// =====================================================
// RENEW ORGANIZATION SUBSCRIPTION
// =====================================================

router.put(

    "/renew/:organizationId",

    authMiddleware,

    requireRole("super_admin"),

    validate(
        renewSubscriptionSchema
    ),

    renewSubscription

);


// =====================================================
// CANCEL ORGANIZATION SUBSCRIPTION
// =====================================================

router.put(

    "/cancel/:organizationId",

    authMiddleware,

    requireRole("super_admin"),

    validate(
        cancelSubscriptionSchema
    ),

    cancelSubscription

);


// =====================================================
// ORGANIZATION
// SUBSCRIPTION INFORMATION
// =====================================================


// =====================================================
// CURRENT SUBSCRIPTION
// =====================================================
//
// IMPORTANT:
// Do NOT use subscriptionMiddleware here.
//
// This endpoint must be able to return the current state
// even when the subscription is expired or missing.
//
// The controller itself validates the subscription.
// =====================================================

router.get(

    "/current",

    authMiddleware,

    getCurrentSubscription

);


// =====================================================
// SUBSCRIPTION VALIDATION
// =====================================================
//
// If your controller exports validateSubscription,
// expose it here as a separate endpoint.
//
// This is useful for frontend authentication/bootstrap.
// =====================================================

const {
    validateSubscription
} =
    require("../controllers/subscriptionController");


router.get(

    "/validate",

    authMiddleware,

    validateSubscription

);


// =====================================================
// SUBSCRIPTION SUMMARY
// =====================================================

router.get(

    "/summary",

    authMiddleware,

    subscriptionMiddleware,

    getSubscriptionSummaryController

);


// =====================================================
// SUBSCRIPTION FEATURES
// =====================================================

router.get(

    "/features",

    authMiddleware,

    subscriptionMiddleware,

    getFeatures

);


// =====================================================
// SUBSCRIPTION LIMITS
// =====================================================

router.get(

    "/limits",

    authMiddleware,

    subscriptionMiddleware,

    getLimits

);


// =====================================================
// CURRENT USAGE
// =====================================================

router.get(

    "/usage",

    authMiddleware,

    subscriptionMiddleware,

    getUsage

);


// =====================================================
// EXPORT
// =====================================================

module.exports =
    router;
