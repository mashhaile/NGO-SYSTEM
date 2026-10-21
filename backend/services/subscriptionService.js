const mongoose =
    require("mongoose");


const Subscription =
    require("../models/subscription");

const Plan =
    require("../models/plan");

const Organization =
    require("../models/organization");

const User =
    require("../models/user");

const Beneficiary =
    require("../models/Beneficiary");

const Enterprise =
    require("../models/Enterprise");

const Donor =
    require("../models/donor");

const Program =
    require("../models/program");

const ServiceDelivery =
    require("../models/ServiceDelivery");

const Donation =
    require("../models/donation");

const Project =
    require("../models/Project");

const Activity =
    require("../models/Activity");

const ActivityRun =
    require("../models/ActivityRun");

const Enrollment =
    require("../models/enrollment");

const AttendanceRecord =
    require("../models/AttendanceRecord");

const CustomField =
    require("../models/CustomField");

const ApiError =
    require("../utils/apiError");


const {
    SUBSCRIPTION_STATUS,
    BILLING_CYCLES,
    ORGANIZATION_STATUS
} =
    require("../config/constants");


// =====================================================
// RESOURCE DEFINITIONS
// =====================================================

const ALLOWED_RESOURCES = [

    "users",

    "beneficiaries",

    "enterprises",

    "donors",

    "donations",

    "programs",

    "projects",

    "activities",

    "activityRuns",

    "enrollments",

    "serviceDeliveries",

    "attendanceRecords",

    "customFields"

];


// =====================================================
// MODULE DEFINITIONS
// =====================================================

const MODULE_ACCESS = [

    "beneficiaries",

    "enterprises",

    "donors",

    "programs",

    "projects",

    "enrollments",

    "donations",

    "serviceDelivery",

    "activities",

    "activityRuns",

    "attendance",

    "trainings",

    "inventory",

    "hr",

    "accounting",

    "gis",

    "customFields",

    "notifications"

];


// =====================================================
// VALIDATE ORGANIZATION ID
// =====================================================

const validateOrganizationId = (
    organizationId
) => {

    if (!organizationId) {

        throw new ApiError(
            "Organization ID is required.",
            400
        );

    }


    if (
        !mongoose.Types.ObjectId.isValid(
            organizationId
        )
    ) {

        throw new ApiError(
            "Invalid Organization ID.",
            400
        );

    }

};


// =====================================================
// VALIDATE CREATOR
// =====================================================

const validateCreatedBy = (
    createdBy
) => {

    if (!createdBy) {

        throw new ApiError(
            "Subscription creator is required.",
            400
        );

    }


    if (
        !mongoose.Types.ObjectId.isValid(
            createdBy
        )
    ) {

        throw new ApiError(
            "Invalid subscription creator.",
            400
        );

    }

};


// =====================================================
// VALIDATE PLAN
// =====================================================

const validatePlan = async (
    planId
) => {

    if (!planId) {

        throw new ApiError(
            "Plan ID is required.",
            400
        );

    }


    if (
        !mongoose.Types.ObjectId.isValid(
            planId
        )
    ) {

        throw new ApiError(
            "Invalid Plan ID.",
            400
        );

    }


    const plan =
        await Plan.findById(
            planId
        );


    if (!plan) {

        throw new ApiError(
            "Plan not found.",
            404
        );

    }


    if (!plan.isActive) {

        throw new ApiError(
            "Selected plan is inactive.",
            400
        );

    }


    if (
        !plan.code ||
        typeof plan.code !== "string" ||
        !plan.code.trim()
    ) {

        throw new ApiError(
            `Plan "${plan.name || planId}" does not have a valid plan code.`,
            400
        );

    }


    if (
        plan.price === undefined ||
        plan.price === null ||
        !Number.isFinite(
            Number(plan.price)
        ) ||
        Number(plan.price) < 0
    ) {

        throw new ApiError(
            "Selected plan has no valid price.",
            400
        );

    }


    if (
        !plan.currency ||
        typeof plan.currency !== "string" ||
        plan.currency.trim().length !== 3
    ) {

        throw new ApiError(
            "Selected plan has no valid currency.",
            400
        );

    }


    if (
        !Object.values(
            BILLING_CYCLES
        ).includes(
            plan.billingCycle
        )
    ) {

        throw new ApiError(
            "Selected plan has no valid billing cycle.",
            400
        );

    }


    if (
        !plan.features ||
        typeof plan.features !== "object" ||
        Array.isArray(plan.features)
    ) {

        throw new ApiError(
            "Selected plan has invalid features configuration.",
            400
        );

    }


    if (
        !plan.limits ||
        typeof plan.limits !== "object" ||
        Array.isArray(plan.limits)
    ) {

        throw new ApiError(
            "Selected plan has invalid limits configuration.",
            400
        );

    }


    const trialDays =
        Number(
            plan.trialDays
        );


    if (
        !Number.isFinite(
            trialDays
        ) ||
        trialDays < 0 ||
        trialDays > 365
    ) {

        throw new ApiError(
            "Selected plan has invalid trial days.",
            400
        );

    }


    return plan;

};


// =====================================================
// BUILD PLAN SNAPSHOT
// =====================================================
//
//
// BUSINESS RULE:
// Every non-lifetime subscription receives
// a fixed 30-day trial.
//
// Lifetime subscriptions do not receive a trial.
//
// =====================================================

const buildPlanSnapshot = (
    plan
) => {

    if (!plan) {

        throw new ApiError(
            "Cannot build subscription plan snapshot.",
            500
        );

    }


    return {

        name:
            plan.name,

        code:
            plan.code
                .trim()
                .toUpperCase(),

        price:
            Number(
                plan.price
            ),

        currency:
            plan.currency
                .trim()
                .toUpperCase(),

        billingCycle:
            plan.billingCycle,

        features: {

            ...(plan.features || {})

        },

        limits: {

            ...(plan.limits || {})

        },

        // ---------------------------------------------
        // FIXED TRIAL POLICY
        // ---------------------------------------------
        // Monthly / Yearly = 30 days
        // Lifetime = 0 days
        // ---------------------------------------------

        trialDays:
            plan.billingCycle ===
            BILLING_CYCLES.LIFETIME
                ? 0
                : 30

    };

};


// =====================================================
// CALCULATE END DATE
// =====================================================

const calculateEndDate = (

    billingCycle,

    startDate

) => {

    const date =
        new Date(
            startDate
        );


    if (
        Number.isNaN(
            date.getTime()
        )
    ) {

        throw new ApiError(
            "Invalid subscription start date.",
            400
        );

    }


    switch (billingCycle) {

        case BILLING_CYCLES.MONTHLY:

            date.setMonth(
                date.getMonth() + 1
            );

            return date;


        case BILLING_CYCLES.YEARLY:

            date.setFullYear(
                date.getFullYear() + 1
            );

            return date;


        case BILLING_CYCLES.LIFETIME:

            return null;


        default:

            throw new ApiError(
                "Invalid billing cycle.",
                400
            );

    }

};


// =====================================================
// UPDATE ORGANIZATION STATUS
// =====================================================
//
// Organization lifecycle is intentionally kept
// independent from subscription lifecycle.
//
// Subscription expiration/cancellation does NOT
// automatically change organization status.
// =====================================================

const updateOrganizationStatus = async (

    organizationId,

    status

) => {

    validateOrganizationId(
        organizationId
    );


    const organization =
        await Organization.findOneAndUpdate(

            {

                _id:
                    organizationId,

                isDeleted:
                    false

            },

            {

                $set: {

                    status

                }

            },

            {

                returnDocument: "after"

            }

        );


    if (!organization) {

        throw new ApiError(
            "Organization not found.",
            404
        );

    }


    return organization;

};


// =====================================================
// GET CURRENT SUBSCRIPTION
// =====================================================
//
// ACTIVE and TRIALING are both current subscriptions.
// =====================================================

const getActiveSubscription = async (
    organizationId
) => {

    if (!organizationId) {

        return null;

    }


    validateOrganizationId(
        organizationId
    );


    return Subscription

        .findOne({

            organization:
                organizationId,

            status: {

                $in: [

                    SUBSCRIPTION_STATUS.ACTIVE,

                    SUBSCRIPTION_STATUS.TRIALING

                ]

            }

        })

        .sort({

            createdAt:
                -1

        })

        .populate(
            "plan"
        )

        .populate(
            "createdBy",
            "name email role"
        );

};


// =====================================================
// EXPIRE ACTIVE SUBSCRIPTION
// =====================================================
//
// Organization status is NOT changed here.
// =====================================================

const expireActiveSubscription = async (
    organizationId
) => {

    validateOrganizationId(
        organizationId
    );


    await Subscription.updateMany(

        {

            organization:
                organizationId,

            status:
                SUBSCRIPTION_STATUS.ACTIVE,

            endDate: {

                $ne:
                    null

            }

        },

        {

            $set: {

                status:
                    SUBSCRIPTION_STATUS.EXPIRED

            }

        }

    );

};


// =====================================================
// ACTIVATE EXPIRED TRIAL
// =====================================================

const activateExpiredTrial = async (
    subscription
) => {

    if (!subscription) {

        throw new ApiError(
            "Subscription is required.",
            500
        );

    }


    if (
        subscription.status !==
        SUBSCRIPTION_STATUS.TRIALING
    ) {

        return subscription;

    }


    if (
        !subscription.trialStartDate ||
        !subscription.trialEndDate
    ) {

        throw new ApiError(
            "Subscription trial configuration is invalid.",
            500
        );

    }


    const billingCycle =
        subscription
            .planSnapshot
            ?.billingCycle;


    if (!billingCycle) {

        throw new ApiError(
            "Subscription does not contain a valid billing cycle.",
            500
        );

    }


    if (
        !Object.values(
            BILLING_CYCLES
        ).includes(
            billingCycle
        )
    ) {

        throw new ApiError(
            "Subscription has an invalid billing cycle.",
            500
        );

    }


    const paidStartDate =
        new Date(
            subscription.trialEndDate
        );


    const paidEndDate =
        calculateEndDate(

            billingCycle,

            paidStartDate

        );


    subscription.startDate =
        paidStartDate;

    subscription.endDate =
        paidEndDate;

    subscription.status =
        SUBSCRIPTION_STATUS.ACTIVE;

    subscription.autoRenew =
        false;

    subscription.cancelAtPeriodEnd =
        false;

    subscription.cancelledAt =
        null;

    subscription.cancellationReason =
        "";


    await subscription.save();


    await Subscription.updateMany(

        {

            organization:
                subscription.organization,

            _id: {

                $ne:
                    subscription._id

            },

            status: {

                $in: [

                    SUBSCRIPTION_STATUS.ACTIVE,

                    SUBSCRIPTION_STATUS.TRIALING

                ]

            }

        },

        {

            $set: {

                status:
                    SUBSCRIPTION_STATUS.EXPIRED

            }

        }

    );


    await updateOrganizationStatus(

        subscription.organization,

        ORGANIZATION_STATUS.ACTIVE

    );


    return subscription;

};


// =====================================================
// PROCESS EXPIRED TRIALS
// =====================================================
//
// Used by the background scheduler.
// =====================================================

const processExpiredTrials = async () => {

    const now =
        new Date();


    const expiredTrials =
        await Subscription.find({

            status:
                SUBSCRIPTION_STATUS.TRIALING,

            trialEndDate: {

                $lte:
                    now

            }

        });


    const processed = [];


    for (
        const subscription
        of expiredTrials
    ) {

        try {

            const activated =
                await activateExpiredTrial(
                    subscription
                );


            processed.push(
                activated._id
            );


        } catch (error) {

            console.error(

                `Failed to activate expired trial ${subscription._id}:`,

                error.message

            );

        }

    }


    return processed;

};


// =====================================================
// VALIDATE SUBSCRIPTION
// =====================================================
//
// ACTIVE   -> access
// TRIALING -> access
//
// Expired trial -> ACTIVE paid subscription
// Expired active -> EXPIRED
// =====================================================

const validateSubscription = async (
    organizationId
) => {

    validateOrganizationId(
        organizationId
    );


    const subscription =
        await getActiveSubscription(
            organizationId
        );


    if (!subscription) {

        throw new ApiError(
            "No active subscription or trial found for this organization.",
            403
        );

    }


    const now =
        new Date();


    // =================================================
    // TRIALING
    // =================================================

    if (

        subscription.status ===
        SUBSCRIPTION_STATUS.TRIALING

    ) {

        if (

            !subscription.trialStartDate ||

            !subscription.trialEndDate

        ) {

            throw new ApiError(
                "Subscription trial configuration is invalid.",
                500
            );

        }


        if (
            subscription.trialEndDate > now
        ) {

            return subscription;

        }


        return activateExpiredTrial(
            subscription
        );

    }


    // =================================================
    // LIFETIME
    // =================================================

    if (
        subscription.endDate === null
    ) {

        return subscription;

    }


    // =================================================
    // ACTIVE
    // =================================================

    if (

        subscription.status ===
        SUBSCRIPTION_STATUS.ACTIVE

    ) {

        if (

            subscription.endDate &&

            subscription.endDate > now

        ) {

            return subscription;

        }


        subscription.status =
            SUBSCRIPTION_STATUS.EXPIRED;


        await subscription.save();


        throw new ApiError(
            "Subscription has expired.",
            403
        );

    }


    throw new ApiError(
        "Subscription does not provide access.",
        403
    );

};


// =====================================================
// CREATE SUBSCRIPTION
// =====================================================
//
// Lifecycle:
//
// Plan assigned
//      ↓
// TRIALING
//      ↓
// Trial ends
//      ↓
// ACTIVE
//      ↓
// Renewal
//
// =====================================================

const createSubscription = async ({

    organizationId,

    planId,

    createdBy,

    startDate

}) => {

    validateOrganizationId(
        organizationId
    );


    validateCreatedBy(
        createdBy
    );


    const plan =
        await validatePlan(
            planId
        );


    const currentSubscription =
        await getActiveSubscription(
            organizationId
        );


    if (currentSubscription) {

        throw new ApiError(
            "Organization already has an active subscription or trial. Use change plan instead.",
            409
        );

    }


    const subscriptionStartDate =
        startDate
            ? new Date(startDate)
            : new Date();


    if (
        Number.isNaN(
            subscriptionStartDate.getTime()
        )
    ) {

        throw new ApiError(
            "Invalid subscription start date.",
            400
        );

    }


    const now =
        new Date();


    if (
        subscriptionStartDate.getTime()
        <
        now.getTime() - 5000
    ) {

        throw new ApiError(
            "Subscription start date cannot be in the past.",
            400
        );

    }


    const planSnapshot =
        buildPlanSnapshot(
            plan
        );


    const trialDays =
        Number(
            planSnapshot.trialDays
        ) || 0;


    // =================================================
    // LIFETIME
    // =================================================

    if (

        plan.billingCycle ===
        BILLING_CYCLES.LIFETIME

    ) {

        let subscription;


        try {

            subscription =
                await Subscription.create({

                    organization:
                        organizationId,

                    plan:
                        plan._id,

                    status:
                        SUBSCRIPTION_STATUS.ACTIVE,

                    startDate:
                        subscriptionStartDate,

                    endDate:
                        null,

                    trialStartDate:
                        null,

                    trialEndDate:
                        null,

                    autoRenew:
                        false,

                    cancelAtPeriodEnd:
                        false,

                    cancelledAt:
                        null,

                    cancellationReason:
                        "",

                    planSnapshot,

                    createdBy

                });


        } catch (error) {

            if (
                error &&
                error.code === 11000
            ) {

                throw new ApiError(
                    "This organization already has an active subscription or trial.",
                    409
                );

            }


            throw error;

        }


        await updateOrganizationStatus(

            organizationId,

            ORGANIZATION_STATUS.ACTIVE

        );


        return Subscription

            .findById(
                subscription._id
            )

            .populate(
                "plan"
            )

            .populate(
                "createdBy",
                "name email role"
            );

    }


    // =================================================
    // TRIAL
    // =====================================================

    if (
        trialDays > 0
    ) {

        const trialStartDate =
            new Date(
                subscriptionStartDate
            );


        const trialEndDate =
            new Date(
                trialStartDate
            );


        trialEndDate.setDate(

            trialEndDate.getDate()
            +
            trialDays

        );


        let subscription;


        try {

            subscription =
                await Subscription.create({

                    organization:
                        organizationId,

                    plan:
                        plan._id,

                    status:
                        SUBSCRIPTION_STATUS.TRIALING,

                    startDate:
                        trialStartDate,

                    endDate:
                        null,

                    trialStartDate,

                    trialEndDate,

                    autoRenew:
                        false,

                    cancelAtPeriodEnd:
                        false,

                    cancelledAt:
                        null,

                    cancellationReason:
                        "",

                    planSnapshot,

                    createdBy

                });


        } catch (error) {

            if (
                error &&
                error.code === 11000
            ) {

                throw new ApiError(
                    "This organization already has an active subscription or trial.",
                    409
                );

            }


            throw error;

        }


        await updateOrganizationStatus(

            organizationId,

            ORGANIZATION_STATUS.TRIAL

        );


        return Subscription

            .findById(
                subscription._id
            )

            .populate(
                "plan"
            )

            .populate(
                "createdBy",
                "name email role"
            );

    }


    // =================================================
    // NO TRIAL
    // =================================================

    const endDate =
        calculateEndDate(

            plan.billingCycle,

            subscriptionStartDate

        );


    let subscription;


    try {

        subscription =
            await Subscription.create({

                organization:
                    organizationId,

                plan:
                    plan._id,

                status:
                    SUBSCRIPTION_STATUS.ACTIVE,

                startDate:
                    subscriptionStartDate,

                endDate,

                trialStartDate:
                    null,

                trialEndDate:
                    null,

                autoRenew:
                    false,

                cancelAtPeriodEnd:
                    false,

                cancelledAt:
                    null,

                cancellationReason:
                    "",

                planSnapshot,

                createdBy

            });


    } catch (error) {

        if (
            error &&
            error.code === 11000
        ) {

            throw new ApiError(
                "This organization already has an active subscription or trial.",
                409
            );

        }


        throw error;

    }


    await updateOrganizationStatus(

        organizationId,

        ORGANIZATION_STATUS.ACTIVE

    );


    return Subscription

        .findById(
            subscription._id
        )

        .populate(
            "plan"
        )

        .populate(
            "createdBy",
            "name email role"
        );

};


// =====================================================
// CHANGE PLAN
// =====================================================
//
// ACTIVE:
//     New plan starts immediately.
//
// TRIALING:
//     New plan replaces the selected plan immediately,
//     but the ORIGINAL trial dates are preserved.
//
// =====================================================

const changePlan = async ({

    organizationId,

    planId,

    createdBy

}) => {

    validateOrganizationId(
        organizationId
    );


    validateCreatedBy(
        createdBy
    );


    const currentSubscription =
        await getActiveSubscription(
            organizationId
        );


    if (!currentSubscription) {

        throw new ApiError(
            "No active subscription or trial found for this organization.",
            404
        );

    }


    const plan =
        await validatePlan(
            planId
        );


    if (

        currentSubscription.plan &&

        currentSubscription.plan._id.toString()
        ===
        plan._id.toString()

    ) {

        throw new ApiError(
            "Organization is already subscribed to this plan.",
            400
        );

    }


    const now =
        new Date();


    const isTrialing =
        currentSubscription.status ===
        SUBSCRIPTION_STATUS.TRIALING;


    const planSnapshot =
        buildPlanSnapshot(
            plan
        );


    // =================================================
    // CHANGE PLAN DURING TRIAL
    // =================================================

    if (isTrialing) {

        const originalTrialStartDate =
            currentSubscription.trialStartDate;


        const originalTrialEndDate =
            currentSubscription.trialEndDate;


        if (
            !originalTrialStartDate ||
            !originalTrialEndDate
        ) {

            throw new ApiError(
                "Current trial configuration is invalid.",
                500
            );

        }


        // Preserve the original trial period.
        planSnapshot.trialDays =
            Number(
                currentSubscription
                    .planSnapshot
                    ?.trialDays
            ) || 0;


        currentSubscription.plan =
            plan._id;

        currentSubscription.planSnapshot =
            planSnapshot;

        currentSubscription.status =
            SUBSCRIPTION_STATUS.TRIALING;

        currentSubscription.startDate =
            originalTrialStartDate;

        currentSubscription.endDate =
            null;

        currentSubscription.trialStartDate =
            originalTrialStartDate;

        currentSubscription.trialEndDate =
            originalTrialEndDate;

        currentSubscription.autoRenew =
            false;

        currentSubscription.cancelAtPeriodEnd =
            false;

        currentSubscription.cancelledAt =
            null;

        currentSubscription.cancellationReason =
            "";

        currentSubscription.createdBy =
            createdBy;


        await currentSubscription.save();


        await updateOrganizationStatus(

            organizationId,

            ORGANIZATION_STATUS.TRIAL

        );


        return Subscription

            .findById(
                currentSubscription._id
            )

            .populate(
                "plan"
            )

            .populate(
                "createdBy",
                "name email role"
            );

    }


    // =================================================
    // CHANGE PLAN FOR ACTIVE SUBSCRIPTION
    // =================================================

    const endDate =
        calculateEndDate(

            plan.billingCycle,

            now

        );


    currentSubscription.plan =
        plan._id;

    currentSubscription.planSnapshot =
        planSnapshot;

    currentSubscription.startDate =
        now;

    currentSubscription.endDate =
        endDate;

    currentSubscription.status =
        SUBSCRIPTION_STATUS.ACTIVE;

    currentSubscription.trialStartDate =
        null;

    currentSubscription.trialEndDate =
        null;

    currentSubscription.autoRenew =
        false;

    currentSubscription.cancelAtPeriodEnd =
        false;

    currentSubscription.cancelledAt =
        null;

    currentSubscription.cancellationReason =
        "";

    currentSubscription.createdBy =
        createdBy;


    await currentSubscription.save();


    await updateOrganizationStatus(

        organizationId,

        ORGANIZATION_STATUS.ACTIVE

    );


    return Subscription

        .findById(
            currentSubscription._id
        )

        .populate(
            "plan"
        )

        .populate(
            "createdBy",
            "name email role"
        );

};


// =====================================================
// RENEW SUBSCRIPTION
// =====================================================
//
// BEFORE EXPIRY:
//     existing endDate + billing period
//
// AFTER EXPIRY:
//     today + billing period
//
// TRIALING:
//     cannot be directly renewed
//
// LIFETIME:
//     cannot be renewed
// =====================================================

const renewSubscription = async (
    organizationId
) => {

    validateOrganizationId(
        organizationId
    );


    const currentSubscription =
        await getActiveSubscription(
            organizationId
        );


    if (

        currentSubscription &&

        currentSubscription.status ===
        SUBSCRIPTION_STATUS.TRIALING

    ) {

        throw new ApiError(
            "Trial subscriptions cannot be renewed before the trial ends.",
            400
        );

    }


    const subscription =
        await Subscription

            .findOne({

                organization:
                    organizationId,

                status: {

                    $in: [

                        SUBSCRIPTION_STATUS.ACTIVE,

                        SUBSCRIPTION_STATUS.EXPIRED,

                        SUBSCRIPTION_STATUS.CANCELLED

                    ]

                }

            })

            .sort({

                createdAt:
                    -1

            });


    if (!subscription) {

        throw new ApiError(
            "No subscription found for this organization.",
            404
        );

    }


    if (
        subscription.endDate === null
    ) {

        throw new ApiError(
            "Lifetime subscription does not require renewal.",
            400
        );

    }


    if (

        !subscription.planSnapshot ||

        !subscription.planSnapshot.billingCycle

    ) {

        throw new ApiError(
            "Subscription does not contain a valid plan snapshot.",
            500
        );

    }


    const billingCycle =
        subscription
            .planSnapshot
            .billingCycle;


    if (
        !Object.values(
            BILLING_CYCLES
        ).includes(
            billingCycle
        )
    ) {

        throw new ApiError(
            "Subscription has an invalid billing cycle.",
            500
        );

    }


    const now =
        new Date();


    // =================================================
    // RENEWAL START
    // =================================================

    let renewalStartDate;


    if (

        subscription.endDate &&

        subscription.endDate > now

    ) {

        renewalStartDate =
            new Date(
                subscription.endDate
            );

    } else {

        renewalStartDate =
            now;

    }


    const newEndDate =
        calculateEndDate(

            billingCycle,

            renewalStartDate

        );


    subscription.startDate =
        renewalStartDate;

    subscription.endDate =
        newEndDate;

    subscription.status =
        SUBSCRIPTION_STATUS.ACTIVE;

    subscription.trialStartDate =
        null;

    subscription.trialEndDate =
        null;

    subscription.autoRenew =
        false;

    subscription.cancelAtPeriodEnd =
        false;

    subscription.cancelledAt =
        null;

    subscription.cancellationReason =
        "";


    await subscription.save();


    // =================================================
    // CLOSE OTHER CURRENT SUBSCRIPTIONS
    // =================================================

    await Subscription.updateMany(

        {

            organization:
                organizationId,

            _id: {

                $ne:
                    subscription._id

            },

            status: {

                $in: [

                    SUBSCRIPTION_STATUS.ACTIVE,

                    SUBSCRIPTION_STATUS.TRIALING

                ]

            }

        },

        {

            $set: {

                status:
                    SUBSCRIPTION_STATUS.EXPIRED

            }

        }

    );


    await updateOrganizationStatus(

        organizationId,

        ORGANIZATION_STATUS.ACTIVE

    );


    return Subscription

        .findById(
            subscription._id
        )

        .populate(
            "plan"
        )

        .populate(
            "createdBy",
            "name email role"
        );

};


// =====================================================
// CANCEL SUBSCRIPTION
// =====================================================

const cancelSubscription = async (

    organizationId,

    reason = ""

) => {

    validateOrganizationId(
        organizationId
    );


    const subscription =
        await validateSubscription(
            organizationId
        );


    if (

        subscription.status !==
            SUBSCRIPTION_STATUS.ACTIVE &&

        subscription.status !==
            SUBSCRIPTION_STATUS.TRIALING

    ) {

        throw new ApiError(
            "Only an active or trialing subscription can be cancelled.",
            400
        );

    }


    // =================================================
    // IMPORTANT:
    // Capture the original state BEFORE changing status.
    // =================================================

    const wasTrialing =
        subscription.status ===
        SUBSCRIPTION_STATUS.TRIALING;


    subscription.status =
        SUBSCRIPTION_STATUS.CANCELLED;

    subscription.cancelledAt =
        new Date();

    subscription.cancelAtPeriodEnd =
        false;

    subscription.autoRenew =
        false;


    // =================================================
    // CLEAR TRIAL DATES ONLY FOR NON-TRIAL CANCELLATION
    // =================================================
    //
    // Trial cancellation keeps the original trial dates
    // for historical reporting/audit purposes.
    //
    // Active subscription cancellation does not need
    // trial dates.
    // =================================================

    if (!wasTrialing) {

        subscription.trialStartDate =
            null;

        subscription.trialEndDate =
            null;

    }


    subscription.cancellationReason =
        typeof reason === "string"
            ? reason
                .trim()
                .slice(0, 500)
            : "";


    await subscription.save();


    // IMPORTANT:
    // Organization status is intentionally NOT
    // changed when subscription is cancelled.


    return Subscription

        .findById(
            subscription._id
        )

        .populate(
            "plan"
        )

        .populate(
            "createdBy",
            "name email role"
        );

};


// =====================================================
// GET FEATURES
// =====================================================

const getFeatures = async (
    organizationId
) => {

    const subscription =
        await validateSubscription(
            organizationId
        );


    return {

        ...(
            subscription
                .planSnapshot
                ?.features
            ||
            {}

        )

    };

};


// =====================================================
// GET LIMITS
// =====================================================

const getLimits = async (
    organizationId
) => {

    const subscription =
        await validateSubscription(
            organizationId
        );


    return {

        ...(
            subscription
                .planSnapshot
                ?.limits
            ||
            {}

        )

    };

};


// =====================================================
// GET MODULE ACCESS
// =====================================================

const getModuleAccess = async (
    organizationId
) => {

    await validateSubscription(
        organizationId
    );


    const moduleAccess = {};


    MODULE_ACCESS.forEach(
        module => {

            moduleAccess[module] =
                true;

        }
    );


    return moduleAccess;

};


// =====================================================
// BUILD USAGE ITEM
// =====================================================

const buildUsageItem = (

    used,

    limit

) => {

    const normalizedUsed =
        Number.isFinite(
            Number(used)
        )
            ? Number(used)
            : 0;


    const normalizedLimit =
        Number.isFinite(
            Number(limit)
        )
            ? Number(limit)
            : 0;


    const unlimited =
        normalizedLimit === -1;


    const remaining =
        unlimited

            ? null

            : Math.max(

                0,

                normalizedLimit -
                normalizedUsed

            );


    const exceeded =
        !unlimited &&
        normalizedUsed >
        normalizedLimit;


    return {

        used:
            normalizedUsed,

        limit:
            normalizedLimit,

        remaining,

        unlimited,

        exceeded

    };

};


// =====================================================
// GET RESOURCE USAGE
// =====================================================

const getResourceUsage = async (

    organizationId,

    resource

) => {

    validateOrganizationId(
        organizationId
    );


    switch (resource) {

        case "users":

            return User.countDocuments({

                organization:
                    organizationId

            });


        case "beneficiaries":

            return Beneficiary.countDocuments({

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        case "enterprises":

            return Enterprise.countDocuments({

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        case "donors":

            return Donor.countDocuments({

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        case "donations":

            return Donation.countDocuments({

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        case "programs":

            return Program.countDocuments({

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        case "projects":

            return Project.countDocuments({

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        case "activities":

            return Activity.countDocuments({

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        case "activityRuns":

            return ActivityRun.countDocuments({

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        case "enrollments":

            return Enrollment.countDocuments({

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        case "serviceDeliveries":

            return ServiceDelivery.countDocuments({

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        case "attendanceRecords":

            return AttendanceRecord.countDocuments({

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        case "customFields":

            return CustomField.countDocuments({

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        default:

            throw new ApiError(

                `Invalid subscription resource: ${resource}.`,

                400

            );

    }

};


// =====================================================
// GET CONFIGURED LIMIT
// =====================================================

const getConfiguredLimit = (

    limits,

    resource

) => {

    const rawLimit =
        limits?.[resource];


    if (
        rawLimit === undefined ||
        rawLimit === null
    ) {

        throw new ApiError(

            `Subscription limit for ${resource} is not configured.`,

            500

        );

    }


    const limit =
        Number(rawLimit);


    if (
        !Number.isFinite(
            limit
        )
    ) {

        throw new ApiError(

            `Invalid subscription limit for ${resource}.`,

            500

        );

    }


    if (
        limit < -1
    ) {

        throw new ApiError(

            `Invalid subscription limit for ${resource}.`,

            500

        );

    }


    return limit;

};


// =====================================================
// CALCULATE USAGE
// =====================================================

const calculateUsage = async (
    organizationId
) => {

    const subscription =
        await validateSubscription(
            organizationId
        );


    const limits =
        subscription
            .planSnapshot
            ?.limits
        ||
        {};


    const resourceCounts =
        await Promise.all(

            ALLOWED_RESOURCES.map(

                resource =>

                    getResourceUsage(

                        organizationId,

                        resource

                    )

            )

        );


    const usage = {};


    ALLOWED_RESOURCES.forEach(

        (
            resource,
            index
        ) => {

            const limit =
                getConfiguredLimit(

                    limits,

                    resource

                );


            usage[resource] =
                buildUsageItem(

                    resourceCounts[index],

                    limit

                );

        }

    );


    const storageLimit =
        getConfiguredLimit(

            limits,

            "storageMB"

        );


    // Storage tracking will be connected
    // to the file/storage system later.
    const storageUsedMB =
        0;


    usage.storageMB =
        buildUsageItem(

            storageUsedMB,

            storageLimit

        );


    return usage;

};


// =====================================================
// CHECK RESOURCE LIMIT
// =====================================================

const checkResourceLimit = async (

    organizationId,

    resource

) => {

    validateOrganizationId(
        organizationId
    );


    if (
        !ALLOWED_RESOURCES.includes(
            resource
        )
    ) {

        throw new ApiError(

            `Invalid subscription resource: ${resource}.`,

            400

        );

    }


    const subscription =
        await validateSubscription(
            organizationId
        );


    const limits =
        subscription
            .planSnapshot
            ?.limits
        ||
        {};


    const limit =
        getConfiguredLimit(

            limits,

            resource

        );


    if (
        limit === -1
    ) {

        return {

            allowed:
                true,

            resource,

            used:
                null,

            limit:
                -1,

            remaining:
                null,

            unlimited:
                true,

            exceeded:
                false

        };

    }


    const used =
        await getResourceUsage(

            organizationId,

            resource

        );


    if (
        used >= limit
    ) {

        throw new ApiError(

            `${resource} limit reached. Your plan allows ${limit} ${resource}.`,

            403

        );

    }


    return {

        allowed:
            true,

        resource,

        used,

        limit,

        remaining:
            Math.max(
                0,
                limit - used - 1
            ),

        unlimited:
            false,

        exceeded:
            false

    };

};


// =====================================================
// SUBSCRIPTION SUMMARY
// =====================================================

const getSubscriptionSummary = async (
    organizationId
) => {

    const subscription =
        await validateSubscription(
            organizationId
        );


    const isTrialing =
        subscription.status ===
        SUBSCRIPTION_STATUS.TRIALING;


    const isLifetime =
        !isTrialing &&
        subscription.endDate === null;


    const now =
        new Date();


    let daysRemaining =
        null;


    if (

        isTrialing &&

        subscription.trialEndDate

    ) {

        daysRemaining =
            Math.max(

                0,

                Math.ceil(

                    (
                        subscription.trialEndDate -
                        now
                    )
                    /
                    (
                        1000 *
                        60 *
                        60 *
                        24
                    )

                )

            );

    }


    if (

        !isTrialing &&

        !isLifetime &&

        subscription.endDate

    ) {

        daysRemaining =
            Math.max(

                0,

                Math.ceil(

                    (
                        subscription.endDate -
                        now
                    )
                    /
                    (
                        1000 *
                        60 *
                        60 *
                        24
                    )

                )

            );

    }


    const usage =
        await calculateUsage(
            organizationId
        );


    return {

        id:
            subscription._id,

        status:
            subscription.status,

        startDate:
            subscription.startDate,

        endDate:
            subscription.endDate,

        trialStartDate:
            subscription.trialStartDate,

        trialEndDate:
            subscription.trialEndDate,

        isTrialing,

        isLifetime,

        daysRemaining,

        autoRenew:
            subscription.autoRenew,

        cancelAtPeriodEnd:
            subscription.cancelAtPeriodEnd,

        cancelledAt:
            subscription.cancelledAt,

        cancellationReason:
            subscription.cancellationReason,

        plan:
            subscription.planSnapshot,

        usage

    };

};


// =====================================================
// EXPORTS
// =====================================================

module.exports = {

    createSubscription,

    renewSubscription,

    changePlan,

    cancelSubscription,

    getActiveSubscription,

    validateSubscription,

    processExpiredTrials,

    expireActiveSubscription,

    getFeatures,

    getLimits,

    getModuleAccess,

    calculateUsage,

    checkResourceLimit,

    getSubscriptionSummary

};