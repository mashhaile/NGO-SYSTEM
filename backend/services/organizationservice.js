const mongoose =
    require("mongoose");

const bcrypt =
    require("bcrypt");


const Organization =
    require("../models/Organization");

const User =
    require("../models/User");

const Plan =
    require("../models/plan");

const Subscription =
    require("../models/subscription");


const ApiError =
    require("../utils/ApiError");

const generateSequence =
    require("../utils/generateSequence");


const {
    initializeOrganization
} =
    require("../initializers/organizationInitializer");


const {
    ROLES,
    USER_STATUS,
    ORGANIZATION_STATUS,
    SUBSCRIPTION_STATUS
} =
    require("../config/constants");



// =====================================================
// HELPERS
// =====================================================


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
// VALIDATE ADMIN
// =====================================================

const validateAdmin = (
    admin
) => {

    if (!admin) {

        throw new ApiError(
            "Organization admin information is required.",
            400
        );

    }


    if (
        !admin.name ||
        typeof admin.name !== "string" ||
        !admin.name.trim()
    ) {

        throw new ApiError(
            "Admin name is required.",
            400
        );

    }


    if (
        !admin.email ||
        typeof admin.email !== "string" ||
        !admin.email.trim()
    ) {

        throw new ApiError(
            "Admin email is required.",
            400
        );

    }


    if (
        !admin.password ||
        typeof admin.password !== "string" ||
        admin.password.length < 6
    ) {

        throw new ApiError(
            "Admin password must be at least 6 characters.",
            400
        );

    }

};


// =====================================================
// NORMALIZE EMAIL
// =====================================================

const normalizeEmail = (
    email
) => {

    if (
        typeof email !== "string"
    ) {

        return "";

    }


    return email
        .trim()
        .toLowerCase();

};


// =====================================================
// GET FREE PLAN
// =====================================================

const getFreePlan = async () => {

    const freePlan =
        await Plan.findOne({

            code:
                "FREE",

            isActive:
                true

        });


    if (!freePlan) {

        throw new ApiError(
            "Free plan not found. Please seed the plans first.",
            500
        );

    }


    return freePlan;

};


// =====================================================
// BUILD PLAN SNAPSHOT
// =====================================================

const buildPlanSnapshot = (
    plan
) => {

    return {

        name:
            plan.name,

        code:
            plan.code
                ? plan.code
                    .trim()
                    .toUpperCase()
                : "",

        price:
            Number(plan.price) || 0,

        currency:
            plan.currency
                ? plan.currency
                    .trim()
                    .toUpperCase()
                : "",

        billingCycle:
            plan.billingCycle,

        features:
            plan.features || {},

        limits:
            plan.limits || {},

        trialDays:
            Number(plan.trialDays) || 0

    };

};


// =====================================================
// BUILD ORGANIZATION STATUS UPDATE
// =====================================================

const buildStatusUpdate = (
    status
) => {

    const update = {

        status

    };


    if (
        status ===
        ORGANIZATION_STATUS.ACTIVE
    ) {

        update.activatedAt =
            new Date();

        update.suspendedAt =
            null;

        update.suspensionReason =
            "";

    }


    else if (
        status ===
        ORGANIZATION_STATUS.SUSPENDED
    ) {

        update.suspendedAt =
            new Date();

    }


    else if (
        status ===
        ORGANIZATION_STATUS.TRIAL
    ) {

        update.suspendedAt =
            null;

        update.suspensionReason =
            "";

    }


    else if (
        status ===
        ORGANIZATION_STATUS.INACTIVE
    ) {

        update.suspendedAt =
            null;

    }


    return update;

};


// =====================================================
// INITIALIZE / REPAIR ORGANIZATION
// =====================================================
//
// This is intentionally safe to call for both new and
// existing organizations.
//
// The organization initializer delegates Service Delivery
// Unit creation and repair to
// serviceDeliveryUnitService.js.
//
// Therefore:
//
// - Missing standard Units are created.
// - Existing Units are preserved.
// - Custom Units are preserved.
// - Inactive Units are preserved.
// - Existing system-default semanticType values are
//   preserved.
// - Missing semanticType on system defaults is repaired.
// - Duplicate Units are not created.
//
// =====================================================

const ensureOrganizationInitialized = async (
    organizationId,
    userId = null
) => {

    validateOrganizationId(
        organizationId
    );


    await initializeOrganization(

        organizationId,

        userId

    );

};


// =====================================================
// CREATE ORGANIZATION
// + ORGANIZATION ADMIN
// + FREE SUBSCRIPTION
// =====================================================

const createOrganization = async (
    organizationData
) => {

    if (
        !organizationData ||
        typeof organizationData !== "object"
    ) {

        throw new ApiError(
            "Organization information is required.",
            400
        );

    }


    const {
        admin,
        ...orgData
    } =
        organizationData;


    validateAdmin(
        admin
    );


    // =================================================
    // NORMALIZE EMAILS
    // =================================================

    orgData.email =
        normalizeEmail(
            orgData.email
        );


    admin.email =
        normalizeEmail(
            admin.email
        );


    if (!orgData.email) {

        throw new ApiError(
            "Organization email is required.",
            400
        );

    }


    // =================================================
    // CHECK ORGANIZATION EMAIL
    // =================================================

    const existingOrganization =
        await Organization.findOne({

            email:
                orgData.email,

            isDeleted:
                false

        });


    if (existingOrganization) {

        throw new ApiError(
            "Organization email already exists.",
            400
        );

    }


    // =================================================
    // CHECK ADMIN EMAIL
    // =================================================

    const existingUser =
        await User.findOne({

            email:
                admin.email

        });


    if (existingUser) {

        throw new ApiError(
            "Admin email already exists.",
            400
        );

    }


    // =================================================
    // GET FREE PLAN
    // =================================================

    const freePlan =
        await getFreePlan();


    // =================================================
    // GENERATE ORGANIZATION CODE
    // =================================================

    const organizationCode =
        await generateSequence(
            "Organization",
            "ORG",
            null
        );


    // =================================================
    // TRIAL DATES
    // =================================================

    const startDate =
        new Date();


    const trialDays =
        Number(
            freePlan.trialDays
        ) || 30;


    const endDate =
        new Date(
            startDate
        );


    endDate.setDate(

        endDate.getDate() +
        trialDays

    );


    // =================================================
    // CREATE ORGANIZATION
    // =================================================

    let organization =
        null;

    let adminUser =
        null;

    let subscription =
        null;


    try {

        organization =
            await Organization.create({

                ...orgData,

                organizationCode,

                status:
                    ORGANIZATION_STATUS.TRIAL,

                trialStartedAt:
                    startDate,

                trialEndedAt:
                    endDate,

                activatedAt:
                    null,

                suspendedAt:
                    null,

                suspensionReason:
                    ""

            });


        // =============================================
        // HASH ADMIN PASSWORD
        // =============================================

        const hashedPassword =
            await bcrypt.hash(
                admin.password,
                10
            );


        // =============================================
        // CREATE ORGANIZATION ADMIN
        // =============================================

        adminUser =
            await User.create({

                organization:
                    organization._id,

                name:
                    admin.name.trim(),

                email:
                    admin.email,

                password:
                    hashedPassword,

                role:
                    ROLES.ORG_ADMIN,

                status:
                    USER_STATUS.ACTIVE

            });


        // =============================================
        // CREATE FREE SUBSCRIPTION
        // =============================================

        subscription =
            await Subscription.create({

                organization:
                    organization._id,

                plan:
                    freePlan._id,

                status:
                    SUBSCRIPTION_STATUS.ACTIVE,

                startDate,

                endDate,

                autoRenew:
                    false,

                cancelAtPeriodEnd:
                    false,

                cancelledAt:
                    null,

                cancellationReason:
                    "",

                createdBy:
                    adminUser._id,

                planSnapshot:
                    buildPlanSnapshot(
                        freePlan
                    )

            });


        // =============================================
        // INITIALIZE TENANT
        // =============================================
        //
        // New organizations receive all platform-required
        // Service Delivery Units here.
        //
        // The operation is idempotent.
        //
        // =============================================

        await ensureOrganizationInitialized(

            organization._id,

            adminUser._id

        );


        // =============================================
        // RETURN
        // =============================================

        return {

            organization,

            admin: {

                id:
                    adminUser._id,

                name:
                    adminUser.name,

                email:
                    adminUser.email,

                role:
                    adminUser.role

            },

            subscription: {

                id:
                    subscription._id,

                plan:
                    freePlan.name,

                code:
                    freePlan.code,

                status:
                    subscription.status,

                startDate:
                    subscription.startDate,

                endDate:
                    subscription.endDate

            }

        };

    }


    catch (error) {

        // =============================================
        // ROLLBACK LOOKUPS
        // =============================================
        //
        // Service Delivery Units may already have been
        // created before a later initialization error.
        //
        // Remove tenant-specific lookup records so the
        // organization creation remains atomic from the
        // application's perspective.
        //
        // =============================================

        if (organization) {

            const Lookup =
                require("../models/Lookup");


            await Lookup.deleteMany({

                organization:
                    organization._id

            });

        }


        // =============================================
        // ROLLBACK USER
        // =============================================

        if (organization) {

            await User.deleteMany({

                organization:
                    organization._id

            });

        }


        // =============================================
        // ROLLBACK SUBSCRIPTION
        // =============================================

        if (organization) {

            await Subscription.deleteMany({

                organization:
                    organization._id

            });

        }


        // =============================================
        // ROLLBACK ORGANIZATION
        // =============================================

        if (organization) {

            await Organization.deleteOne({

                _id:
                    organization._id

            });

        }


        throw error;

    }

};


// =====================================================
// GET CURRENT ORGANIZATION
// =====================================================
//
// IMPORTANT:
//
// This is the automatic repair point for existing
// organizations.
//
// If an organization was created before the standard
// Service Delivery Units were introduced, accessing the
// organization through the normal organization endpoint
// will initialize the missing Units.
//
// Because initialization is idempotent, this is safe for
// organizations that already contain all standard Units.
//
// =====================================================

const getMyOrganization = async (
    organizationId,
    userId = null
) => {

    validateOrganizationId(
        organizationId
    );


    const organization =
        await Organization.findOne({

            _id:
                organizationId,

            isDeleted:
                false

        }).lean();


    if (!organization) {

        throw new ApiError(
            "Organization not found.",
            404
        );

    }


    // =================================================
    // INITIALIZE / REPAIR ORGANIZATION
    // =================================================

    await ensureOrganizationInitialized(

        organizationId,

        userId

    );


    return organization;

};


// =====================================================
// UPDATE CURRENT ORGANIZATION
// =====================================================

const updateMyOrganization = async (
    organizationId,
    organizationData
) => {

    validateOrganizationId(
        organizationId
    );


    if (
        !organizationData ||
        typeof organizationData !== "object"
    ) {

        throw new ApiError(
            "Organization information is required.",
            400
        );

    }


    // =================================================
    // ORG ADMIN EDITABLE FIELDS
    // =================================================

    const allowedFields = [

        "name",

        "legalName",

        "organizationType",

        "description",

        "foundedYear",

        "registrationNumber",

        "taxIdentificationNumber",

        "email",

        "phone",

        "alternativePhone",

        "website",

        "primaryContact",

        "address",

        "addressLine2",

        "city",

        "stateRegion",

        "postalCode",

        "country",

        "logo"

    ];


    const updateData = {};


    for (
        const field
        of allowedFields
    ) {

        if (
            Object.prototype.hasOwnProperty.call(
                organizationData,
                field
            )
        ) {

            updateData[field] =
                organizationData[field];

        }

    }


    // =================================================
    // NOTHING TO UPDATE
    // =================================================

    if (
        Object.keys(updateData).length === 0
    ) {

        throw new ApiError(
            "No organization information provided for update.",
            400
        );

    }


    // =================================================
    // NORMALIZE EMAIL
    // =================================================

    if (
        Object.prototype.hasOwnProperty.call(
            updateData,
            "email"
        )
    ) {

        updateData.email =
            normalizeEmail(
                updateData.email
            );


        if (!updateData.email) {

            throw new ApiError(
                "Organization email is required.",
                400
            );

        }

    }


    // =================================================
    // CHECK DUPLICATE EMAIL
    // =================================================

    if (
        updateData.email
    ) {

        const existingOrganization =
            await Organization.findOne({

                email:
                    updateData.email,

                _id: {
                    $ne:
                        organizationId
                },

                isDeleted:
                    false

            });


        if (existingOrganization) {

            throw new ApiError(
                "Organization email already exists.",
                400
            );

        }

    }


    // =================================================
    // UPDATE
    // =================================================

    const organization =
        await Organization.findOneAndUpdate(

            {

                _id:
                    organizationId,

                isDeleted:
                    false

            },

            {

                $set:
                    updateData

            },

            {

                new:
                    true,

                runValidators:
                    true

            }

        ).lean();


    if (!organization) {

        throw new ApiError(
            "Organization not found.",
            404
        );

    }


    return organization;

};


// =====================================================
// SUPER ADMIN
// GET ALL ORGANIZATIONS
// + CURRENT SUBSCRIPTION
// =====================================================

const getAllOrganizations = async () => {

    const organizations =
        await Organization
            .find({

                isDeleted:
                    false

            })
            .sort({

                createdAt:
                    -1

            })
            .lean();


    const organizationIds =
        organizations.map(
            organization =>
                organization._id
        );


    const subscriptions =
        await Subscription
            .find({

                organization: {
                    $in:
                        organizationIds
                },

                status:
                    SUBSCRIPTION_STATUS.ACTIVE

            })
            .lean();


    const subscriptionMap =
        new Map();


    subscriptions.forEach(
        subscription => {

            subscriptionMap.set(

                String(
                    subscription.organization
                ),

                subscription

            );

        }
    );


    return organizations.map(
        organization => ({

            ...organization,

            subscription:
                subscriptionMap.get(
                    String(
                        organization._id
                    )
                ) || null

        })
    );

};


// =====================================================
// SUPER ADMIN
// GET ORGANIZATION BY ID
// + ORGANIZATION ADMIN
// + ACTIVE SUBSCRIPTION
// =====================================================
//
// Opening an individual organization also repairs any
// missing platform-default Service Delivery Units.
//
// =====================================================

const getOrganizationById = async (
    organizationId,
    userId = null
) => {

    validateOrganizationId(
        organizationId
    );


    const organization =
        await Organization.findOne({

            _id:
                organizationId,

            isDeleted:
                false

        }).lean();


    if (!organization) {

        throw new ApiError(
            "Organization not found.",
            404
        );

    }


    // =================================================
    // INITIALIZE / REPAIR ORGANIZATION
    // =================================================

    await ensureOrganizationInitialized(

        organizationId,

        userId

    );


    // =================================================
    // ORGANIZATION ADMIN
    // =================================================

    const admin =
        await User.findOne({

            organization:
                organization._id,

            role:
                ROLES.ORG_ADMIN

        })

        .select(
            "_id name email role status lastLogin createdAt updatedAt"
        )

        .lean();


    // =================================================
    // ACTIVE SUBSCRIPTION
    // =================================================

    const subscription =
        await Subscription.findOne({

            organization:
                organization._id,

            status:
                SUBSCRIPTION_STATUS.ACTIVE

        })

        .populate(
            "plan"
        )

        .lean();


    return {

        ...organization,

        admin:
            admin || null,

        subscription:
            subscription || null

    };

};


// =====================================================
// SUPER ADMIN
// UPDATE ORGANIZATION
// =====================================================

const updateOrganization = async (
    organizationId,
    organizationData
) => {

    validateOrganizationId(
        organizationId
    );


    if (
        !organizationData ||
        typeof organizationData !== "object"
    ) {

        throw new ApiError(
            "Organization information is required.",
            400
        );

    }


    // =================================================
    // SUPER ADMIN EDITABLE FIELDS
    //
    // IMPORTANT:
    //
    // enabledModules is intentionally NOT included.
    //
    // Module access belongs to subscription/plan.
    // =================================================

    const allowedFields = [

        "name",

        "legalName",

        "organizationType",

        "description",

        "foundedYear",

        "registrationNumber",

        "taxIdentificationNumber",

        "email",

        "phone",

        "alternativePhone",

        "website",

        "primaryContact",

        "address",

        "addressLine2",

        "city",

        "stateRegion",

        "postalCode",

        "country",

        "logo"

    ];


    const updateData = {};


    for (
        const field
        of allowedFields
    ) {

        if (
            Object.prototype.hasOwnProperty.call(
                organizationData,
                field
            )
        ) {

            updateData[field] =
                organizationData[field];

        }

    }


    // =================================================
    // NOTHING TO UPDATE
    // =================================================

    if (
        Object.keys(updateData).length === 0
    ) {

        throw new ApiError(
            "No organization information provided for update.",
            400
        );

    }


    // =================================================
    // NORMALIZE EMAIL
    // =================================================

    if (
        Object.prototype.hasOwnProperty.call(
            updateData,
            "email"
        )
    ) {

        updateData.email =
            normalizeEmail(
                updateData.email
            );


        if (!updateData.email) {

            throw new ApiError(
                "Organization email is required.",
                400
            );

        }

    }


    // =================================================
    // CHECK DUPLICATE EMAIL
    // =================================================

    if (
        updateData.email
    ) {

        const existingOrganization =
            await Organization.findOne({

                email:
                    updateData.email,

                _id: {
                    $ne:
                        organizationId
                },

                isDeleted:
                    false

            });


        if (existingOrganization) {

            throw new ApiError(
                "Organization email already exists.",
                400
            );

        }

    }


    // =================================================
    // UPDATE
    // =================================================

    const organization =
        await Organization.findOneAndUpdate(

            {

                _id:
                    organizationId,

                isDeleted:
                    false

            },

            {

                $set:
                    updateData

            },

            {

                new:
                    true,

                runValidators:
                    true

            }

        ).lean();


    if (!organization) {

        throw new ApiError(
            "Organization not found.",
            404
        );

    }


    return organization;

};


// =====================================================
// SUPER ADMIN
// UPDATE ORGANIZATION STATUS
// =====================================================

const updateOrganizationStatus = async (
    organizationId,
    status
) => {

    validateOrganizationId(
        organizationId
    );


    if (!status) {

        throw new ApiError(
            "Organization status is required.",
            400
        );

    }


    const allowedStatuses =
        Object.values(
            ORGANIZATION_STATUS
        );


    if (
        !allowedStatuses.includes(
            status
        )
    ) {

        throw new ApiError(
            "Invalid organization status.",
            400
        );

    }


    const organization =
        await Organization.findOneAndUpdate(

            {

                _id:
                    organizationId,

                isDeleted:
                    false

            },

            {

                $set:
                    buildStatusUpdate(
                        status
                    )

            },

            {

                new:
                    true,

                runValidators:
                    true

            }

        ).lean();


    if (!organization) {

        throw new ApiError(
            "Organization not found.",
            404
        );

    }


    return organization;

};


// =====================================================
// SUPER ADMIN
// SOFT DELETE ORGANIZATION
// =====================================================

const deleteOrganization = async (
    organizationId
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

                    isDeleted:
                        true,

                    deletedAt:
                        new Date(),

                    status:
                        ORGANIZATION_STATUS.INACTIVE

                }

            },

            {

                new:
                    true,

                runValidators:
                    true

            }

        ).lean();


    if (!organization) {

        throw new ApiError(
            "Organization not found.",
            404
        );

    }


    return organization;

};


// =====================================================
// SUPER ADMIN
// RESTORE ORGANIZATION
// =====================================================

const restoreOrganization = async (
    organizationId
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
                    true

            },

            {

                $set: {

                    isDeleted:
                        false,

                    deletedAt:
                        null,

                    status:
                        ORGANIZATION_STATUS.ACTIVE,

                    activatedAt:
                        new Date(),

                    suspendedAt:
                        null,

                    suspensionReason:
                        ""

                }

            },

            {

                new:
                    true,

                runValidators:
                    true

            }

        ).lean();


    if (!organization) {

        throw new ApiError(
            "Deleted organization not found.",
            404
        );

    }


    return organization;

};


// =====================================================
// EXPORTS
// =====================================================

module.exports = {

    createOrganization,

    getMyOrganization,

    updateMyOrganization,

    getAllOrganizations,

    getOrganizationById,

    updateOrganization,

    updateOrganizationStatus,

    deleteOrganization,

    restoreOrganization

};
