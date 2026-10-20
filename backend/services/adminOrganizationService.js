const escapeRegex = require("../utils/escapeRegex");
const bcrypt =
    require("bcrypt");

const {
    assertStrongPassword,
    getPasswordProblem
} = require("../utils/password");

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

const Project =
    require("../models/Project");

const Donation =
    require("../models/donation");

const ServiceDelivery =
    require("../models/ServiceDelivery");

const Enrollment =
    require("../models/enrollment");

const Activity =
    require("../models/Activity");

const ActivityRun =
    require("../models/ActivityRun");

const AttendanceRecord =
    require("../models/AttendanceRecord");

const CustomField =
    require("../models/CustomField");

const Subscription =
    require("../models/subscription");

const auditLogService =
    require("./auditLogService");

const systemNotificationService =
    require("./systemNotificationService");

const ApiError =
    require("../utils/apiError");

const {
    ORGANIZATION_STATUS,
    SUBSCRIPTION_STATUS,
    ROLES,
    USER_STATUS,
    AUDIT_ACTIONS
} = require("../config/constants");


// =====================================================
// HELPERS
// =====================================================

const createOrganizationAuditLog = async (
    organization,
    action,
    description,
    previousStatus,
    actor,
    metadata = {}
) => {

    if (!actor || !actor.userId) {

        return;

    }


    await auditLogService.createAuditLog({

        userId:
            actor.userId,

        organizationId:
            organization._id,

        action,

        module:
            "Organization",

        entityType:
            "Organization",

        entityId:
            organization._id,

        description,

        metadata: {

            previousStatus,

            newStatus:
                organization.status,

            ...metadata

        },

        ipAddress:
            actor.ipAddress,

        userAgent:
            actor.userAgent

    });

};


const generateOrganizationCode = async () => {

    const lastOrganization =
        await Organization
            .findOne({
                organizationCode: {
                    $regex: /^ORG-\d+$/
                }
            })
            .sort({
                organizationCode: -1
            })
            .select("organizationCode")
            .lean();


    let nextNumber = 1;


    if (
        lastOrganization?.organizationCode
    ) {

        const match =
            lastOrganization.organizationCode.match(
                /^ORG-(\d+)$/
            );


        if (match) {

            nextNumber =
                Number(match[1]) + 1;

        }

    }


    return `ORG-${String(nextNumber).padStart(6, "0")}`;

};


// =====================================================
// FIND ORGANIZATION
// =====================================================

const findOrganization = async (
    organizationId,
    includeDeleted = false
) => {

    if (!organizationId) {

        throw new ApiError(
            "Organization ID is required.",
            400
        );

    }


    const filter = {

        _id:
            organizationId

    };


    if (!includeDeleted) {

        filter.isDeleted =
            false;

    }


    const organization =
        await Organization.findOne(filter);


    if (!organization) {

        throw new ApiError(
            "Organization not found.",
            404
        );

    }


    return organization;

};


// =====================================================
// CREATE ORGANIZATION
// SUPER ADMIN
// =====================================================

const createOrganization = async (
    data = {},
    actor
) => {

    const name =
        String(
            data.name || ""
        ).trim();

    const email =
        String(
            data.email || ""
        )
            .trim()
            .toLowerCase();

    const phone =
        data.phone
            ? String(data.phone).trim()
            : undefined;

    const country =
        data.country
            ? String(data.country).trim()
            : undefined;

    const address =
        data.address
            ? String(data.address).trim()
            : undefined;

    const website =
        data.website
            ? String(data.website).trim()
            : undefined;

    const logo =
        data.logo
            ? String(data.logo).trim()
            : undefined;


    const admin =
        data.admin || {};


    const adminName =
        String(
            data.adminName ||
            admin.name ||
            ""
        ).trim();

    const adminEmail =
        String(
            data.adminEmail ||
            admin.email ||
            ""
        )
            .trim()
            .toLowerCase();

    const adminPassword =
        String(
            data.adminPassword ||
            admin.password ||
            ""
        );


    if (!name) {

        throw new ApiError(
            "Organization name is required.",
            400
        );

    }


    if (!email) {

        throw new ApiError(
            "Organization email is required.",
            400
        );

    }


    if (!adminName) {

        throw new ApiError(
            "Organization administrator name is required.",
            400
        );

    }


    if (!adminEmail) {

        throw new ApiError(
            "Organization administrator email is required.",
            400
        );

    }


    if (!adminPassword) {

        throw new ApiError(
            "Organization administrator password is required.",
            400
        );

    }


    if (adminPassword.length < 6) {

        throw new ApiError(
            "Organization administrator password must be at least 6 characters.",
            400
        );

    }


    const existingOrganization =
        await Organization.findOne({

            email

        });


    if (existingOrganization) {

        throw new ApiError(
            "An organization with this email already exists.",
            409
        );

    }


    const existingUser =
        await User.findOne({

            email:
                adminEmail

        });


    if (existingUser) {

        throw new ApiError(
            "A user with this administrator email already exists.",
            409
        );

    }


    const organizationCode =
        await generateOrganizationCode();


    const organization =
        new Organization({

            organizationCode,

            name,

            email,

            phone,

            country,

            address,

            website,

            logo,

            status:
                ORGANIZATION_STATUS.TRIAL,

            createdBy:
                actor?.userId || null

        });


    try {

        await organization.save();

    }

    catch (error) {

        if (
            error?.code === 11000
        ) {

            throw new ApiError(
                "An organization with the provided unique information already exists.",
                409
            );

        }

        throw error;

    }


    assertStrongPassword(adminPassword);

    const hashedPassword =
        await bcrypt.hash(
            adminPassword,
            12
        );


    const administrator =
        new User({

            organization:
                organization._id,

            name:
                adminName,

            email:
                adminEmail,

            password:
                hashedPassword,

            role:
                ROLES.ORG_ADMIN,

            status:
                USER_STATUS.ACTIVE

        });


    try {

        await administrator.save();

    }

    catch (error) {

        try {

            await Organization.deleteOne({

                _id:
                    organization._id

            });

        }

        catch (rollbackError) {

            // Preserve original error.

        }


        if (
            error?.code === 11000
        ) {

            throw new ApiError(
                "A user with this administrator email already exists.",
                409
            );

        }

        throw error;

    }


    try {

        await createOrganizationAuditLog(

            organization,

            AUDIT_ACTIONS.ORGANIZATION_CREATED,

            "Organization created by Super Admin with an initial Organization Administrator.",

            null,

            actor

        );

    }

    catch (auditError) {

        console.error(
            "Organization creation audit log failed:",
            auditError
        );

    }


    const organizationData =
        organization.toObject();

    const administratorData =
        administrator.toObject();


    delete administratorData.password;


    return {

        organization:
            organizationData,

        administrator:
            administratorData,

        subscription:
            null,

        message:
            "Organization and initial administrator created successfully. Assign a subscription plan when ready."

    };

};


// =====================================================
// UPDATE ORGANIZATION
// SUPER ADMIN
//
// Updates organization profile information only.
//
// Does NOT change:
// - organizationCode
// - status
// - subscription
// - plan
// - administrator password
// =====================================================

const updateOrganization = async (
    organizationId,
    data = {},
    actor
) => {

    const organization =
        await findOrganization(
            organizationId,
            false
        );


    // -------------------------------------------------
    // Normalize values
    // -------------------------------------------------

    const updates = {};


    const stringFields = [

        "name",
        "legalName",
        "organizationType",
        "description",
        "registrationNumber",
        "taxIdentificationNumber",
        "email",
        "phone",
        "alternativePhone",
        "website",
        "address",
        "addressLine2",
        "city",
        "stateRegion",
        "postalCode",
        "country",
        "logo"

    ];


    stringFields.forEach(
        (field) => {

            if (
                data[field] !== undefined
            ) {

                updates[field] =
                    String(
                        data[field] ?? ""
                    ).trim();

            }

        }
    );


    // -------------------------------------------------
    // Founded year
    // -------------------------------------------------

    if (
        data.foundedYear !== undefined &&
        data.foundedYear !== null &&
        data.foundedYear !== ""
    ) {

        const foundedYear =
            Number(
                data.foundedYear
            );


        if (
            !Number.isInteger(
                foundedYear
            )
        ) {

            throw new ApiError(
                "Founded year must be a valid year.",
                400
            );

        }


        if (
            foundedYear < 1800 ||
            foundedYear > new Date().getFullYear()
        ) {

            throw new ApiError(
                "Founded year is outside the allowed range.",
                400
            );

        }


        updates.foundedYear =
            foundedYear;

    }
    else if (
        data.foundedYear === "" ||
        data.foundedYear === null
    ) {

        updates.foundedYear =
            undefined;

    }


    // -------------------------------------------------
    // Primary contact
    // -------------------------------------------------

    if (
        data.primaryContact !== undefined
    ) {

        const primaryContact =
            data.primaryContact || {};


        updates.primaryContact = {

            name:
                primaryContact.name !== undefined
                    ? String(
                        primaryContact.name || ""
                    ).trim()
                    : organization.primaryContact?.name,

            position:
                primaryContact.position !== undefined
                    ? String(
                        primaryContact.position || ""
                    ).trim()
                    : organization.primaryContact?.position,

            email:
                primaryContact.email !== undefined
                    ? String(
                        primaryContact.email || ""
                    )
                        .trim()
                        .toLowerCase()
                    : organization.primaryContact?.email,

            phone:
                primaryContact.phone !== undefined
                    ? String(
                        primaryContact.phone || ""
                    ).trim()
                    : organization.primaryContact?.phone

        };

    }


    // -------------------------------------------------
    // Required organization fields
    // -------------------------------------------------

    const finalName =
        updates.name !== undefined
            ? updates.name
            : organization.name;

    const finalEmail =
        updates.email !== undefined
            ? updates.email.toLowerCase()
            : organization.email;

    const finalPhone =
        updates.phone !== undefined
            ? updates.phone
            : organization.phone;

    const finalCountry =
        updates.country !== undefined
            ? updates.country
            : organization.country;


    if (!finalName) {

        throw new ApiError(
            "Organization name is required.",
            400
        );

    }


    if (finalName.length < 3) {

        throw new ApiError(
            "Organization name must be at least 3 characters.",
            400
        );

    }


    if (!finalEmail) {

        throw new ApiError(
            "Organization email is required.",
            400
        );

    }


    if (!finalPhone) {

        throw new ApiError(
            "Organization phone number is required.",
            400
        );

    }


    if (!finalCountry) {

        throw new ApiError(
            "Organization country is required.",
            400
        );

    }


    // -------------------------------------------------
    // Duplicate organization email
    // -------------------------------------------------

    if (
        finalEmail !== organization.email
    ) {

        const existingOrganization =
            await Organization.findOne({

                email:
                    finalEmail,

                _id: {
                    $ne:
                        organization._id
                }

            });


        if (existingOrganization) {

            throw new ApiError(
                "An organization with this email already exists.",
                409
            );

        }

    }


    // -------------------------------------------------
    // Apply changes
    // -------------------------------------------------

    Object.assign(
        organization,
        updates
    );


    organization.updatedBy =
        actor?.userId || null;


    try {

        await organization.save();

    }

    catch (error) {

        if (
            error?.code === 11000
        ) {

            throw new ApiError(
                "An organization with the provided email already exists.",
                409
            );

        }

        throw error;

    }


    // -------------------------------------------------
    // Audit
    // -------------------------------------------------

    try {

        await createOrganizationAuditLog(

            organization,

            AUDIT_ACTIONS.ORGANIZATION_UPDATED ||
            "ORGANIZATION_UPDATED",

            "Organization profile updated by Super Admin.",

            organization.status,

            actor,

            {

                updatedFields:
                    Object.keys(updates)

            }

        );

    }

    catch (auditError) {

        console.error(
            "Organization update audit log failed:",
            auditError
        );

    }


    return {

        organization:
            organization.toObject(),

        message:
            "Organization updated successfully."

    };

};

//get organization 

const getOrganizations = async (query = {}) => {

    const {
        search = "",
        status,
        country,
        sortBy = "createdAt",
        sortOrder = "desc",
        page = 1,
        limit = 20,
        includeDeleted,
        deletedOnly
    } = query;


    // =================================================
    // FILTER
    // =================================================

    const filter = {};


    const isDeletedOnly =
        String(deletedOnly).toLowerCase() === "true";


    const shouldIncludeDeleted =
        String(includeDeleted).toLowerCase() === "true";


    if (isDeletedOnly) {

        filter.isDeleted = true;

    } else if (!shouldIncludeDeleted) {

        filter.isDeleted = false;

    }


    // =================================================
    // SEARCH
    // =================================================

    if (search.trim()) {

        const searchRegex =
            new RegExp(
                escapeRegex(search.trim()),
                "i"
            );

        filter.$or = [

            {
                name: searchRegex
            },

            {
                email: searchRegex
            },

            {
                organizationCode: searchRegex
            },

            {
                phone: searchRegex
            },

            {
                country: searchRegex
            }

        ];

    }


    // =================================================
    // STATUS
    // =================================================

    if (status) {

        filter.status = status;

    }


    // =================================================
    // COUNTRY
    // =================================================

    if (country) {

        filter.country = country;

    }


    // =================================================
    // PAGINATION
    // =================================================

    const currentPage =
        Math.max(
            Number(page) || 1,
            1
        );


    const currentLimit =
        Math.min(
            Math.max(
                Number(limit) || 20,
                1
            ),
            100
        );


    const skip =
        (currentPage - 1) *
        currentLimit;


    // =================================================
    // SORT
    // =================================================

    const sort = {

        [sortBy]:
            sortOrder === "asc"
                ? 1
                : -1

    };


    // =================================================
    // QUERY
    // =================================================

    const [
        organizations,
        total
    ] = await Promise.all([

        Organization
            .find(filter)
            .sort(sort)
            .skip(skip)
            .limit(currentLimit)
            .lean(),

        Organization.countDocuments(
            filter
        )

    ]);


    // =================================================
    // SUBSCRIPTIONS
    // =================================================

    const organizationIds =
        organizations.map(
            organization =>
                organization._id
        );


    const subscriptions =
        organizationIds.length
            ? await Subscription
                .find({
                    organization: {
                        $in: organizationIds
                    }
                })
                .populate(
                    "plan",
                    "name code"
                )
                .sort({
                    createdAt: -1
                })
                .lean()
            : [];


    // =================================================
    // MAP LATEST SUBSCRIPTION
    // =================================================

    const subscriptionMap =
        new Map();


    for (
        const subscription
        of subscriptions
    ) {

        const organizationId =
            String(
                subscription.organization
            );


        if (
            !subscriptionMap.has(
                organizationId
            )
        ) {

            subscriptionMap.set(
                organizationId,
                subscription
            );

        }

    }


    // =================================================
    // RESPONSE
    // =================================================

    const data =
        organizations.map(
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


    return {

        organizations:
            data,

        pagination: {

            page:
                currentPage,

            limit:
                currentLimit,

            total,

            totalPages:
                Math.ceil(
                    total /
                    currentLimit
                )

        }

    };

};


const getOrganizationDetails = async (
    organizationId
) => {

    const organization =
        await findOrganization(
            organizationId,
            false
        );


    // Get the organization's latest subscription.
    // Super Admin must be able to see the subscription
    // even when it is expired or cancelled.

    const subscription =
        await Subscription
            .findOne({

                organization:
                    organizationId

            })
            .sort({

                createdAt:
                    -1

            })
            .populate("plan")
            .lean();


    const [

        users,

        beneficiaries,

        enterprises,

        donors,

        programs,

        projects,

        donations,

        serviceDeliveries,

        enrollments,

        activities,

        activityRuns,

        attendanceRecords,

        customFields

    ] = await Promise.all([

        User.countDocuments({

            organization:
                organizationId,

            isDeleted: false

        }),

        Beneficiary.countDocuments({

            organization:
                organizationId,

            isDeleted: false

        }),

        Enterprise.countDocuments({

            organization:
                organizationId,

            isDeleted: false

        }),

        Donor.countDocuments({

            organization:
                organizationId,

            isDeleted: false

        }),

        Program.countDocuments({

            organization:
                organizationId,

            isDeleted: false

        }),

        Project.countDocuments({

            organization:
                organizationId,

            isDeleted: false

        }),

        Donation.countDocuments({

            organization:
                organizationId,

            isDeleted: false

        }),

        ServiceDelivery.countDocuments({

            organization:
                organizationId,

            isDeleted: false

        }),

        Enrollment.countDocuments({

            organization:
                organizationId,

            isDeleted: false

        }),

        Activity.countDocuments({

            organization:
                organizationId,

            isDeleted: false

        }),

        ActivityRun.countDocuments({

            organization:
                organizationId,

            isDeleted: false

        }),

        AttendanceRecord.countDocuments({

            organization:
                organizationId,

            isDeleted: false

        }),

        CustomField.countDocuments({

            organization:
                organizationId,

            isDeleted: false

        })

    ]);


    const usage = {

        users,

        beneficiaries,

        enterprises,

        donors,

        donations,

        programs,

        projects,

        activities,

        activityRuns,

        enrollments,

        serviceDeliveries,

        attendanceRecords,

        customFields

    };


    const limits =
        subscription?.planSnapshot?.limits ||
        subscription?.plan?.limits ||
        null;


    const usagePercentage = {};


    if (limits) {

        Object.keys(usage).forEach(
            (resource) => {

                const limit =
                    limits[resource];

                const current =
                    usage[resource];


                if (
                    limit === -1 ||
                    limit === undefined ||
                    limit === null
                ) {

                    usagePercentage[resource] =
                        null;

                    return;

                }


                if (limit === 0) {

                    usagePercentage[resource] =
                        current > 0
                            ? 100
                            : 0;

                    return;

                }


                usagePercentage[resource] =
                    Math.min(

                        Math.round(

                            (
                                current /
                                limit

                            ) * 100

                        ),

                        100

                    );

            }
        );

    }


    return {

        organization,

        subscription,

        plan:
            subscription?.plan || null,

        usage,

        limits,

        usagePercentage

    };

};


// =====================================================
// ACTIVATE ORGANIZATION
// =====================================================

const activateOrganization = async (
    organizationId,
    actor
) => {

    const organization =
        await findOrganization(
            organizationId,
            false
        );


    const previousStatus =
        organization.status;


    if (
        previousStatus ===
        ORGANIZATION_STATUS.ACTIVE
    ) {

        return organization;

    }


    organization.status =
        ORGANIZATION_STATUS.ACTIVE;

    organization.activatedAt =
        new Date();

    organization.suspendedAt =
        null;

    organization.suspensionReason =
        "";


    await organization.save();


    await createOrganizationAuditLog(

        organization,

        AUDIT_ACTIONS.ORGANIZATION_ACTIVATED,

        "Organization activated by Super Admin.",

        previousStatus,

        actor

    );


    return organization;

};


// =====================================================
// SUSPEND ORGANIZATION
// =====================================================

const suspendOrganization = async (
    organizationId,
    actor
) => {

    const organization =
        await findOrganization(
            organizationId,
            false
        );


    const previousStatus =
        organization.status;


    if (
        previousStatus ===
        ORGANIZATION_STATUS.SUSPENDED
    ) {

        return organization;

    }


    organization.status =
        ORGANIZATION_STATUS.SUSPENDED;

    organization.suspendedAt =
        new Date();


    await organization.save();


    await systemNotificationService
        .notifyOrganizationAdmins(

            organizationId,

            "Organization Suspended",

            "Your organization has been suspended by the platform administrator.",

            "organization"

        );


    await createOrganizationAuditLog(

        organization,

        AUDIT_ACTIONS.ORGANIZATION_SUSPENDED,

        "Organization suspended by Super Admin.",

        previousStatus,

        actor

    );


    return organization;

};


// =====================================================
// DEACTIVATE ORGANIZATION
// =====================================================

const deactivateOrganization = async (
    organizationId,
    actor
) => {

    const organization =
        await findOrganization(
            organizationId,
            false
        );


    const previousStatus =
        organization.status;


    if (
        previousStatus ===
        ORGANIZATION_STATUS.INACTIVE
    ) {

        return organization;

    }


    organization.status =
        ORGANIZATION_STATUS.INACTIVE;


    await organization.save();


    await createOrganizationAuditLog(

        organization,

        AUDIT_ACTIONS.ORGANIZATION_DEACTIVATED,

        "Organization deactivated by Super Admin.",

        previousStatus,

        actor

    );


    return organization;

};


// =====================================================
// RESTORE ORGANIZATION
// =====================================================

const restoreOrganization = async (
    organizationId,
    actor
) => {

    const organization =
        await findOrganization(
            organizationId,
            true
        );


    if (!organization.isDeleted) {

        throw new ApiError(
            "Organization is not deleted.",
            400
        );

    }


    organization.isDeleted =
        false;

    organization.deletedAt =
        null;


    await organization.save();


    await createOrganizationAuditLog(

        organization,

        AUDIT_ACTIONS.ORGANIZATION_RESTORED,

        "Organization restored by Super Admin.",

        null,

        actor

    );


    return organization;

};


// =====================================================
// SOFT DELETE ORGANIZATION
// =====================================================

const deleteOrganization = async (
    organizationId,
    actor
) => {

    const organization =
        await findOrganization(
            organizationId,
            false
        );


    const previousStatus =
        organization.status;


    organization.isDeleted =
        true;

    organization.deletedAt =
        new Date();


    await organization.save();


    await createOrganizationAuditLog(

        organization,

        AUDIT_ACTIONS.ORGANIZATION_DELETED,

        "Organization soft deleted by Super Admin.",

        previousStatus,

        actor

    );


    return organization;

};


// =====================================================
// EXPORTS
// =====================================================

module.exports = {

    createOrganization,

    updateOrganization,

    getOrganizations,

    getOrganizationDetails,

    activateOrganization,

    suspendOrganization,

    deactivateOrganization,

    restoreOrganization,

    deleteOrganization

};