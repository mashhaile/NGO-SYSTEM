const bcrypt = require("bcrypt");

const User = require("../models/user");

const {
    assertStrongPassword,
    getPasswordProblem
} = require("../utils/password");

const ApiError =
    require("../utils/apiError");

const {
    ROLES,
    USER_STATUS
} = require("../config/constants");


// ==========================================
// GET ORGANIZATION USERS
// ==========================================

const getOrganizationUsers = async (
    organizationId
) => {

    if (!organizationId) {

        throw new ApiError(
            "Organization ID is required.",
            400
        );

    }


    const users =
        await User.find({

            organization:
                organizationId

        })
        .select("-password")
        .sort({
            createdAt: -1
        })
        .lean();


    return users;

};



// ==========================================
// GET ORGANIZATION USER BY ID
// ==========================================

const getOrganizationUserById = async (
    organizationId,
    userId
) => {

    if (!organizationId) {

        throw new ApiError(
            "Organization ID is required.",
            400
        );

    }


    if (!userId) {

        throw new ApiError(
            "User ID is required.",
            400
        );

    }


    const user =
        await User.findOne({

            _id:
                userId,

            organization:
                organizationId

        })
        .select("-password")
        .lean();


    if (!user) {

        throw new ApiError(
            "User not found.",
            404
        );

    }


    return user;

};



// ==========================================
// CREATE ORGANIZATION USER
// ==========================================

const createOrganizationUser = async (
    organizationId,
    userData
) => {

    if (!organizationId) {

        throw new ApiError(
            "Organization ID is required.",
            400
        );

    }


    const {
        name,
        email,
        password,
        role
    } = userData;


    // ==========================================
    // REQUIRED FIELDS
    // ==========================================

    if (!name) {

        throw new ApiError(
            "User name is required.",
            400
        );

    }


    if (!email) {

        throw new ApiError(
            "User email is required.",
            400
        );

    }


    if (!password) {

        throw new ApiError(
            "User password is required.",
            400
        );

    }


    if (!role) {

        throw new ApiError(
            "User role is required.",
            400
        );

    }


    // ==========================================
    // PROTECT SUPER ADMIN
    // ==========================================

    if (
        role ===
        ROLES.SUPER_ADMIN
    ) {

        throw new ApiError(
            "Organization administrators cannot create Super Admin users.",
            403
        );

    }


    // ==========================================
    // ALLOWED ORGANIZATION ROLES
    // ==========================================

    const allowedRoles = [

        ROLES.DATA_ENTRY,

        ROLES.FINANCE,

        ROLES.VIEWER

    ];


    if (
        !allowedRoles.includes(role)
    ) {

        throw new ApiError(
            "Invalid organization user role.",
            400
        );

    }


    // ==========================================
    // NORMALIZE EMAIL
    // ==========================================

    const normalizedEmail =
        email
            .trim()
            .toLowerCase();


    // ==========================================
    // CHECK EMAIL
    // ==========================================

    const existingUser =
        await User.findOne({

            email:
                normalizedEmail

        });


    if (existingUser) {

        throw new ApiError(
            "User email already exists.",
            400
        );

    }


    // ==========================================
    // HASH PASSWORD
    // ==========================================

    assertStrongPassword(password);

    const hashedPassword =
        await bcrypt.hash(
            password,
            10
        );


    // ==========================================
    // CREATE USER
    // ==========================================

    const user =
        await User.create({

            organization:
                organizationId,

            name:
                name.trim(),

            email:
                normalizedEmail,

            password:
                hashedPassword,

            role,

            status:
                USER_STATUS.ACTIVE

        });


    // ==========================================
    // REMOVE PASSWORD
    // ==========================================

    const result =
        user.toObject();


    delete result.password;


    return result;

};



// ==========================================
// UPDATE ORGANIZATION USER
// ==========================================

const updateOrganizationUser = async (
    organizationId,
    userId,
    userData
) => {

    if (!organizationId) {

        throw new ApiError(
            "Organization ID is required.",
            400
        );

    }


    if (!userId) {

        throw new ApiError(
            "User ID is required.",
            400
        );

    }


    // ==========================================
    // FIND USER INSIDE CURRENT ORGANIZATION
    // ==========================================

    const user =
        await User.findOne({

            _id:
                userId,

            organization:
                organizationId

        });


    if (!user) {

        throw new ApiError(
            "User not found.",
            404
        );

    }


    // ==========================================
    // PROTECT ORGANIZATION ADMIN
    // ==========================================
    //
    // Organization Admin should not be
    // modified through this service.
    //
    // We will manage the organization admin
    // separately.
    // ==========================================

    if (
        user.role ===
        ROLES.ORG_ADMIN
    ) {

        throw new ApiError(
            "Organization Admin cannot be modified through user management.",
            403
        );

    }


    // ==========================================
    // UPDATE NAME
    // ==========================================

    if (
        Object.prototype.hasOwnProperty.call(
            userData,
            "name"
        )
    ) {

        if (!userData.name?.trim()) {

            throw new ApiError(
                "User name cannot be empty.",
                400
            );

        }


        user.name =
            userData.name.trim();

    }


    // ==========================================
    // UPDATE EMAIL
    // ==========================================

    if (
        Object.prototype.hasOwnProperty.call(
            userData,
            "email"
        )
    ) {

        const normalizedEmail =
            userData.email
                ?.trim()
                .toLowerCase();


        if (!normalizedEmail) {

            throw new ApiError(
                "User email cannot be empty.",
                400
            );

        }


        const existingUser =
            await User.findOne({

                email:
                    normalizedEmail,

                _id: {
                    $ne:
                        userId
                }

            });


        if (existingUser) {

            throw new ApiError(
                "User email already exists.",
                400
            );

        }


        user.email =
            normalizedEmail;

    }


    // ==========================================
    // UPDATE ROLE
    // ==========================================

    if (
        Object.prototype.hasOwnProperty.call(
            userData,
            "role"
        )
    ) {

        const allowedRoles = [

            ROLES.DATA_ENTRY,

            ROLES.FINANCE,

            ROLES.VIEWER

        ];


        if (
            !allowedRoles.includes(
                userData.role
            )
        ) {

            throw new ApiError(
                "Invalid organization user role.",
                400
            );

        }


        user.role =
            userData.role;

    }


    // ==========================================
    // UPDATE STATUS
    // ==========================================

    if (
        Object.prototype.hasOwnProperty.call(
            userData,
            "status"
        )
    ) {

        if (
            !Object.values(
                USER_STATUS
            ).includes(
                userData.status
            )
        ) {

            throw new ApiError(
                "Invalid user status.",
                400
            );

        }


        user.status =
            userData.status;

    }


    // ==========================================
    // UPDATE PASSWORD
    // ==========================================

    if (
        Object.prototype.hasOwnProperty.call(
            userData,
            "password"
        )
    ) {

        assertStrongPassword(
            userData.password
        );


        user.password =
            await bcrypt.hash(
                userData.password,
                10
            );

    }


    // ==========================================
    // SAVE
    // ==========================================

    await user.save();


    // ==========================================
    // REMOVE PASSWORD
    // ==========================================

    const result =
        user.toObject();


    delete result.password;


    return result;

};



// ==========================================
// DELETE ORGANIZATION USER
// ==========================================

const deleteOrganizationUser = async (
    organizationId,
    userId
) => {

    if (!organizationId) {

        throw new ApiError(
            "Organization ID is required.",
            400
        );

    }


    if (!userId) {

        throw new ApiError(
            "User ID is required.",
            400
        );

    }


    const user =
        await User.findOne({

            _id:
                userId,

            organization:
                organizationId

        });


    if (!user) {

        throw new ApiError(
            "User not found.",
            404
        );

    }


    // ==========================================
    // PROTECT ORGANIZATION ADMIN
    // ==========================================

    if (
        user.role ===
        ROLES.ORG_ADMIN
    ) {

        throw new ApiError(
            "Organization Admin cannot be deleted through user management.",
            403
        );

    }


    // ==========================================
    // DELETE USER
    // ==========================================

    await User.findByIdAndDelete(
        userId
    );


    return {

        id:
            userId,

        deleted:
            true

    };

};

// ==========================================
// GET ORGANIZATION USER LOOKUP
// ==========================================

const getOrganizationUserLookup = async (
    organizationId
) => {

    if (!organizationId) {

        throw new ApiError(
            "Organization ID is required.",
            400
        );

    }


    const users =
        await User.find({

            organization:
                organizationId,

            status:
                USER_STATUS.ACTIVE

        })
        .select("_id name email role")
        .sort({
            name: 1
        })
        .lean();


    return users;

};

// ==========================================
// EXPORTS
// ==========================================
module.exports = {

    getOrganizationUsers,

    getOrganizationUserById,

    getOrganizationUserLookup,

    createOrganizationUser,

    updateOrganizationUser,

    deleteOrganizationUser

};