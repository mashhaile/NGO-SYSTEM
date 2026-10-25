const roleService = require("./roleService");
const bcrypt = require("bcrypt");

const User = require("../models/user");

const generateToken = require("../utils/generateToken");

const ApiError = require("../utils/apiError");

const {
    assertStrongPassword,
    hashPassword
} = require("../utils/password");

const {
    USER_STATUS
} = require("../config/constants");

const rolePermissions =
    require("../constants/rolepermissions");


// ==========================================
// LOGIN LOCKOUT
// ==========================================
//
// After MAX_FAILED_LOGINS wrong passwords in a row the
// account is locked for LOCK_MINUTES. The per-IP rate
// limit in server.js stays in place as well.
//
// ==========================================

const MAX_FAILED_LOGINS = 5;

const LOCK_MINUTES = 15;

const INVALID_CREDENTIALS =
    "Invalid email or password";


const toLoginUser = (user) => ({

    id: user._id,

    organizationId:
        user.organization,

    name: user.name,

    email: user.email,

    role: user.role,

    permissions:
        rolePermissions[user.role] || [],
    mustChangePassword:
        Boolean(user.mustChangePassword)
});

// with a custom role: its permissions and name
const withRole = async (loginUser, user) => ({
    ...loginUser,
    permissions: await roleService.permissionsOf(user),
    roleName: await roleService.roleNameOf(user)
});


// ==========================================
// LOGIN
// ==========================================

const login = async ({
    email,
    password
}) => {

    // Emails are stored lowercase.

    const normalizedEmail =
        String(email || "").trim().toLowerCase();

    const user =
        normalizedEmail
            ? await User.findOne({
                email: normalizedEmail
            })
            : null;


    if (!user) {

        throw new ApiError(
            INVALID_CREDENTIALS,
            401
        );

    }


    // ==========================================
    // LOCKED?
    // ==========================================

    if (
        user.lockUntil &&
        user.lockUntil > new Date()
    ) {

        const minutes =
            Math.max(
                1,
                Math.ceil((user.lockUntil - Date.now()) / 60000)
            );

        throw new ApiError(
            `Too many failed attempts. This account is locked for ${minutes} more minute${minutes === 1 ? "" : "s"}.`,
            423
        );

    }


    // ==========================================
    // PASSWORD CHECK
    // ==========================================

    const isMatch =
        await bcrypt.compare(
            String(password || ""),
            user.password
        );


    if (!isMatch) {

        const attempts =
            (user.failedLoginAttempts || 0) + 1;

        const update = {
            failedLoginAttempts: attempts
        };

        if (attempts >= MAX_FAILED_LOGINS) {

            update.failedLoginAttempts = 0;

            update.lockUntil =
                new Date(Date.now() + LOCK_MINUTES * 60000);

        }

        await User.updateOne(
            {
                _id: user._id
            },
            {
                $set: update
            }
        );

        if (update.lockUntil) {

            throw new ApiError(
                `Too many failed attempts. This account is locked for ${LOCK_MINUTES} minutes.`,
                423
            );

        }

        throw new ApiError(
            INVALID_CREDENTIALS,
            401
        );

    }


    // ==========================================
    // CHECK USER STATUS
    // ==========================================
    //
    // Checked after the password so an inactive
    // account does not reveal itself to guessers.
    //
    // ==========================================

    if (
        user.status !== USER_STATUS.ACTIVE
    ) {

        throw new ApiError(
            "Account is inactive. Contact administrator.",
            403
        );

    }


    // ==========================================
    // SUCCESS
    // ==========================================

    await User.updateOne(
        {
            _id: user._id
        },
        {
            $set: {
                lastLogin: new Date(),
                failedLoginAttempts: 0,
                lockUntil: null
            }
        }
    );


    return {

        user:
            await withRole(toLoginUser(user), user),

        token:
            generateToken(user)

    };

};


// ==========================================
// CHANGE OWN PASSWORD
// ==========================================
//
// Requires the current password. Ends the user's other
// sessions (tokens issued before the change) and
// returns a fresh token for this one.
//
// ==========================================

const changePassword = async (
    userId,
    {
        currentPassword,
        newPassword
    }
) => {

    const user =
        await User.findById(userId);

    if (!user) {
        throw new ApiError(
            "User not found",
            404
        );
    }

    const isMatch =
        await bcrypt.compare(
            String(currentPassword || ""),
            user.password
        );

    if (!isMatch) {
        throw new ApiError(
            "Current password is incorrect.",
            400,
            [
                {
                    field: "currentPassword",
                    message: "Current password is incorrect."
                }
            ]
        );
    }

    assertStrongPassword(
        newPassword,
        {
            email: user.email
        }
    );

    if (await bcrypt.compare(newPassword, user.password)) {
        throw new ApiError(
            "The new password must be different from the current one.",
            400,
            [
                {
                    field: "newPassword",
                    message: "Choose a password you have not used just now."
                }
            ]
        );
    }

    user.password =
        await hashPassword(newPassword);

    user.passwordChangedAt =
        new Date();

    user.mustChangePassword =
        false;

    user.failedLoginAttempts = 0;

    user.lockUntil = null;

    await user.save();

    return {

        user:
            await withRole(toLoginUser(user), user),

        token:
            generateToken(user)

    };

};


// ==========================================
// CURRENT USER
// ==========================================

const getCurrentUser = async (userId) => {

    const user = await User.findById(userId)

        .select("-password")

        .populate(
            "organization",
            "name organizationCode status"
        );


    if (!user) {

        throw new Error(
            "User not found"
        );

    }


    // ==========================================
    // GET ROLE PERMISSIONS
    // ==========================================

    const permissions =
        await roleService.permissionsOf(user);


    // ==========================================
    // RETURN USER WITH PERMISSIONS
    // ==========================================

    return {

        id: user._id,

        organizationId:
            user.organization?._id ||
            user.organization,

        name: user.name,

        email: user.email,

        role: user.role,
        roleName: await roleService.roleNameOf(user),
        status: user.status,
        permissions,

        mustChangePassword:
            Boolean(user.mustChangePassword),

        organization:
            user.organization

    };

};


module.exports = {

    login,

    changePassword,

    getCurrentUser

};
