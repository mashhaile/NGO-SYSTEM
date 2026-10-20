const mongoose = require("mongoose");

const User = require("../models/user");

const ApiError = require("../utils/apiError");

const {
    generateTemporaryPassword,
    hashPassword
} = require("../utils/password");

const {
    ROLES
} = require("../config/constants");


// =====================================================
// ADMIN PASSWORD RESET
// =====================================================
//
// An admin sets a temporary password for a user. The
// user must choose a new one at next login
// (mustChangePassword), their current sessions end
// (passwordChangedAt) and any lockout is cleared.
//
// The temporary password is returned ONCE to the admin
// to pass on; it is never stored in plain text.
//
// Organization admins: users of their own organization,
// never super admins, never themselves.
// Super admin: any user except themselves.
//
// =====================================================

const applyReset = async (user) => {

    const temporaryPassword =
        generateTemporaryPassword();

    await User.updateOne(
        {
            _id: user._id
        },
        {
            $set: {
                password: await hashPassword(temporaryPassword),
                mustChangePassword: true,
                passwordChangedAt: new Date(),
                failedLoginAttempts: 0,
                lockUntil: null
            }
        }
    );

    return {
        user: {
            id: user._id,
            name: user.name,
            email: user.email
        },
        temporaryPassword
    };

};


const assertNotSelf = (userId, actorUserId) => {

    if (String(userId) === String(actorUserId)) {
        throw new ApiError(
            "Use Change Password to change your own password.",
            400
        );
    }

};


const resetOrganizationUserPassword = async (
    organizationId,
    userId,
    actorUserId
) => {

    if (!mongoose.isValidObjectId(userId)) {
        throw new ApiError("User not found.", 404);
    }

    assertNotSelf(userId, actorUserId);

    const user =
        await User.findOne({
            _id: userId,
            organization: organizationId,
            isDeleted: {
                $ne: true
            }
        })
            .select("name email role")
            .lean();

    if (!user) {
        throw new ApiError("User not found.", 404);
    }

    if (user.role === ROLES.SUPER_ADMIN) {
        throw new ApiError(
            "A super admin password cannot be reset here.",
            403
        );
    }

    return applyReset(user);

};


const resetAnyUserPassword = async (
    userId,
    actorUserId
) => {

    if (!mongoose.isValidObjectId(userId)) {
        throw new ApiError("User not found.", 404);
    }

    assertNotSelf(userId, actorUserId);

    const user =
        await User.findById(userId)
            .select("name email role")
            .lean();

    if (!user) {
        throw new ApiError("User not found.", 404);
    }

    return applyReset(user);

};


module.exports = {
    resetOrganizationUserPassword,
    resetAnyUserPassword
};
