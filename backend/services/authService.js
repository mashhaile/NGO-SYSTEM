const bcrypt = require("bcrypt");

const User = require("../models/user");

const generateToken = require("../utils/generateToken");

const {
    USER_STATUS
} = require("../config/constants");

const rolePermissions =
    require("../constants/rolepermissions");


// ==========================================
// LOGIN
// ==========================================

const login = async ({
    email,
    password
}) => {

    const user = await User.findOne({
        email
    });


    if (!user) {

        throw new Error(
            "Invalid email or password"
        );

    }


    // ==========================================
    // CHECK USER STATUS
    // ==========================================

    if (
        user.status !== USER_STATUS.ACTIVE
    ) {

        throw new Error(
            "Account is inactive. Contact administrator."
        );

    }


    // ==========================================
    // PASSWORD CHECK
    // ==========================================

    const isMatch = await bcrypt.compare(
        password,
        user.password
    );


    if (!isMatch) {

        throw new Error(
            "Invalid email or password"
        );

    }


    // ==========================================
    // UPDATE LOGIN TIME
    // ==========================================

    user.lastLogin = new Date();

    await user.save();


    // ==========================================
    // GET ROLE PERMISSIONS
    // ==========================================

    const permissions =
        rolePermissions[user.role] || [];


    // ==========================================
    // GENERATE TOKEN
    // ==========================================

    const token =
        generateToken(user);


    // ==========================================
    // RETURN LOGIN DATA
    // ==========================================

    return {

        user: {

            id: user._id,

            organizationId:
                user.organization,

            name: user.name,

            email: user.email,

            role: user.role,

            permissions

        },

        token

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
        rolePermissions[user.role] || [];


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

        status: user.status,

        permissions,

        organization:
            user.organization

    };

};


module.exports = {

    login,

    getCurrentUser

};