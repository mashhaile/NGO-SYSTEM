const bcrypt = require("bcrypt");

const {
    assertStrongPassword,
    getPasswordProblem
} = require("../utils/password");

const User =
    require("../models/user");

const {
    USER_STATUS,
    ROLES
} =
    require("../config/constants");

const PERMISSIONS =
    require("../constants/permissions");

const {
    createAuditLog
} =
    require("../services/auditLogService");


// ==========================================
// HELPER
// CHECK IF CURRENT USER HAS PERMISSION
// ==========================================

const hasPermission = (
    req,
    permission
) => {

    const permissions =
        req.user?.permissions || [];

    // Super Admin
    if (
        permissions.includes("*")
    ) {

        return true;

    }

    return permissions.includes(
        permission
    );

};


// ==========================================
// CHECK ROLE ASSIGNMENT PERMISSION
// ==========================================

const canAssignRole = (
    req,
    role
) => {

    switch (role) {

        case ROLES.DATA_ENTRY:

            return hasPermission(
                req,
                PERMISSIONS.USER_ASSIGN_DATA_ENTRY
            );


        case ROLES.VIEWER:

            return hasPermission(
                req,
                PERMISSIONS.USER_ASSIGN_VIEWER
            );


        case ROLES.ORG_ADMIN:

            return hasPermission(
                req,
                PERMISSIONS.USER_ASSIGN_ORG_ADMIN
            );


        default:

            return false;

    }

};


// ==========================================
// CREATE USER
// ==========================================

const createUserController = async (
    req,
    res
) => {

    try {

        const {
            name,
            email,
            password,
            role
        } = req.body;


        const organizationId =
            req.user.organizationId;


        // ==========================================
        // ORGANIZATION REQUIRED
        // ==========================================

        if (!organizationId) {

            return res.status(400).json({

                success: false,

                message:
                    "Organization is required."

            });

        }


        // ==========================================
        // BASIC VALIDATION
        // ==========================================

        if (
            !name ||
            !email ||
            !password ||
            !role
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Name, email, password and role are required."

            });

        }


        // ==========================================
        // USER CREATE PERMISSION
        // ==========================================

        if (
            !hasPermission(
                req,
                PERMISSIONS.USER_CREATE
            )
        ) {

            return res.status(403).json({

                success: false,

                message:
                    "You do not have permission to create users."

            });

        }


        // ==========================================
        // ROLE ASSIGNMENT PERMISSION
        // ==========================================

        if (
            !canAssignRole(
                req,
                role
            )
        ) {

            return res.status(403).json({

                success: false,

                message:
                    "You do not have permission to assign this role."

            });

        }


        // ==========================================
        // NORMALIZE EMAIL
        // ==========================================

        const normalizedEmail =
            email.trim().toLowerCase();


        // ==========================================
        // CHECK EMAIL
        // ==========================================

        const existing =
            await User.findOne({

                email:
                    normalizedEmail,

                organization:
                    organizationId

            });


        if (existing) {

            return res.status(400).json({

                success: false,

                message:
                    "Email already exists in this organization."

            });

        }


        // ==========================================
        // HASH PASSWORD
        // ==========================================

        const passwordProblem =
            getPasswordProblem(password);

        if (passwordProblem) {
            return res.status(400).json({
                success: false,
                message: passwordProblem
            });
        }

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
        // AUDIT LOG
        // ==========================================

        await createAuditLog({

            organizationId,

            userId:
                req.user.userId,

            action:
                "USER_CREATED",

            module:
                "User",

            entityType:
                "User",

            entityId:
                user._id,

            description:
                `User "${user.name}" created`,

            metadata: {

                name:
                    user.name,

                email:
                    user.email,

                role:
                    user.role

            },

            severity:
                "info",

            ipAddress:
                req.ip,

            userAgent:
                req.headers["user-agent"]

        });


        // ==========================================
        // RESPONSE
        // ==========================================

        return res.status(201).json({

            success: true,

            message:
                "User created successfully.",

            data: {

                id:
                    user._id,

                name:
                    user.name,

                email:
                    user.email,

                role:
                    user.role,

                status:
                    user.status

            }

        });

    }
    catch (error) {

        console.error(
            "Create user error:",
            error
        );

        return res.status(500).json({

            success: false,

            message:
                error.message

        });

    }

};


// ==========================================
// GET USERS
// ==========================================

const getUsersController = async (
    req,
    res
) => {

    try {

        const users =
            await User.find({

                organization:
                    req.user.organizationId,

                isDeleted: {
                    $ne: true
                }

            })
            .select("-password");


        return res.json({

            success: true,

            data:
                users

        });

    }
    catch (error) {

        console.error(
            "Get users error:",
            error
        );

        return res.status(500).json({

            success: false,

            message:
                error.message

        });

    }

};


// ==========================================
// UPDATE USER
// ==========================================

const updateUserController = async (
    req,
    res
) => {

    try {

        const {
            name,
            role,
            status
        } = req.body;


        const user =
            await User.findOne({

                _id:
                    req.params.id,

                organization:
                    req.user.organizationId,

                isDeleted: {
                    $ne: true
                }

            });


        if (!user) {

            return res.status(404).json({

                success: false,

                message:
                    "User not found."

            });

        }


        // ==========================================
        // ROLE CHANGE PERMISSION
        // ==========================================

        if (
            role &&
            role !== user.role
        ) {

            if (
                !canAssignRole(
                    req,
                    role
                )
            ) {

                return res.status(403).json({

                    success: false,

                    message:
                        "You do not have permission to assign this role."

                });

            }

        }


        // ==========================================
        // VALID USER STATUS
        // ==========================================

        const allowedStatuses = [

            USER_STATUS.ACTIVE,

            USER_STATUS.INACTIVE,

            USER_STATUS.SUSPENDED

        ];


        if (
            status &&
            !allowedStatuses.includes(status)
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Invalid user status."

            });

        }


        // ==========================================
        // PREVENT SELF ROLE CHANGE
        // ==========================================

        if (

            user._id.toString() ===
            req.user.userId.toString()

            &&

            role

            &&

            role !== user.role

        ) {

            return res.status(400).json({

                success: false,

                message:
                    "You cannot change your own role."

            });

        }


        // ==========================================
        // PREVENT SELF DEACTIVATION
        // ==========================================

        if (

            user._id.toString() ===
            req.user.userId.toString()

            &&

            status

            &&

            status !== USER_STATUS.ACTIVE

        ) {

            return res.status(400).json({

                success: false,

                message:
                    "You cannot deactivate or suspend your own account."

            });

        }


        // ==========================================
        // OLD DATA
        // ==========================================

        const oldData = {

            name:
                user.name,

            role:
                user.role,

            status:
                user.status

        };


        // ==========================================
        // UPDATE
        // ==========================================

        if (name) {

            user.name =
                name.trim();

        }


        if (role) {

            user.role =
                role;

        }


        if (status) {

            user.status =
                status;

        }


        await user.save();


        // ==========================================
        // AUDIT LOG
        // ==========================================

        await createAuditLog({

            organizationId:
                req.user.organizationId,

            userId:
                req.user.userId,

            action:
                "USER_UPDATED",

            module:
                "User",

            entityType:
                "User",

            entityId:
                user._id,

            description:
                `User "${user.name}" updated`,

            metadata: {

                oldData,

                newData: {

                    name:
                        user.name,

                    role:
                        user.role,

                    status:
                        user.status

                }

            },

            severity:
                "info",

            ipAddress:
                req.ip,

            userAgent:
                req.headers["user-agent"]

        });


        return res.json({

            success: true,

            message:
                "User updated successfully.",

            data: {

                id:
                    user._id,

                name:
                    user.name,

                email:
                    user.email,

                role:
                    user.role,

                status:
                    user.status

            }

        });

    }
    catch (error) {

        console.error(
            "Update user error:",
            error
        );

        return res.status(500).json({

            success: false,

            message:
                error.message

        });

    }

};

// ==========================================
// USER / STAFF LOOKUP
// ==========================================

const getStaffLookup = async (
    req,
    res
) => {

    try {

        const organizationId =
            req.user.organizationId;


        // ==========================================
        // ORGANIZATION REQUIRED
        // ==========================================

        if (!organizationId) {

            return res.status(400).json({

                success: false,

                message:
                    "Organization is required."

            });

        }


        // ==========================================
        // GET ACTIVE ORGANIZATION USERS
        // ==========================================

        const users =
            await User.find({

                organization:
                    organizationId,

                status:
                    USER_STATUS.ACTIVE,

                isDeleted: {
                    $ne: true
                }

            })
            .select(
                "_id name email role"
            )
            .sort({
                name: 1
            })
            .lean();


        // ==========================================
        // RESPONSE
        // ==========================================

        return res.json({

            success: true,

            data:
                users

        });

    }
    catch (error) {

        console.error(
            "User / staff lookup error:",
            error
        );

        return res.status(500).json({

            success: false,

            message:
                error.message

        });

    }

};



// ==========================================
// DEACTIVATE USER
// ==========================================

const deleteUserController = async (
    req,
    res
) => {

    try {

        const user =
            await User.findOne({

                _id:
                    req.params.id,

                organization:
                    req.user.organizationId,

                isDeleted: {
                    $ne: true
                }

            });


        if (!user) {

            return res.status(404).json({

                success: false,

                message:
                    "User not found."

            });

        }


        // ==========================================
        // DELETE USER PERMISSION
        // ==========================================

        if (
            !hasPermission(
                req,
                PERMISSIONS.USER_DELETE
            )
        ) {

            return res.status(403).json({

                success: false,

                message:
                    "You do not have permission to deactivate users."

            });

        }


        // ==========================================
        // PREVENT SELF DEACTIVATION
        // ==========================================

        if (

            user._id.toString() ===
            req.user.userId.toString()

        ) {

            return res.status(400).json({

                success: false,

                message:
                    "You cannot deactivate your own account."

            });

        }


        // ==========================================
        // ALREADY INACTIVE
        // ==========================================

        if (
            user.status ===
            USER_STATUS.INACTIVE
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "User is already inactive."

            });

        }


        // ==========================================
        // DEACTIVATE
        // ==========================================

        user.status =
            USER_STATUS.INACTIVE;


        await user.save();


        // ==========================================
        // AUDIT LOG
        // ==========================================

        await createAuditLog({

            organizationId:
                req.user.organizationId,

            userId:
                req.user.userId,

            action:
                "USER_DELETED",

            module:
                "User",

            entityType:
                "User",

            entityId:
                user._id,

            description:
                `User "${user.name}" deactivated`,

            metadata: {

                email:
                    user.email

            },

            severity:
                "warning",

            ipAddress:
                req.ip,

            userAgent:
                req.headers["user-agent"]

        });


        return res.json({

            success: true,

            message:
                "User deactivated successfully."

        });

    }
    catch (error) {

        console.error(
            "Delete user error:",
            error
        );

        return res.status(500).json({

            success: false,

            message:
                error.message

        });

    }

};


// ==========================================
// EXPORTS
// ==========================================

// ==========================================
// RESET USER PASSWORD (organization admin)
// ==========================================

const resetUserPasswordController = async (
    req,
    res,
    next
) => {

    try {

        const result =
            await require("../services/passwordResetService")
                .resetOrganizationUserPassword(
                    req.user.organizationId,
                    req.params.id,
                    req.user.userId
                );

        res.json({
            success: true,
            message: "Temporary password created. Share it with the user; they must change it at next login.",
            data: result
        });

    }
    catch (error) {

        next(error);

    }

};


module.exports = {

    resetUserPasswordController,

    createUserController,

    getUsersController,

    updateUserController,

    deleteUserController,

    getStaffLookup

};