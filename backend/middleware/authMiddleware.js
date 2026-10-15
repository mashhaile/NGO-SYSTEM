const jwt =
    require("jsonwebtoken");

const User =
    require("../models/User");

const Organization =
    require("../models/Organization");

const {
    USER_STATUS,
    ROLES,
    ORGANIZATION_STATUS
} = require("../config/constants");

const rolePermissions =
    require("../constants/rolePermissions");


// ==========================================
// AUTHENTICATION MIDDLEWARE
//
// Responsibilities:
//
// 1. Validate JWT
// 2. Load current user
// 3. Verify user status
// 4. Verify organization status
// 5. Verify organization is not deleted
// 6. Build normalized authentication context
// 7. Resolve Super Admin organization context
//
// Does NOT:
//
// - check subscription
// - check plan features
// - check resource limits
// - check specific permissions
//
// Those belong to separate middleware.
// ==========================================

const authMiddleware = async (

    req,

    res,

    next

) => {

    try {

        // ==========================================
        // AUTHORIZATION HEADER
        // ==========================================

        const authHeader =
            req.headers.authorization;


        if (
            !authHeader ||
            !authHeader.startsWith("Bearer ")
        ) {

            return res.status(401).json({

                success: false,

                message:
                    "Authentication token is required."

            });

        }


        // ==========================================
        // EXTRACT TOKEN
        // ==========================================

        const token =
            authHeader
                .substring(7)
                .trim();


        if (!token) {

            return res.status(401).json({

                success: false,

                message:
                    "Authentication token is required."

            });

        }


        // ==========================================
        // VERIFY JWT
        // ==========================================

        let decoded;


        try {

            decoded =
                jwt.verify(

                    token,

                    process.env.JWT_SECRET

                );

        }

        catch (error) {

            if (
                error.name ===
                "TokenExpiredError"
            ) {

                return res.status(401).json({

                    success: false,

                    message:
                        "Authentication token has expired."

                });

            }


            return res.status(401).json({

                success: false,

                message:
                    "Invalid authentication token."

            });

        }


        // ==========================================
        // VALIDATE JWT PAYLOAD
        // ==========================================

        if (!decoded.userId) {

            return res.status(401).json({

                success: false,

                message:
                    "Invalid authentication token."

            });

        }


        // ==========================================
        // LOAD CURRENT USER
        // ==========================================

        const user =
            await User.findById(

                decoded.userId

            ).lean();


        if (!user) {

            return res.status(401).json({

                success: false,

                message:
                    "User account not found."

            });

        }


        // ==========================================
        // USER STATUS
        // ==========================================

        if (
            user.status !==
            USER_STATUS.ACTIVE
        ) {

            return res.status(403).json({

                success: false,

                message:
                    "User account is not active."

            });

        }


        // ==========================================
        // ROLE
        // ==========================================

        const role =
            user.role;


        // ==========================================
        // ROLE VALIDATION
        // ==========================================

        if (!role) {

            return res.status(403).json({

                success: false,

                message:
                    "User role is not assigned."

            });

        }


        // ==========================================
        // ROLE PERMISSIONS
        // ==========================================

        const permissions =
            rolePermissions[role] || [];


        // ==========================================
        // SUPER ADMIN
        //
        // Platform-level user.
        //
        // Organization is optional.
        //
        // If x-organization-id exists,
        // resolve and validate it here.
        //
        // This becomes the central organization
        // context for downstream middleware/controllers.
        // ==========================================

        if (
            role ===
            ROLES.SUPER_ADMIN
        ) {

            const selectedOrganizationId =
                req.headers[
                    "x-organization-id"
                ] || null;


            let selectedOrganization =
                null;


            // ======================================
            // RESOLVE SELECTED ORGANIZATION
            // ======================================

            if (
                selectedOrganizationId
            ) {

                selectedOrganization =
                    await Organization.findOne({

                        _id:
                            selectedOrganizationId,

                        isDeleted:
                            false

                    })
                    .select(
                        "_id name organizationCode status isDeleted"
                    )
                    .lean();


                if (
                    !selectedOrganization
                ) {

                    return res.status(404).json({

                        success: false,

                        message:
                            "Selected organization was not found."

                    });

                }

            }


            // ======================================
            // NORMALIZED SUPER ADMIN CONTEXT
            // ======================================

            req.user = {

                userId:
                    user._id,

                organizationId:
                    selectedOrganization?._id ||
                    null,

                role,

                permissions

            };


            // ======================================
            // CENTRAL ORGANIZATION CONTEXT
            // ======================================

            req.organizationId =
                selectedOrganization?._id ||
                null;


            req.organization =
                selectedOrganization ||
                null;


            return next();

        }


        // ==========================================
        // ORGANIZATION USER
        // ==========================================

        if (!user.organization) {

            return res.status(403).json({

                success: false,

                message:
                    "User is not associated with an organization."

            });

        }


        // ==========================================
        // LOAD ORGANIZATION
        //
        // IMPORTANT:
        //
        // Do not trust organization status
        // from JWT.
        //
        // Always load current organization state.
        // ==========================================

        const organization =
            await Organization.findById(

                user.organization

            )
            .select(
                "_id name organizationCode status isDeleted"
            )
            .lean();


        if (!organization) {

            return res.status(403).json({

                success: false,

                message:
                    "Organization not found."

            });

        }


        // ==========================================
        // ORGANIZATION SOFT DELETE
        // ==========================================

        if (
            organization.isDeleted
        ) {

            return res.status(403).json({

                success: false,

                message:
                    "Organization is no longer active."

            });

        }


        // ==========================================
        // ORGANIZATION LIFECYCLE STATUS
        //
        // Subscription status is NOT checked here.
        // ==========================================

        const allowedOrganizationStatuses = [

            ORGANIZATION_STATUS.TRIAL,

            ORGANIZATION_STATUS.ACTIVE

        ];


        if (
            !allowedOrganizationStatuses.includes(
                organization.status
            )
        ) {

            if (
                organization.status ===
                ORGANIZATION_STATUS.SUSPENDED
            ) {

                return res.status(403).json({

                    success: false,

                    message:
                        "Organization is suspended."

                });

            }


            if (
                organization.status ===
                ORGANIZATION_STATUS.INACTIVE
            ) {

                return res.status(403).json({

                    success: false,

                    message:
                        "Organization is inactive."

                });

            }


            return res.status(403).json({

                success: false,

                message:
                    "Organization is not active."

            });

        }


        // ==========================================
        // NORMALIZED USER CONTEXT
        // ==========================================

        req.user = {

            userId:
                user._id,

            organizationId:
                organization._id,

            role,

            permissions

        };


        // ==========================================
        // CENTRAL ORGANIZATION CONTEXT
        //
        // For normal organization users,
        // their own organization is always used.
        //
        // The Super Admin header is ignored here.
        // ==========================================

        req.organizationId =
            organization._id;


        req.organization =
            organization;


        // ==========================================
        // CONTINUE
        // ==========================================

        return next();

    }

    catch (error) {

        console.error(

            "Authentication middleware error:",

            error

        );


        return res.status(401).json({

            success: false,

            message:
                "Authentication failed."

        });

    }

};


module.exports =
    authMiddleware;