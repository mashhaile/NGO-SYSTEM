const ApiError =
    require("../utils/ApiError");

const {
    ROLES
} = require("../config/constants");


// ======================================================
// REQUIRE ROLE MIDDLEWARE
//
// PURPOSE:
//
// Checks the user's actual authenticated role.
//
// This is different from:
//
// authorize()
//     -> checks permission
//
// subscriptionMiddleware
//     -> checks organization subscription
//
// featureMiddleware
//     -> checks plan feature
//
// limitMiddleware
//     -> checks plan resource limit
// ======================================================

const requireRole = (
    ...roles
) => {

    return (
        req,
        res,
        next
    ) => {

        try {

            // ==================================================
            // AUTHENTICATION
            // ==================================================

            if (!req.user) {

                throw new ApiError(
                    "Authentication required.",
                    401
                );

            }


            // ==================================================
            // VALIDATE CONFIGURATION
            // ==================================================

            if (
                roles.length === 0
            ) {

                throw new ApiError(
                    "At least one role is required.",
                    500
                );

            }


            // ==================================================
            // SUPER ADMIN
            //
            // If explicitly included in the allowed roles,
            // it passes normally.
            // ==================================================

            if (
                roles.includes(
                    ROLES.SUPER_ADMIN
                ) &&
                req.user.role ===
                    ROLES.SUPER_ADMIN
            ) {

                return next();

            }


            // ==================================================
            // ROLE CHECK
            // ==================================================

            if (
                !roles.includes(
                    req.user.role
                )
            ) {

                throw new ApiError(

                    "Access denied: insufficient role permissions.",

                    403,

                    [

                        {

                            type:
                                "ROLE_DENIED",

                            requiredRoles:
                                roles,

                            role:
                                req.user.role

                        }

                    ]

                );

            }


            // ==================================================
            // AUTHORIZED
            // ==================================================

            return next();

        }

        catch (error) {

            return next(error);

        }

    };

};


module.exports =
    requireRole;