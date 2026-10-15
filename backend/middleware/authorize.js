const ApiError =
    require("../utils/ApiError");



// ==========================================
// AUTHORIZE MIDDLEWARE
//
// Responsibilities:
//
// 1. Require authenticated user
// 2. Check requested permission
// 3. Allow Super Admin through "*"
// 4. Never perform subscription checks
//
// RBAC answers:
//
// "Is this USER allowed to perform this action?"
//
// Subscription middleware answers:
//
// "Is this ORGANIZATION allowed to use this capability?"
//
// These responsibilities must remain separate.
// ==========================================

const authorize = (

    requiredPermission

) => {


    return (

        req,

        res,

        next

    ) => {


        try {


            // ==========================================
            // AUTHENTICATION
            // ==========================================

            if (!req.user) {

                throw new ApiError(

                    "Authentication required.",

                    401

                );

            }



            // ==========================================
            // VALIDATE PERMISSION
            // ==========================================

            if (!requiredPermission) {

                throw new ApiError(

                    "Permission is required.",

                    500

                );

            }



            // ==========================================
            // GET PERMISSIONS
            //
            // authMiddleware already resolved the
            // permissions for the current role.
            // ==========================================

            const permissions =
                req.user.permissions || [];



            // ==========================================
            // SUPER ADMIN
            //
            // "*" represents platform-wide access.
            // ==========================================

            if (

                permissions.includes("*")

            ) {

                return next();

            }



            // ==========================================
            // CHECK REQUIRED PERMISSION
            // ==========================================

            const hasPermission =
                permissions.includes(

                    requiredPermission

                );



            if (!hasPermission) {

                throw new ApiError(

                    "Access denied. Insufficient permissions.",

                    403,

                    [

                        {

                            type:
                                "PERMISSION_DENIED",

                            permission:
                                requiredPermission,

                            role:
                                req.user.role

                        }

                    ]

                );

            }



            // ==========================================
            // AUTHORIZED
            // ==========================================

            return next();

        }

        catch (error) {

            return next(error);

        }

    };

};



module.exports =
    authorize;