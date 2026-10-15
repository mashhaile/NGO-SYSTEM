const {
    createLookup,
    getLookups,
    createLookupsBulk,
    getLookupCategoriesByModule,
    getLookupByModuleAndCategory,
    getLookupById,
    updateLookup,
    deleteLookup
} = require("../services/lookupService");


const {
    logActivity
} = require("../utils/auditLogger");


// =====================================================
// HELPERS
// =====================================================

const getOrganizationId = (req) => {

    return (
        req.user?.organizationId ||
        req.user?.organization ||
        req.organizationId ||
        req.organization?._id ||
        null
    );

};


const getUserId = (req) => {

    return (
        req.user?.userId ||
        req.user?._id ||
        req.user?.id ||
        null
    );

};


const getErrorStatus = (
    error,
    fallback = 400
) => {

    if (error?.statusCode) {

        return error.statusCode;

    }

    if (error?.name === "ValidationError") {

        return 400;

    }

    if (error?.name === "CastError") {

        return 400;

    }

    if (error?.code === 11000) {

        return 409;

    }

    return fallback;

};


// =====================================================
// CREATE
// =====================================================

const createLookupController = async (
    req,
    res
) => {

    try {

        const organizationId =
            getOrganizationId(req);

        const userId =
            getUserId(req);


        if (!organizationId) {

            return res.status(400).json({

                success: false,

                message:
                    "Organization is required."

            });

        }


        const lookup =
            await createLookup(

                req.body || {},

                organizationId,

                userId

            );


        try {

            await logActivity({

                req,

                action:
                    "CREATE",

                module:
                    "Lookup",

                entityType:
                    "Lookup",

                entityId:
                    lookup._id,

                description:
                    `Lookup "${lookup.value}" created in ${lookup.module}/${lookup.category}`

            });

        }

        catch (auditError) {

            console.error(
                "Lookup audit log error:",
                auditError
            );

        }


        return res.status(201).json({

            success: true,

            message:
                "Lookup created successfully",

            data:
                lookup

        });

    }

    catch (error) {

        console.error(
            "Create lookup error:",
            error
        );


        return res.status(
            getErrorStatus(error)
        ).json({

            success: false,

            message:
                error?.message ||
                "Failed to create lookup."

        });

    }

};


// =====================================================
// BULK CREATE
// =====================================================

const createLookupsBulkController = async (
    req,
    res
) => {

    try {

        const body =
            req.body || {};


        const organizationId =
            getOrganizationId(req);

        const userId =
            getUserId(req);


        if (!organizationId) {

            return res.status(400).json({

                success: false,

                message:
                    "Organization is required."

            });

        }


        const module =
            body.module;

        const category =
            body.category;

        const values =
            body.values;

        const active =
            body.active !== undefined
                ? body.active
                : true;


        if (
            !module ||
            String(module).trim() === ""
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Module is required."

            });

        }


        if (
            !category ||
            String(category).trim() === ""
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Lookup category is required."

            });

        }


        if (
            !Array.isArray(values) ||
            values.length === 0
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "At least one lookup value is required."

            });

        }


        const lookups =
            await createLookupsBulk(

                module,

                category,

                values,

                organizationId,

                userId,

                active

            );


        for (
            const lookup
            of lookups
        ) {

            try {

                await logActivity({

                    req,

                    action:
                        "CREATE",

                    module:
                        "Lookup",

                    entityType:
                        "Lookup",

                    entityId:
                        lookup._id,

                    description:
                        `Lookup "${lookup.value}" created in ${lookup.module}/${lookup.category}`

                });

            }

            catch (auditError) {

                console.error(
                    "Lookup audit log error:",
                    auditError
                );

            }

        }


        return res.status(201).json({

            success: true,

            message:
                lookups.length === 1
                    ? "Lookup created successfully"
                    : `${lookups.length} lookups created successfully`,

            data:
                lookups

        });

    }

    catch (error) {

        console.error(
            "Bulk lookup creation error:",
            error
        );


        return res.status(
            getErrorStatus(error)
        ).json({

            success: false,

            message:
                error?.message ||
                "Failed to create lookups."

        });

    }

};


// =====================================================
// GET ALL
// =====================================================

const getLookupsController = async (
    req,
    res
) => {

    try {

        const organizationId =
            getOrganizationId(req);


        if (!organizationId) {

            return res.status(400).json({

                success: false,

                message:
                    "Organization is required."

            });

        }


        const data =
            await getLookups(

                organizationId,

                req.query || {}

            );


        return res.json({

            success: true,

            data

        });

    }

    catch (error) {

        console.error(
            "Get lookups error:",
            error
        );


        return res.status(
            getErrorStatus(
                error,
                500
            )
        ).json({

            success: false,

            message:
                error?.message ||
                "Failed to load lookups."

        });

    }

};


// =====================================================
// CATEGORIES
// =====================================================

const getLookupCategoriesByModuleController = async (
    req,
    res
) => {

    try {

        const organizationId =
            getOrganizationId(req);


        if (!organizationId) {

            return res.status(400).json({

                success: false,

                message:
                    "Organization is required."

            });

        }


        const module =
            req.params?.module;


        if (
            !module ||
            String(module).trim() === ""
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Module is required."

            });

        }


        const data =
            await getLookupCategoriesByModule(

                module,

                organizationId

            );


        return res.json({

            success: true,

            data

        });

    }

    catch (error) {

        console.error(
            "Get lookup categories error:",
            error
        );


        return res.status(
            getErrorStatus(error)
        ).json({

            success: false,

            message:
                error?.message ||
                "Failed to load lookup categories."

        });

    }

};


// =====================================================
// MODULE + CATEGORY
// =====================================================
//
// Supports:
//
// GET /lookups/ServiceDelivery/ServiceCategory
//
// GET /lookups/ServiceDelivery/ServiceType?parentLookup=ID
//
// =====================================================

const getLookupByModuleAndCategoryController = async (
    req,
    res
) => {

    try {

        const organizationId =
            getOrganizationId(req);


        if (!organizationId) {

            return res.status(400).json({

                success: false,

                message:
                    "Organization is required."

            });

        }


        const module =
            req.params?.module;


        const category =
            req.params?.category;


        const parentLookup =
            req.query?.parentLookup || null;


        if (
            !module ||
            String(module).trim() === ""
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Module is required."

            });

        }


        if (
            !category ||
            String(category).trim() === ""
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Lookup category is required."

            });

        }


        const data =
            await getLookupByModuleAndCategory(

                module,

                category,

                organizationId,

                parentLookup

            );


        return res.json({

            success: true,

            data

        });

    }

    catch (error) {

        console.error(
            "Get lookup module/category error:",
            error
        );


        return res.status(
            getErrorStatus(error)
        ).json({

            success: false,

            message:
                error?.message ||
                "Failed to load lookup values."

        });

    }

};


// =====================================================
// GET BY ID
// =====================================================

const getLookupByIdController = async (
    req,
    res
) => {

    try {

        const organizationId =
            getOrganizationId(req);


        if (!organizationId) {

            return res.status(400).json({

                success: false,

                message:
                    "Organization is required."

            });

        }


        const id =
            req.params?.id;


        if (!id) {

            return res.status(400).json({

                success: false,

                message:
                    "Lookup ID is required."

            });

        }


        const data =
            await getLookupById(

                id,

                organizationId

            );


        return res.json({

            success: true,

            data

        });

    }

    catch (error) {

        console.error(
            "Get lookup by ID error:",
            error
        );


        return res.status(
            getErrorStatus(
                error,
                404
            )
        ).json({

            success: false,

            message:
                error?.message ||
                "Lookup not found."

        });

    }

};


// =====================================================
// UPDATE
// =====================================================

const updateLookupController = async (
    req,
    res
) => {

    try {

        const organizationId =
            getOrganizationId(req);

        const userId =
            getUserId(req);


        if (!organizationId) {

            return res.status(400).json({

                success: false,

                message:
                    "Organization is required."

            });

        }


        const id =
            req.params?.id;


        if (!id) {

            return res.status(400).json({

                success: false,

                message:
                    "Lookup ID is required."

            });

        }


        const data =
            await updateLookup(

                id,

                req.body || {},

                organizationId,

                userId

            );


        try {

            await logActivity({

                req,

                action:
                    "UPDATE",

                module:
                    "Lookup",

                entityType:
                    "Lookup",

                entityId:
                    data._id,

                description:
                    `Lookup "${data.value}" updated in ${data.module}/${data.category}`

            });

        }

        catch (auditError) {

            console.error(
                "Lookup audit log error:",
                auditError
            );

        }


        return res.json({

            success: true,

            message:
                "Lookup updated successfully",

            data

        });

    }

    catch (error) {

        console.error(
            "Update lookup error:",
            error
        );


        return res.status(
            getErrorStatus(error)
        ).json({

            success: false,

            message:
                error?.message ||
                "Failed to update lookup."

        });

    }

};


// =====================================================
// DEACTIVATE
// =====================================================

const deleteLookupController = async (
    req,
    res
) => {

    try {

        const organizationId =
            getOrganizationId(req);

        const userId =
            getUserId(req);


        if (!organizationId) {

            return res.status(400).json({

                success: false,

                message:
                    "Organization is required."

            });

        }


        const id =
            req.params?.id;


        if (!id) {

            return res.status(400).json({

                success: false,

                message:
                    "Lookup ID is required."

            });

        }


        const lookup =
            await deleteLookup(

                id,

                organizationId,

                userId

            );


        try {

            await logActivity({

                req,

                action:
                    "DEACTIVATE",

                module:
                    "Lookup",

                entityType:
                    "Lookup",

                entityId:
                    lookup._id,

                description:
                    `Lookup "${lookup.value}" deactivated from ${lookup.module}/${lookup.category}`

            });

        }

        catch (auditError) {

            console.error(
                "Lookup audit log error:",
                auditError
            );

        }


        return res.json({

            success: true,

            message:
                "Lookup deactivated successfully",

            data:
                lookup

        });

    }

    catch (error) {

        console.error(
            "Delete lookup error:",
            error
        );


        return res.status(
            getErrorStatus(error)
        ).json({

            success: false,

            message:
                error?.message ||
                "Failed to deactivate lookup."

        });

    }

};


// =====================================================
// EXPORT
// =====================================================

module.exports = {

    createLookupController,

    createLookupsBulkController,

    getLookupsController,

    getLookupCategoriesByModuleController,

    getLookupByModuleAndCategoryController,

    getLookupByIdController,

    updateLookupController,

    deleteLookupController

};