const service =
    require("../services/adminOrganizationService");

const asyncHandler =
    require("../utils/asyncHandler");

const ApiResponse =
    require("../utils/apiresponse");


// =====================================================
// ACTOR
// =====================================================

const getActor = (req) => {

    return {

        userId:
            req.user.userId,

        ipAddress:
            req.ip,

        userAgent:
            req.headers["user-agent"]

    };

};


// =====================================================
// CREATE ORGANIZATION
// SUPER ADMIN
// =====================================================

const createOrganization =
    asyncHandler(async (req, res) => {

        const data =
            await service.createOrganization(
                req.body,
                getActor(req)
            );

        return ApiResponse.success(
            res,
            201,
            "Organization created successfully.",
            data
        );

    });


// =====================================================
// GET ORGANIZATIONS
// SUPER ADMIN
// =====================================================

const getOrganizations =
    asyncHandler(async (req, res) => {

        const data =
            await service.getOrganizations(
                req.query
            );

        return ApiResponse.success(
            res,
            200,
            "Organizations retrieved successfully.",
            data
        );

    });


// =====================================================
// GET ORGANIZATION DETAILS
// SUPER ADMIN
// =====================================================

const getOrganizationDetails =
    asyncHandler(async (req, res) => {

        const data =
            await service.getOrganizationDetails(
                req.params.id
            );

        return ApiResponse.success(
            res,
            200,
            "Organization details retrieved successfully.",
            data
        );

    });


// =====================================================
// UPDATE ORGANIZATION
// SUPER ADMIN
// =====================================================

const updateOrganization =
    asyncHandler(async (req, res) => {

        const data =
            await service.updateOrganization(
                req.params.id,
                req.body,
                getActor(req)
            );

        return ApiResponse.success(
            res,
            200,
            "Organization updated successfully.",
            data
        );

    });


// =====================================================
// ACTIVATE ORGANIZATION
// SUPER ADMIN
// =====================================================

const activateOrganization =
    asyncHandler(async (req, res) => {

        const data =
            await service.activateOrganization(
                req.params.id,
                getActor(req)
            );

        return ApiResponse.success(
            res,
            200,
            "Organization activated successfully.",
            data
        );

    });


// =====================================================
// SUSPEND ORGANIZATION
// SUPER ADMIN
// =====================================================

const suspendOrganization =
    asyncHandler(async (req, res) => {

        const data =
            await service.suspendOrganization(
                req.params.id,
                getActor(req)
            );

        return ApiResponse.success(
            res,
            200,
            "Organization suspended successfully.",
            data
        );

    });


// =====================================================
// DEACTIVATE ORGANIZATION
// SUPER ADMIN
// =====================================================

const deactivateOrganization =
    asyncHandler(async (req, res) => {

        const data =
            await service.deactivateOrganization(
                req.params.id,
                getActor(req)
            );

        return ApiResponse.success(
            res,
            200,
            "Organization deactivated successfully.",
            data
        );

    });


// =====================================================
// RESTORE ORGANIZATION
// SUPER ADMIN
// =====================================================

const restoreOrganization =
    asyncHandler(async (req, res) => {

        const data =
            await service.restoreOrganization(
                req.params.id,
                getActor(req)
            );

        return ApiResponse.success(
            res,
            200,
            "Organization restored successfully.",
            data
        );

    });


// =====================================================
// SOFT DELETE ORGANIZATION
// SUPER ADMIN
// =====================================================

const deleteOrganization =
    asyncHandler(async (req, res) => {

        const data =
            await service.deleteOrganization(
                req.params.id,
                getActor(req)
            );

        return ApiResponse.success(
            res,
            200,
            "Organization deleted successfully.",
            data
        );

    });


// =====================================================
// EXPORTS
// =====================================================

module.exports = {

    createOrganization,

    getOrganizations,

    getOrganizationDetails,

    updateOrganization,

    activateOrganization,

    suspendOrganization,

    deactivateOrganization,

    restoreOrganization,

    deleteOrganization

};
