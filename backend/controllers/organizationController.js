const organizationService =
    require("../services/organizationservice");

const ApiResponse =
    require("../utils/apiresponse");

const asyncHandler =
    require("../utils/asyncHandler");



// ==========================================
// CREATE ORGANIZATION
// ==========================================

const createOrganization =
    asyncHandler(async (req, res) => {

        const result =
            await organizationService.createOrganization(
                req.body
            );


        return ApiResponse.success(

            res,

            201,

            "Organization created successfully.",

            result

        );

    });



// ==========================================
// GET CURRENT ORGANIZATION
// ==========================================

const getMyOrganization =
    asyncHandler(async (req, res) => {

        const result =
            await organizationService.getMyOrganization(

                req.user.organizationId,

                req.user.id

            );


        return ApiResponse.success(

            res,

            200,

            "Organization retrieved successfully.",

            result

        );

    });



// ==========================================
// UPDATE CURRENT ORGANIZATION
// ==========================================

const updateMyOrganization =
    asyncHandler(async (req, res) => {

        const result =
            await organizationService.updateMyOrganization(

                req.user.organizationId,

                req.body

            );


        return ApiResponse.success(

            res,

            200,

            "Organization updated successfully.",

            result

        );

    });



// ==========================================
// SUPER ADMIN
// GET ALL ORGANIZATIONS
// ==========================================

const getAllOrganizations =
    asyncHandler(async (req, res) => {

        const result =
            await organizationService.getAllOrganizations();


        return ApiResponse.success(

            res,

            200,

            "Organizations retrieved successfully.",

            result

        );

    });



// ==========================================
// SUPER ADMIN
// GET ORGANIZATION BY ID
// ==========================================

const getOrganizationById =
    asyncHandler(async (req, res) => {

        const result =
            await organizationService.getOrganizationById(

                req.params.id,

                req.user.id

            );


        return ApiResponse.success(

            res,

            200,

            "Organization retrieved successfully.",

            result

        );

    });



// ==========================================
// SUPER ADMIN
// UPDATE ORGANIZATION
// ==========================================

const updateOrganization =
    asyncHandler(async (req, res) => {

        const result =
            await organizationService.updateOrganization(

                req.params.id,

                req.body

            );


        return ApiResponse.success(

            res,

            200,

            "Organization updated successfully.",

            result

        );

    });



// ==========================================
// SUPER ADMIN
// UPDATE ORGANIZATION STATUS
// ==========================================

const updateOrganizationStatus =
    asyncHandler(async (req, res) => {

        const {
            status
        } = req.body;


        const result =
            await organizationService.updateOrganizationStatus(

                req.params.id,

                status

            );


        return ApiResponse.success(

            res,

            200,

            "Organization status updated successfully.",

            result

        );

    });



// ==========================================
// SUPER ADMIN
// SOFT DELETE ORGANIZATION
// ==========================================

const deleteOrganization =
    asyncHandler(async (req, res) => {

        const result =
            await organizationService.deleteOrganization(

                req.params.id

            );


        return ApiResponse.success(

            res,

            200,

            "Organization deleted successfully.",

            result

        );

    });



// ==========================================
// SUPER ADMIN
// RESTORE ORGANIZATION
// ==========================================

const restoreOrganization =
    asyncHandler(async (req, res) => {

        const result =
            await organizationService.restoreOrganization(

                req.params.id

            );


        return ApiResponse.success(

            res,

            200,

            "Organization restored successfully.",

            result

        );

    });



// ==========================================
// EXPORTS
// ==========================================

module.exports = {

    createOrganization,

    getMyOrganization,

    updateMyOrganization,

    getAllOrganizations,

    getOrganizationById,

    updateOrganization,

    updateOrganizationStatus,

    deleteOrganization,

    restoreOrganization

};