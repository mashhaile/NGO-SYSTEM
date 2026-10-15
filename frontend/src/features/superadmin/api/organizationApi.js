import axiosClient
    from "../../../services/axiosClient";


// =====================================================
// CREATE ORGANIZATION
// SUPER ADMIN ONLY
// =====================================================

export const createOrganizationApi =
    async (
        data
    ) => {

        const response =
            await axiosClient.post(
                "/admin/organizations",
                data
            );

        return response.data;

    };


// =====================================================
// GET ORGANIZATIONS
// SUPER ADMIN ONLY
// =====================================================

export const getOrganizationsApi =
    async (
        params = {}
    ) => {

        const response =
            await axiosClient.get(
                "/admin/organizations",
                {
                    params
                }
            );

        return response.data;

    };


// =====================================================
// GET ORGANIZATION BY ID
// SUPER ADMIN ONLY
// =====================================================

export const getOrganizationByIdApi =
    async (
        id
    ) => {

        const response =
            await axiosClient.get(
                `/admin/organizations/${id}`
            );

        return response.data;

    };


// =====================================================
// UPDATE ORGANIZATION
// SUPER ADMIN ONLY
// =====================================================

export const updateOrganizationApi =
    async (
        id,
        data
    ) => {

        const response =
            await axiosClient.patch(
                `/admin/organizations/${id}`,
                data
            );

        return response.data;

    };


// =====================================================
// ACTIVATE ORGANIZATION
// =====================================================

export const activateOrganizationApi =
    async (
        id
    ) => {

        const response =
            await axiosClient.patch(
                `/admin/organizations/${id}/activate`
            );

        return response.data;

    };


// =====================================================
// SUSPEND ORGANIZATION
// =====================================================

export const suspendOrganizationApi =
    async (
        id
    ) => {

        const response =
            await axiosClient.patch(
                `/admin/organizations/${id}/suspend`
            );

        return response.data;

    };


// =====================================================
// DEACTIVATE ORGANIZATION
// =====================================================

export const deactivateOrganizationApi =
    async (
        id
    ) => {

        const response =
            await axiosClient.patch(
                `/admin/organizations/${id}/deactivate`
            );

        return response.data;

    };


// =====================================================
// RESTORE ORGANIZATION
// =====================================================

export const restoreOrganizationApi =
    async (
        id
    ) => {

        const response =
            await axiosClient.patch(
                `/admin/organizations/${id}/restore`
            );

        return response.data;

    };


// =====================================================
// DELETE ORGANIZATION
// =====================================================

export const deleteOrganizationApi =
    async (
        id
    ) => {

        const response =
            await axiosClient.delete(
                `/admin/organizations/${id}`
            );

        return response.data;

    };
