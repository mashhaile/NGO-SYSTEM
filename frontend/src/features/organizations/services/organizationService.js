import {
    getMyOrganizationApi,
    updateMyOrganizationApi
} from "../api/organizationApi";


// ==========================================
// GET CURRENT ORGANIZATION
// ==========================================

export const getMyOrganizationService =
    async () => {

        const response =
            await getMyOrganizationApi();

        return response;

    };


// ==========================================
// UPDATE CURRENT ORGANIZATION
// ==========================================

export const updateMyOrganizationService =
    async (
        organizationData
    ) => {

        const response =
            await updateMyOrganizationApi(
                organizationData
            );

        return response;

    };
