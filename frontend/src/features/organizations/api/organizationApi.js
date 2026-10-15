import axiosClient from "../../../services/axiosClient";


// ==========================================
// GET CURRENT ORGANIZATION
// ==========================================

export const getMyOrganizationApi = async () => {

    const response =
        await axiosClient.get(
            "/organizations/me"
        );

    return response.data;

};


// ==========================================
// UPDATE CURRENT ORGANIZATION
// ==========================================

export const updateMyOrganizationApi = async (
    organizationData
) => {

    const response =
        await axiosClient.put(

            "/organizations/me",

            organizationData

        );

    return response.data;

};