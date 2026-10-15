import axiosClient from "../../../services/axiosClient";


// =================================
// CREATE ENTERPRISE
// =================================

export const createEnterpriseApi = async (data) => {

    const response = await axiosClient.post(
        "/enterprises",
        data
    );

    return response.data;

};


// =================================
// GET ALL ENTERPRISES
// =================================

export const getEnterprisesApi = async (params = {}) => {

    const response = await axiosClient.get(
        "/enterprises",
        {
            params
        }
    );

    return response.data;

};


// =================================
// GET ENTERPRISE LOOKUP
// =================================

export const getEnterpriseLookupApi = async (params = {}) => {

    const response = await axiosClient.get(
        "/enterprises/lookup",
        {
            params
        }
    );

    return response.data;

};


// =================================
// GET ENTERPRISES BY BENEFICIARY
// =================================

export const getEnterprisesByBeneficiaryApi = async (
    beneficiaryId
) => {

    const response = await axiosClient.get(
        `/enterprises/beneficiary/${beneficiaryId}`
    );

    return response.data;

};


// =================================
// GET ENTERPRISE BY ID
// =================================

export const getEnterpriseByIdApi = async (id) => {

    const response = await axiosClient.get(
        `/enterprises/${id}`
    );

    return response.data;

};


// =================================
// UPDATE ENTERPRISE
// =================================

export const updateEnterpriseApi = async (
    id,
    data
) => {

    const response = await axiosClient.put(
        `/enterprises/${id}`,
        data
    );

    return response.data;

};


// =================================
// DELETE ENTERPRISE
// =================================

export const deleteEnterpriseApi = async (id) => {

    const response = await axiosClient.delete(
        `/enterprises/${id}`
    );

    return response.data;

};