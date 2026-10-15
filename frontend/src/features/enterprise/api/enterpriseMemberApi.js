import axiosClient from "../../../services/axiosClient";


// =================================
// CREATE ENTERPRISE MEMBER
// =================================

export const createEnterpriseMemberApi = async (
    data
) => {

    const response =
        await axiosClient.post(
            "/enterprise-members",
            data
        );

    return response.data;

};



// =================================
// GET ALL ENTERPRISE MEMBERS
// =================================

export const getEnterpriseMembersApi = async (
    params = {}
) => {

    const response =
        await axiosClient.get(
            "/enterprise-members",
            {
                params
            }
        );

    return response.data;

};



// =================================
// GET MEMBERS BY ENTERPRISE
// =================================

export const getMembersByEnterpriseApi = async (
    enterpriseId,
    params = {}
) => {

    const response =
        await axiosClient.get(

            `/enterprise-members/enterprise/${enterpriseId}`,

            {
                params
            }

        );

    return response.data;

};



// =================================
// GET ENTERPRISES BY BENEFICIARY
// =================================

export const getEnterprisesByMemberApi = async (
    beneficiaryId,
    params = {}
) => {

    const response =
        await axiosClient.get(

            `/enterprise-members/beneficiary/${beneficiaryId}`,

            {
                params
            }

        );

    return response.data;

};



// =================================
// GET ENTERPRISE MEMBER BY ID
// =================================

export const getEnterpriseMemberByIdApi = async (
    id
) => {

    const response =
        await axiosClient.get(
            `/enterprise-members/${id}`
        );

    return response.data;

};



// =================================
// UPDATE ENTERPRISE MEMBER
// =================================

export const updateEnterpriseMemberApi = async (
    id,
    data
) => {

    const response =
        await axiosClient.put(

            `/enterprise-members/${id}`,

            data

        );

    return response.data;

};



// =================================
// DELETE ENTERPRISE MEMBER
// =================================

export const deleteEnterpriseMemberApi = async (
    id
) => {

    const response =
        await axiosClient.delete(

            `/enterprise-members/${id}`

        );

    return response.data;

};