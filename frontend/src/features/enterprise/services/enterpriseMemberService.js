import {
    createEnterpriseMemberApi,
    getEnterpriseMembersApi,
    getMembersByEnterpriseApi,
    getEnterprisesByMemberApi,
    getEnterpriseMemberByIdApi,
    updateEnterpriseMemberApi,
    deleteEnterpriseMemberApi
} from "../api/enterpriseMemberApi";


// =================================
// CREATE ENTERPRISE MEMBER
// =================================

export const createEnterpriseMemberService = async (
    data
) => {

    return await createEnterpriseMemberApi(
        data
    );

};


// =================================
// GET ALL ENTERPRISE MEMBERS
// =================================

export const getEnterpriseMembersService = async (
    params = {}
) => {

    return await getEnterpriseMembersApi(
        params
    );

};


// =================================
// GET MEMBERS BY ENTERPRISE
// =================================

export const getMembersByEnterpriseService = async (
    enterpriseId,
    params = {}
) => {

    return await getMembersByEnterpriseApi(
        enterpriseId,
        params
    );

};


// =================================
// GET ENTERPRISES BY BENEFICIARY
// =================================

export const getEnterprisesByMemberService = async (
    beneficiaryId,
    params = {}
) => {

    return await getEnterprisesByMemberApi(
        beneficiaryId,
        params
    );

};


// =================================
// GET ENTERPRISE MEMBER BY ID
// =================================

export const getEnterpriseMemberByIdService = async (
    id
) => {

    return await getEnterpriseMemberByIdApi(
        id
    );

};


// =================================
// UPDATE ENTERPRISE MEMBER
// =================================

export const updateEnterpriseMemberService = async (
    id,
    data
) => {

    return await updateEnterpriseMemberApi(
        id,
        data
    );

};


// =================================
// DELETE ENTERPRISE MEMBER
// =================================

export const deleteEnterpriseMemberService = async (
    id
) => {

    return await deleteEnterpriseMemberApi(
        id
    );

};
