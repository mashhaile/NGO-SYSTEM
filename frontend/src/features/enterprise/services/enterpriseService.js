import {
    createEnterpriseApi,
    getEnterprisesApi,
    getEnterpriseLookupApi,
    getEnterprisesByBeneficiaryApi,
    getEnterpriseByIdApi,
    updateEnterpriseApi,
    deleteEnterpriseApi
} from "../api/enterpriseApi";



// =================================
// CREATE ENTERPRISE
// =================================

export const createEnterpriseService = async (
    data
) => {

    return await createEnterpriseApi(
        data
    );

};



// =================================
// GET ALL ENTERPRISES
// =================================

export const getEnterprisesService = async (
    params = {}
) => {

    return await getEnterprisesApi(
        params
    );

};



// =================================
// GET ENTERPRISE LOOKUP
// =================================

export const getEnterpriseLookupService = async (
    params = {}
) => {

    return await getEnterpriseLookupApi(
        params
    );

};



// =================================
// GET ENTERPRISES BY BENEFICIARY
// =================================

export const getEnterprisesByBeneficiaryService = async (

    beneficiaryId,

    params = {}

) => {

    return await getEnterprisesByBeneficiaryApi(

        beneficiaryId,

        params

    );

};



// =================================
// GET ENTERPRISE BY ID
// =================================

export const getEnterpriseByIdService = async (
    id
) => {

    return await getEnterpriseByIdApi(
        id
    );

};



// =================================
// UPDATE ENTERPRISE
// =================================

export const updateEnterpriseService = async (

    id,

    data

) => {

    return await updateEnterpriseApi(

        id,

        data

    );

};



// =================================
// DELETE ENTERPRISE
// =================================

export const deleteEnterpriseService = async (
    id
) => {

    return await deleteEnterpriseApi(
        id
    );

};
