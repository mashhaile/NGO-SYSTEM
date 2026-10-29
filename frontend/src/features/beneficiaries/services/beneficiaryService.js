import {
    getBeneficiariesApi,
    getBeneficiaryByIdApi,
    createBeneficiaryApi,
    updateBeneficiaryApi,
    deleteBeneficiaryApi,
    getBeneficiaryLookupApi
} from "../api/beneficiaryApi";


// =====================================================
// GET BENEFICIARIES
// =====================================================

export const getBeneficiariesService = async (
    params = {}
) => {

    return await getBeneficiariesApi(
        params
    );

};


// =====================================================
// GET BENEFICIARY BY ID
// =====================================================

export const getBeneficiaryByIdService = async (
    id
) => {

    return await getBeneficiaryByIdApi(
        id
    );

};


// =====================================================
// CREATE BENEFICIARY
// =====================================================

export const createBeneficiaryService = async (
    data
) => {

    return await createBeneficiaryApi(
        data
    );

};


// =====================================================
// UPDATE BENEFICIARY
// =====================================================

export const updateBeneficiaryService = async (
    id,
    data
) => {

    return await updateBeneficiaryApi(
        id,
        data
    );

};


// =====================================================
// DELETE BENEFICIARY
// =====================================================

export const deleteBeneficiaryService = async (
    id
) => {

    return await deleteBeneficiaryApi(
        id
    );

};


// =====================================================
// BENEFICIARY LOOKUP
// =====================================================

export const getBeneficiariesLookupService = async (
    programId = "",
    include = [],
    projectId = ""
) => {

    const response =
        await getBeneficiaryLookupApi(
            programId,
            include,
            projectId
        );

    return response?.data || [];

};