import {
    getCustomFieldsApi,
    getCustomFieldByIdApi,
    createCustomFieldApi,
    updateCustomFieldApi,
    deleteCustomFieldApi
} from "../api/customFieldApi";


// =====================================================
// SUPPORTED CUSTOM FIELD MODULES
// =====================================================

export const CUSTOM_FIELD_MODULES = [

    "Beneficiary",

    "Donor",

    "Program",

    "ServiceDelivery",

    "User",

    "Enterprise",

    "EnterpriseMember"

];


// =====================================================
// GET CUSTOM FIELDS BY MODULE
// =====================================================

export const getCustomFieldsByModuleService = async (
    module
) => {

    if (!module) {

        throw new Error(
            "Custom field module is required"
        );

    }

    return await getCustomFieldsApi(
        module
    );

};


// =====================================================
// GENERIC GET
// =====================================================

export const getCustomFieldsService = async (
    module
) => {

    return await getCustomFieldsByModuleService(
        module
    );

};


// =====================================================
// BENEFICIARY
// =====================================================

export const getBeneficiaryCustomFieldsService =
    async () => {

        return await getCustomFieldsByModuleService(
            "Beneficiary"
        );

    };


// =====================================================
// DONOR
// =====================================================

export const getDonorCustomFieldsService =
    async () => {

        return await getCustomFieldsByModuleService(
            "Donor"
        );

    };


// =====================================================
// PROGRAM
// =====================================================

export const getProgramCustomFieldsService =
    async () => {

        return await getCustomFieldsByModuleService(
            "Program"
        );

    };


// =====================================================
// SERVICE DELIVERY
// =====================================================

export const getServiceDeliveryCustomFieldsService =
    async () => {

        return await getCustomFieldsByModuleService(
            "ServiceDelivery"
        );

    };


// =====================================================
// USER
// =====================================================

export const getUserCustomFieldsService =
    async () => {

        return await getCustomFieldsByModuleService(
            "User"
        );

    };


// =====================================================
// ENTERPRISE
// =====================================================

export const getEnterpriseCustomFieldsService =
    async () => {

        return await getCustomFieldsByModuleService(
            "Enterprise"
        );

    };


// =====================================================
// ENTERPRISE MEMBER
// =====================================================

export const getEnterpriseMemberCustomFieldsService =
    async () => {

        return await getCustomFieldsByModuleService(
            "EnterpriseMember"
        );

    };


// =====================================================
// CREATE
// =====================================================

export const createCustomFieldService =
    async (
        data
    ) => {

        return await createCustomFieldApi(
            data
        );

    };


// =====================================================
// GET BY ID
// =====================================================

export const getCustomFieldByIdService =
    async (
        id
    ) => {

        return await getCustomFieldByIdApi(
            id
        );

    };


// =====================================================
// UPDATE
// =====================================================

export const updateCustomFieldService =
    async (
        id,
        data
    ) => {

        return await updateCustomFieldApi(
            id,
            data
        );

    };


// =====================================================
// DELETE
// =====================================================

export const deleteCustomFieldService =
    async (
        id
    ) => {

        return await deleteCustomFieldApi(
            id
        );

    };