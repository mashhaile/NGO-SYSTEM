import axiosClient from "../../../services/axiosClient";


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
// VALIDATE MODULE
// =====================================================

const validateCustomFieldModule = (
    module
) => {

    if (!module) {

        throw new Error(
            "Custom field module is required"
        );

    }

    if (
        !CUSTOM_FIELD_MODULES.includes(
            module
        )
    ) {

        throw new Error(
            `Unsupported custom field module: ${module}`
        );

    }

};


// =====================================================
// CREATE CUSTOM FIELD
// =====================================================

export const createCustomFieldApi = async (
    data
) => {

    const response =
        await axiosClient.post(
            "/custom-fields",
            data
        );

    return response.data;

};


// =====================================================
// GET CUSTOM FIELDS BY MODULE
// =====================================================

export const getCustomFieldsApi = async (
    module
) => {

    validateCustomFieldModule(
        module
    );


    const response =
        await axiosClient.get(

            `/custom-fields/module/${encodeURIComponent(
                module
            )}`

        );


    return response.data.data;

};


// =====================================================
// GET CUSTOM FIELD BY ID
// =====================================================

export const getCustomFieldByIdApi = async (
    id
) => {

    if (!id) {

        throw new Error(
            "Custom field ID is required"
        );

    }


    const response =
        await axiosClient.get(
            `/custom-fields/${id}`
        );


    return response.data.data;

};


// =====================================================
// UPDATE CUSTOM FIELD
// =====================================================

export const updateCustomFieldApi = async (
    id,
    data
) => {

    if (!id) {

        throw new Error(
            "Custom field ID is required"
        );

    }


    const response =
        await axiosClient.put(

            `/custom-fields/${id}`,

            data

        );


    return response.data;

};


// =====================================================
// DELETE CUSTOM FIELD
// =====================================================

export const deleteCustomFieldApi = async (
    id
) => {

    if (!id) {

        throw new Error(
            "Custom field ID is required"
        );

    }


    const response =
        await axiosClient.delete(

            `/custom-fields/${id}`

        );


    return response.data;

};