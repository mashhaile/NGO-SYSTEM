import axiosClient from "../../../services/axiosClient";


// =====================================================
// GET ALL LOOKUPS
// =====================================================

export const getLookupsApi = async (
    params = {}
) => {

    const response =
        await axiosClient.get(
            "/lookups",
            {
                params
            }
        );

    return response.data.data;

};


// =====================================================
// GET LOOKUP CATEGORIES BY MODULE
// =====================================================

export const getLookupCategoriesByModuleApi = async (
    module
) => {

    if (
        !module ||
        !String(module).trim()
    ) {

        throw new Error(
            "Lookup module is required"
        );

    }


    const cleanModule =
        String(module).trim();


    const response =
        await axiosClient.get(
            `/lookups/module/${encodeURIComponent(
                cleanModule
            )}/categories`
        );


    return response.data.data;

};


// =====================================================
// GET LOOKUPS BY MODULE + CATEGORY
// =====================================================
//
// Supports:
//
// Normal lookup:
//
// /lookups/module/Beneficiary/category/Gender
//
// Dependent lookup:
//
// /lookups/module/ServiceDelivery/category/ServiceType
//     ?parentLookup=<ServiceCategoryId>
//
// =====================================================

export const getLookupsByModuleAndCategoryApi = async (
    module,
    category,
    parentLookup = null
) => {

    if (
        !module ||
        !String(module).trim()
    ) {

        throw new Error(
            "Lookup module is required"
        );

    }


    if (
        !category ||
        !String(category).trim()
    ) {

        throw new Error(
            "Lookup category is required"
        );

    }


    const cleanModule =
        String(module).trim();


    const cleanCategory =
        String(category).trim();


    const params = {};


    // -------------------------------------------------
    // Parent lookup
    // -------------------------------------------------

    if (
        parentLookup
    ) {

        params.parentLookup =
            parentLookup;

    }


    const response =
        await axiosClient.get(

            `/lookups/module/${encodeURIComponent(
                cleanModule
            )}/category/${encodeURIComponent(
                cleanCategory
            )}`,

            {
                params
            }

        );


    return response.data.data;

};


// =====================================================
// GET LOOKUPS BY CATEGORY
// =====================================================
//
// Compatibility helper.
//
// =====================================================

export const getLookupsByCategoryApi = async (
    module,
    category,
    parentLookup = null
) => {

    return getLookupsByModuleAndCategoryApi(

        module,

        category,

        parentLookup

    );

};


// =====================================================
// GET LOOKUP BY ID
// =====================================================

export const getLookupByIdApi = async (
    id
) => {

    if (!id) {

        throw new Error(
            "Lookup ID is required"
        );

    }


    const response =
        await axiosClient.get(
            `/lookups/${id}`
        );


    return response.data.data;

};


// =====================================================
// CREATE SINGLE LOOKUP
// =====================================================
//
// ServiceType example:
//
// {
//     module: "ServiceDelivery",
//     category: "ServiceType",
//     value: "Vaccination",
//     code: "VACCINATION",
//     parentLookup: "<ServiceCategoryId>"
// }
//
// =====================================================

export const createLookupApi = async (
    data
) => {

    if (
        !data ||
        typeof data !== "object"
    ) {

        throw new Error(
            "Lookup data is required"
        );

    }


    const response =
        await axiosClient.post(
            "/lookups",
            data
        );


    return response.data.data;

};


// =====================================================
// CREATE BULK LOOKUPS
// =====================================================

export const createLookupsBulkApi = async (
    data
) => {

    if (
        !data ||
        typeof data !== "object"
    ) {

        throw new Error(
            "Bulk lookup data is required"
        );

    }


    const response =
        await axiosClient.post(
            "/lookups/bulk",
            data
        );


    return response.data.data;

};


// =====================================================
// UPDATE LOOKUP
// =====================================================
//
// parentLookup can be changed for ServiceType.
//
// =====================================================

export const updateLookupApi = async (
    id,
    data
) => {

    if (!id) {

        throw new Error(
            "Lookup ID is required"
        );

    }


    if (
        !data ||
        typeof data !== "object"
    ) {

        throw new Error(
            "Lookup update data is required"
        );

    }


    const response =
        await axiosClient.put(
            `/lookups/${id}`,
            data
        );


    return response.data.data;

};


// =====================================================
// DEACTIVATE LOOKUP
// =====================================================

export const deleteLookupApi = async (
    id
) => {

    if (!id) {

        throw new Error(
            "Lookup ID is required"
        );

    }


    const response =
        await axiosClient.delete(
            `/lookups/${id}`
        );


    return response.data.data;

};


// =====================================================
// BENEFICIARY ENTITY LOOKUP
// =====================================================

export const getBeneficiariesLookupApi = async (
    params = {}
) => {

    const response =
        await axiosClient.get(

            "/beneficiaries/lookup",

            {
                params
            }

        );


    return response.data.data;

};