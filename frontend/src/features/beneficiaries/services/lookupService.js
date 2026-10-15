import {
    getLookupsByCategoryApi,
    getBeneficiariesLookupApi
} from "../api/lookupApi";


// =====================================================
// GET LOOKUPS BY MODULE + CATEGORY
// =====================================================
//
// Example:
//
// getLookupsByCategoryService(
//     "Beneficiary",
//     "Gender"
// )
//
// Returns organization-specific lookup values.
//
// =====================================================

export const getLookupsByCategoryService = async (
    module,
    category
) => {

    return await getLookupsByCategoryApi(
        module,
        category
    );

};


// =====================================================
// GET BENEFICIARY LOOKUPS
// =====================================================
//
// Legacy / aggregated endpoint.
//
// Keep this available because other Beneficiary
// components may still use it.
//
// =====================================================

export const getBeneficiariesLookupService = async (
    params = {}
) => {

    return await getBeneficiariesLookupApi(
        params
    );

};