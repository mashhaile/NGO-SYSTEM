import {

    getProgramsLookupApi,

    getBeneficiariesLookupApi

} from "../api/lookupApi";






// ==========================================
// PROGRAM LOOKUP SERVICE
// ==========================================

export const getProgramsLookupService = async()=>{


    const response =

    await getProgramsLookupApi();



    return response?.data?.data || [];


};








// ==========================================
// BENEFICIARY LOOKUP SERVICE
// ==========================================

export const getBeneficiariesLookupService = async()=>{


    const response =

    await getBeneficiariesLookupApi();



    return response?.data?.data || [];


};