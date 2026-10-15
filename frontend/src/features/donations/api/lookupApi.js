import axiosClient from "../../../services/axiosClient";




// ==========================================
// PROGRAM LOOKUP
// ==========================================

export const getProgramsLookupApi = ()=>{

    return axiosClient.get(

        "/programs/lookup"

    );

};







// ==========================================
// BENEFICIARY LOOKUP
// ==========================================

export const getBeneficiariesLookupApi = ()=>{

    return axiosClient.get(

        "/beneficiaries/lookup"

    );

};