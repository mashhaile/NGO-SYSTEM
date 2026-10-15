import {

    getLookupsByCategoryApi,

    getBeneficiariesLookupApi

}
from "../api/lookupApi";




// =====================================
// LOOKUPS BY CATEGORY
// =====================================

export const getLookupsByCategoryService = async(category)=>{


    return await getLookupsByCategoryApi(

        category

    );


};





// =====================================
// BENEFICIARY LOOKUP
// =====================================

export const getBeneficiariesLookupService = async(params={})=>{


    return await getBeneficiariesLookupApi(

        params

    );


};