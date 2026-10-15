import axiosClient from "../../../services/axiosClient";



// =====================================
// GET LOOKUPS BY CATEGORY
// =====================================

export const getLookupsByCategoryApi = async(category)=>{


    const response = await axiosClient.get(

        `/lookups/category/${category}`

    );


    return response.data.data;


};




// =====================================
// BENEFICIARY LOOKUP
// Used by dropdown/selectors
// =====================================

export const getBeneficiariesLookupApi = async(params = {})=>{


    const response = await axiosClient.get(

        "/beneficiaries/lookup",

        {
            params
        }

    );


    return response.data.data;


};