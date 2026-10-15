import axiosClient from "../../../services/axiosClient";



// ==========================================
// GET LOOKUP OPTIONS
// ==========================================

export const getLookupOptionsApi = (category)=>{

    return axiosClient.get(
        "/lookups",
        {
            params:{
                category
            }
        }
    );

};