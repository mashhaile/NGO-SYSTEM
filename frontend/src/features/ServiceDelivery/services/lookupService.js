import {

    getLookupOptionsApi

} from "../api/lookupApi";



// ==========================================
// GET LOOKUP OPTIONS
// ==========================================

export const getLookupOptionsService = (category)=>{

    return getLookupOptionsApi(category);

};