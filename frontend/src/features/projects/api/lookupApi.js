import axiosClient from "../../../services/axiosClient";


// ==========================================
// PROJECT LOOKUP
// Used for dropdowns
// ==========================================

export const getProjectLookupApi = ()=>{

    return axiosClient.get(
        "/projects/lookup"
    );

};