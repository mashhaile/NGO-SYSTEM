import axiosClient from "../../../services/axiosClient";



// ==========================================
// GET ACTIVITIES LOOKUP
// Used by Activity Run creation
// ==========================================

export const getActivitiesLookupApi = () => {

    return axiosClient.get(
        "/activities/lookup"
    );

};