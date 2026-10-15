import axiosClient from "../../../services/axiosClient";




// ==========================================
// GET ALL ACTIVITY RUNS
// ==========================================

export const getActivityRunsApi = (params)=>{

    return axiosClient.get(

        "/activity-runs",

        {
            params
        }

    );

};






// ==========================================
// GET ACTIVITY RUN BY ID
// ==========================================

export const getActivityRunByIdApi = (id)=>{

    return axiosClient.get(

        `/activity-runs/${id}`

    );

};






// ==========================================
// CREATE ACTIVITY RUN
// ==========================================

export const createActivityRunApi = (data)=>{

    return axiosClient.post(

        "/activity-runs",

        data

    );

};






// ==========================================
// UPDATE ACTIVITY RUN
// ==========================================

export const updateActivityRunApi = (

    id,

    data

)=>{

    return axiosClient.put(

        `/activity-runs/${id}`,

        data

    );

};






// ==========================================
// DELETE ACTIVITY RUN
// ==========================================

export const deleteActivityRunApi = (id)=>{

    return axiosClient.delete(

        `/activity-runs/${id}`

    );

};






// ==========================================
// ACTIVITY RUN LOOKUP
// ==========================================

export const getActivityRunLookupApi = ()=>{

    return axiosClient.get(

        "/activity-runs/lookup"

    );

};