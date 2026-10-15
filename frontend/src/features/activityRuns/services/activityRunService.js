import {


    getActivityRunsApi,

    getActivityRunByIdApi,

    createActivityRunApi,

    updateActivityRunApi,

    deleteActivityRunApi,

    getActivityRunLookupApi


}
from "../api/activityRunApi";






// ==========================================
// GET ALL ACTIVITY RUNS
// ==========================================

export const getActivityRunsService = (params)=>{


    return getActivityRunsApi(params);


};








// ==========================================
// GET ACTIVITY RUN BY ID
// ==========================================

export const getActivityRunByIdService = (id)=>{


    return getActivityRunByIdApi(id);


};








// ==========================================
// ACTIVITY RUN LOOKUP
// ==========================================

export const getActivityRunLookupService = ()=>{


    return getActivityRunLookupApi();


};








// ==========================================
// CREATE ACTIVITY RUN
// ==========================================

export const createActivityRunService = (data)=>{


    return createActivityRunApi(data);


};








// ==========================================
// UPDATE ACTIVITY RUN
// ==========================================

export const updateActivityRunService = (

    id,

    data

)=>{


    return updateActivityRunApi(

        id,

        data

    );


};








// ==========================================
// DELETE ACTIVITY RUN
// ==========================================

export const deleteActivityRunService = (id)=>{


    return deleteActivityRunApi(id);


};