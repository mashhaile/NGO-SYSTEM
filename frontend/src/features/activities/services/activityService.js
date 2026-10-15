import {

    getActivitiesApi,

    getActivityByIdApi,

    createActivityApi,

    updateActivityApi,

    deleteActivityApi

}
from "../api/activityApi";





export const getActivitiesService=(params)=>{

    return getActivitiesApi(params);

};



export const getActivityByIdService=(id)=>{

    return getActivityByIdApi(id);

};



export const createActivityService=(data)=>{

    return createActivityApi(data);

};



export const updateActivityService=(id,data)=>{

    return updateActivityApi(
        id,
        data
    );

};



export const deleteActivityService=(id)=>{

    return deleteActivityApi(id);

};