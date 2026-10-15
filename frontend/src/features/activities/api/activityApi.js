import axiosClient from "../../../services/axiosClient";



// GET ALL

export const getActivitiesApi = (params)=>{

    return axiosClient.get(

        "/activities",

        {
            params
        }

    );

};





// GET ONE

export const getActivityByIdApi = (id)=>{

    return axiosClient.get(

        `/activities/${id}`

    );

};





// CREATE

export const createActivityApi = (data)=>{

    return axiosClient.post(

        "/activities",

        data

    );

};





// UPDATE

export const updateActivityApi = (

    id,

    data

)=>{

    return axiosClient.put(

        `/activities/${id}`,

        data

    );

};





// DELETE

export const deleteActivityApi = (id)=>{

    return axiosClient.delete(

        `/activities/${id}`

    );

};