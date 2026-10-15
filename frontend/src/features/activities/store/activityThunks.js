import {
    createAsyncThunk
}
from "@reduxjs/toolkit";


import {

    getActivitiesService,

    getActivityByIdService,

    createActivityService,

    updateActivityService,

    deleteActivityService

}
from "../services/activityService";







export const getActivitiesThunk=createAsyncThunk(


"activities/getAll",


async(params,{rejectWithValue})=>{


try{


const response=

await getActivitiesService(params);



return response.data;



}

catch(error){


return rejectWithValue(

error.response?.data?.message ||

error.message

);


}


}


);









export const getActivityByIdThunk=createAsyncThunk(


"activities/getOne",


async(id,{rejectWithValue})=>{


try{


const response=

await getActivityByIdService(id);



return response.data.data || response.data;



}

catch(error){


return rejectWithValue(

error.response?.data?.message ||

error.message

);


}



}


);









export const createActivityThunk=createAsyncThunk(


"activities/create",


async(data,{rejectWithValue})=>{


try{


const response=

await createActivityService(data);



return response.data.data || response.data;



}

catch(error){


return rejectWithValue(

error.response?.data?.message ||

error.message

);


}



}


);









export const updateActivityThunk=createAsyncThunk(


"activities/update",


async({id,data},{rejectWithValue})=>{


try{


const response=

await updateActivityService(

id,

data

);



return response.data.data || response.data;



}

catch(error){


return rejectWithValue(

error.response?.data?.message ||

error.message

);


}


}


);









export const deleteActivityThunk=createAsyncThunk(


"activities/delete",


async(id,{rejectWithValue})=>{


try{


await deleteActivityService(id);



return id;



}

catch(error){


return rejectWithValue(

error.response?.data?.message ||

error.message

);


}



}


);