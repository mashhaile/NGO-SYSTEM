import {
createAsyncThunk
}
from "@reduxjs/toolkit";



import {


getAttendancesService,

getAttendanceByIdService,

createAttendanceService,

updateAttendanceService,

deleteAttendanceService,

getAttendanceRecordsService,

saveAttendanceRecordsService


}
from "../services/attendanceService";





export const getAttendancesThunk=createAsyncThunk(

"attendance/getAll",


async(params,{rejectWithValue})=>{


try{


const response =
await getAttendancesService(params);


return response.data.data;


}
catch(error){


return rejectWithValue(

error.response?.data?.message ||

error.message

);


}


}

);







export const getAttendanceByIdThunk=createAsyncThunk(

"attendance/getOne",


async(id,{rejectWithValue})=>{


try{


const response =
await getAttendanceByIdService(id);


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







export const createAttendanceThunk=createAsyncThunk(

"attendance/create",


async(data,{rejectWithValue})=>{


try{


const response =
await createAttendanceService(data);


return response.data.data;


}
catch(error){


return rejectWithValue(

error.response?.data?.message ||

error.message

);


}


}

);







export const updateAttendanceThunk=createAsyncThunk(

"attendance/update",


async({id,data},{rejectWithValue})=>{


try{


const response =
await updateAttendanceService(id,data);


return response.data.data;


}
catch(error){


return rejectWithValue(

error.response?.data?.message ||

error.message

);


}


}

);







export const deleteAttendanceThunk=createAsyncThunk(

"attendance/delete",


async(id,{rejectWithValue})=>{


try{


await deleteAttendanceService(id);


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







export const getAttendanceRecordsThunk=createAsyncThunk(

"attendance/getRecords",


async(id,{rejectWithValue})=>{


try{


const response =
await getAttendanceRecordsService(id);


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







export const saveAttendanceRecordsThunk=createAsyncThunk(

"attendance/saveRecords",


async({id,data},{rejectWithValue})=>{


try{


const response =

await saveAttendanceRecordsService(

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