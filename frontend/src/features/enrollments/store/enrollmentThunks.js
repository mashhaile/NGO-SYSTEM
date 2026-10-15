import {
    createAsyncThunk
} from "@reduxjs/toolkit";


import {

    getEnrollmentsService,

    getEnrollmentByIdService,

    createEnrollmentService,

    updateEnrollmentService,

    deleteEnrollmentService

} from "../services/enrollmentService";





// ==========================================
// GET ALL ENROLLMENTS
// ==========================================

export const getEnrollmentsThunk = createAsyncThunk(

    "enrollments/getAll",

    async(params,{rejectWithValue})=>{

        try{


            const response =

            await getEnrollmentsService(params);



            return response.data;



        }
       catch(error){


    return rejectWithValue(

        error.response?.data?.message ||

        "Failed to create enrollment"

    );


}
    }

);







// ==========================================
// GET ONE ENROLLMENT
// ==========================================

export const getEnrollmentByIdThunk = createAsyncThunk(

    "enrollments/getOne",

    async(id,{rejectWithValue})=>{


        try{


            const response =

            await getEnrollmentByIdService(id);



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







// ==========================================
// CREATE ENROLLMENT
// ==========================================

export const createEnrollmentThunk = createAsyncThunk(

    "enrollments/create",

    async(data,{rejectWithValue})=>{


        try{


            const response =

            await createEnrollmentService(data);



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







// ==========================================
// UPDATE ENROLLMENT
// ==========================================

export const updateEnrollmentThunk = createAsyncThunk(

    "enrollments/update",

    async({id,data},{rejectWithValue})=>{


        try{


            const response =

            await updateEnrollmentService(

                id,

                data

            );



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







// ==========================================
// DELETE ENROLLMENT
// ==========================================

export const deleteEnrollmentThunk = createAsyncThunk(

    "enrollments/delete",

    async(id,{rejectWithValue})=>{


        try{


            await deleteEnrollmentService(id);



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