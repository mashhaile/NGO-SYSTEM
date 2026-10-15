import { createAsyncThunk } from "@reduxjs/toolkit";


import {
    getDashboardService
} from "../services/dashboardService";



export const getDashboardThunk = createAsyncThunk(

    "dashboard/getDashboard",


    async (_, thunkAPI) => {


        try {


            const response =
                await getDashboardService();


            return response.data;


        }
        catch(error){


            return thunkAPI.rejectWithValue(

                error.response?.data?.message ||

                error.message

            );


        }


    }

);