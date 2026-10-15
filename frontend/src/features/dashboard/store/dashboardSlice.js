import { createSlice } from "@reduxjs/toolkit";


import {
    getDashboardThunk
} from "./dashboardThunks";



const initialState = {

    data: null,

    loading: false,

    error: null

};



const dashboardSlice = createSlice({

    name: "dashboard",

    initialState,


    reducers: {},


    extraReducers: (builder)=>{


        builder.addCase(

            getDashboardThunk.pending,

            (state)=>{

                state.loading = true;

                state.error = null;

            }

        );



        builder.addCase(

            getDashboardThunk.fulfilled,

            (state, action)=>{


                state.data =
                    action.payload;


                state.loading = false;


            }

        );



        builder.addCase(

            getDashboardThunk.rejected,

            (state, action)=>{


                state.loading = false;


                state.error =
                    action.payload;


            }

        );


    }


});


export default dashboardSlice.reducer;