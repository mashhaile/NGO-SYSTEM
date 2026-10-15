import {
    createSlice
} from "@reduxjs/toolkit";


import {

    getEnrollmentsThunk,

    getEnrollmentByIdThunk,

    createEnrollmentThunk,

    updateEnrollmentThunk,

    deleteEnrollmentThunk

} from "./enrollmentThunks";






const initialState = {


    data: [],


    current: null,


    pagination: null,


    loading: false,


    error: null


};







const enrollmentSlice = createSlice({


    name:"enrollments",



    initialState,



    reducers:{},




    extraReducers:(builder)=>{


        builder





        // ==========================================
        // GET ALL
        // ==========================================


        .addCase(

            getEnrollmentsThunk.pending,

            (state)=>{

                state.loading=true;

                state.error=null;

            }

        )



        .addCase(

            getEnrollmentsThunk.fulfilled,

            (state,action)=>{


                state.loading=false;



                state.data =

                action.payload?.data || [];



                state.pagination =

                action.payload?.pagination || null;



            }

        )



        .addCase(

            getEnrollmentsThunk.rejected,

            (state,action)=>{


                state.loading=false;


                state.error =

                action.payload;


            }

        )








        // ==========================================
        // GET ONE
        // ==========================================


        .addCase(

            getEnrollmentByIdThunk.fulfilled,

            (state,action)=>{


                state.current =

                action.payload;


            }

        )








        // ==========================================
        // CREATE
        // ==========================================


        .addCase(

            createEnrollmentThunk.pending,

            (state)=>{


                state.loading=true;


            }

        )



        .addCase(

            createEnrollmentThunk.fulfilled,

            (state,action)=>{


                state.loading=false;



                if(action.payload){


                    state.data.unshift(

                        action.payload

                    );


                }


            }

        )



        .addCase(

            createEnrollmentThunk.rejected,

            (state,action)=>{


                state.loading=false;


                state.error =

                action.payload;


            }

        )









        // ==========================================
        // UPDATE
        // ==========================================


        .addCase(

            updateEnrollmentThunk.fulfilled,

            (state,action)=>{


                const index =

                state.data.findIndex(

                    item =>

                    item._id === action.payload._id

                );



                if(index !== -1){


                    state.data[index] =

                    action.payload;


                }



                state.current =

                action.payload;


            }

        )










        // ==========================================
        // DELETE
        // ==========================================


        .addCase(

            deleteEnrollmentThunk.fulfilled,

            (state,action)=>{


                state.data =

                state.data.filter(

                    item =>

                    item._id !== action.payload

                );


            }

        );



    }



});





export default enrollmentSlice.reducer;