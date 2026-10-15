import {
    createSlice
} from "@reduxjs/toolkit";


import {

    getAttendancesThunk,

    createAttendanceThunk,

    deleteAttendanceThunk,

    getAttendanceRecordsThunk,

    saveAttendanceRecordsThunk

} from "./attendanceThunk";





const initialState = {

    data: [],

    records: [],

    loading: false,

    error: null

};






const attendanceSlice = createSlice({

    name: "attendance",

    initialState,


    reducers: {},



    extraReducers: (builder) => {


        builder



        // =====================================
        // GET ALL ATTENDANCE
        // =====================================

        .addCase(
            getAttendancesThunk.pending,
            (state) => {

                state.loading = true;

                state.error = null;

            }
        )


        .addCase(
            getAttendancesThunk.fulfilled,
            (state, action) => {

                state.loading = false;

                state.data =
                    action.payload || [];

            }
        )


        .addCase(
            getAttendancesThunk.rejected,
            (state, action) => {

                state.loading = false;

                state.error =
                    action.payload;

            }
        )





        // =====================================
        // CREATE ATTENDANCE
        // =====================================

        .addCase(
            createAttendanceThunk.pending,
            (state) => {

                state.loading = true;

            }
        )


        .addCase(
            createAttendanceThunk.fulfilled,
            (state, action) => {

                state.loading = false;


                if(action.payload){

                    state.data.unshift(
                        action.payload
                    );

                }

            }
        )


        .addCase(
            createAttendanceThunk.rejected,
            (state, action) => {

                state.loading = false;

                state.error =
                    action.payload;

            }
        )





        // =====================================
        // DELETE ATTENDANCE
        // =====================================

        .addCase(
            deleteAttendanceThunk.fulfilled,
            (state, action) => {


                state.data =
                    state.data.filter(

                        item =>
                            item._id !== action.payload

                    );


            }
        )





        // =====================================
        // GET RECORDS
        // =====================================

        .addCase(
            getAttendanceRecordsThunk.pending,
            (state)=>{

                state.loading = true;

            }
        )


        .addCase(
            getAttendanceRecordsThunk.fulfilled,
            (state, action)=>{


                state.loading = false;


                state.records =
                    action.payload || [];


            }
        )


        .addCase(
            getAttendanceRecordsThunk.rejected,
            (state, action)=>{


                state.loading = false;


                state.error =
                    action.payload;


            }
        )






        // =====================================
        // SAVE RECORDS
        // =====================================

        .addCase(
            saveAttendanceRecordsThunk.pending,
            (state)=>{

                state.loading = true;

            }
        )


        .addCase(
            saveAttendanceRecordsThunk.fulfilled,
            (state, action)=>{


                state.loading = false;


                state.records =
                    action.payload || [];


            }
        )


        .addCase(
            saveAttendanceRecordsThunk.rejected,
            (state, action)=>{


                state.loading = false;


                state.error =
                    action.payload;


            }
        );



    }


});






export default attendanceSlice.reducer;