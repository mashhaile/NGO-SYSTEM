import { createSlice } from "@reduxjs/toolkit";

import {
    importBeneficiariesThunk
}
from "./beneficiaryImportThunks";



const initialState={

    loading:false,

    successMessage:null,

    error:null

};




const beneficiaryImportSlice=createSlice({

    name:"beneficiaryImport",

    initialState,


    reducers:{


        clearImportMessage:(state)=>{

            state.successMessage=null;

            state.error=null;

        }


    },



    extraReducers:(builder)=>{


        builder.addCase(

            importBeneficiariesThunk.pending,

            (state)=>{

                state.loading=true;

                state.error=null;

            }

        );




        builder.addCase(

            importBeneficiariesThunk.fulfilled,

            (state,action)=>{


                state.loading=false;


                state.successMessage =

                    action.payload.message ||

                    "Import completed successfully";


            }

        );





        builder.addCase(

            importBeneficiariesThunk.rejected,

            (state,action)=>{


                state.loading=false;


                state.error =

                    action.payload;


            }

        );



    }


});



export const {
    clearImportMessage
}
=
beneficiaryImportSlice.actions;



export default beneficiaryImportSlice.reducer;