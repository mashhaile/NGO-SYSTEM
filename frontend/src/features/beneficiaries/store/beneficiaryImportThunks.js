import { createAsyncThunk } from "@reduxjs/toolkit";

import {
    importBeneficiariesService,
    downloadBeneficiaryTemplateService
} from "../services/beneficiaryImportService";




// =====================================
// IMPORT BENEFICIARIES
// =====================================

export const importBeneficiariesThunk = createAsyncThunk(

    "beneficiaries/import",

    async(file, thunkAPI)=>{

        try{


            const response =
                await importBeneficiariesService(file);



            return response;


        }
        catch(error){


            return thunkAPI.rejectWithValue(

                error.response?.data?.message ||

                error.message ||

                "Import failed"

            );


        }


    }

);





// =====================================
// DOWNLOAD TEMPLATE
// =====================================

export const downloadBeneficiaryTemplateThunk = createAsyncThunk(


    "beneficiaries/template",


    async(_, thunkAPI)=>{


        try{


            const response =

                await downloadBeneficiaryTemplateService();



            return response;


        }
        catch(error){


            return thunkAPI.rejectWithValue(

                "Template download failed"

            );


        }


    }


);