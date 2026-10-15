import {
    createAsyncThunk
} from "@reduxjs/toolkit";


import {
    getProgramsService,
    getProgramByIdService,
    createProgramService,
    updateProgramService,
    deleteProgramService
} from "../services/programService";



// ==========================================
// GET PROGRAMS
// ==========================================

export const getProgramsThunk = createAsyncThunk(

    "programs/getPrograms",

    async (params, thunkAPI) => {

        try {

            const response =
                await getProgramsService(params);


            return (
                response.data?.data
                    ? response.data
                    : response.data
            );

        }

        catch (error) {

            return thunkAPI.rejectWithValue(

                error.response?.data?.message ||
                error.message ||
                "Failed to load programs"

            );

        }

    }

);



// ==========================================
// GET PROGRAM BY ID
// ==========================================

export const getProgramByIdThunk = createAsyncThunk(

    "programs/getProgramById",

    async (id, thunkAPI) => {

        try {

            const response =
                await getProgramByIdService(id);


            return (
                response.data?.data ||
                response.data
            );

        }

        catch (error) {

            return thunkAPI.rejectWithValue(

                error.response?.data?.message ||
                error.message ||
                "Failed to load program"

            );

        }

    }

);



// ==========================================
// CREATE PROGRAM
// ==========================================

export const createProgramThunk = createAsyncThunk(

    "programs/createProgram",

    async (data, thunkAPI) => {

        try {

            const response =
                await createProgramService(data);


            /*
             * Backend:
             *
             * {
             *     success: true,
             *     message: "...",
             *     data: { ...program }
             * }
             *
             * Return ONLY the program.
             */

            return (
                response.data?.data ||
                response.data
            );

        }

        catch (error) {

            return thunkAPI.rejectWithValue(

                error.response?.data?.message ||
                error.message ||
                "Failed to create program"

            );

        }

    }

);



// ==========================================
// UPDATE PROGRAM
// ==========================================

export const updateProgramThunk = createAsyncThunk(

    "programs/updateProgram",

    async (
        {
            id,
            data
        },
        thunkAPI
    ) => {

        try {

            const response =
                await updateProgramService(
                    id,
                    data
                );


            /*
             * IMPORTANT
             *
             * Backend returns:
             *
             * {
             *     success: true,
             *     message: "Program updated successfully",
             *     data: {
             *         _id: "...",
             *         programCode: "...",
             *         name: "...",
             *         ...
             *     }
             * }
             *
             * Redux must receive:
             *
             * {
             *     _id: "...",
             *     programCode: "...",
             *     name: "...",
             *     ...
             * }
             */

            return (
                response.data?.data ||
                response.data
            );

        }

        catch (error) {

            return thunkAPI.rejectWithValue(

                error.response?.data?.message ||
                error.message ||
                "Failed to update program"

            );

        }

    }

);



// ==========================================
// DELETE PROGRAM
// ==========================================

export const deleteProgramThunk = createAsyncThunk(

    "programs/deleteProgram",

    async (id, thunkAPI) => {

        try {

            await deleteProgramService(id);

            return id;

        }

        catch (error) {

            return thunkAPI.rejectWithValue(

                error.response?.data?.message ||
                error.message ||
                "Failed to delete program"

            );

        }

    }

);