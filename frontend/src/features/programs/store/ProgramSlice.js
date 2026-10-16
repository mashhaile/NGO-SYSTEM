import {
    createSlice
} from "@reduxjs/toolkit";


import {

    getProgramsThunk,
    getProgramByIdThunk,
    createProgramThunk,
    updateProgramThunk,
    deleteProgramThunk

} from "./ProgramThunks";



// ==========================================
// INITIAL STATE
// ==========================================

const initialState = {

    programs: [],

    selectedProgram: null,

    pagination: null,

    loading: false,

    error: null

};



// ==========================================
// PROGRAM SLICE
// ==========================================

const programSlice = createSlice({

    name: "programs",

    initialState,

    reducers: {},


    extraReducers: (builder) => {


        // ==========================================
        // GET PROGRAMS
        // ==========================================

        builder.addCase(

            getProgramsThunk.pending,

            (state) => {

                state.loading = true;

                state.error = null;

            }

        );


        builder.addCase(

            getProgramsThunk.fulfilled,

            (state, action) => {

                state.loading = false;

                state.error = null;


                /*
                 * Expected thunk response:
                 *
                 * {
                 *     data: [],
                 *     pagination: {}
                 * }
                 */


                state.programs =
                    Array.isArray(
                        action.payload?.data
                    )
                        ? action.payload.data
                        : [];


                state.pagination =
                    action.payload?.pagination ||
                    null;

            }

        );


        builder.addCase(

            getProgramsThunk.rejected,

            (state, action) => {

                state.loading = false;

                state.error =
                    action.payload ||
                    "Failed to load programs";

            }

        );



        // ==========================================
        // GET PROGRAM BY ID
        // ==========================================

        builder.addCase(

            getProgramByIdThunk.pending,

            (state) => {

                state.loading = true;

                state.error = null;

                state.selectedProgram = null;

            }

        );


        builder.addCase(

            getProgramByIdThunk.fulfilled,

            (state, action) => {

                state.loading = false;

                state.error = null;


                /*
                 * Thunk returns the actual
                 * program object.
                 */


                state.selectedProgram =
                    action.payload || null;

            }

        );


        builder.addCase(

            getProgramByIdThunk.rejected,

            (state, action) => {

                state.loading = false;

                state.selectedProgram = null;

                state.error =
                    action.payload ||
                    "Failed to load program";

            }

        );



        // ==========================================
        // CREATE PROGRAM
        // ==========================================

        builder.addCase(

            createProgramThunk.pending,

            (state) => {

                state.loading = true;

                state.error = null;

            }

        );


        builder.addCase(

            createProgramThunk.fulfilled,

            (state, action) => {

                state.loading = false;

                state.error = null;


                const newProgram =
                    action.payload;


                if (!newProgram) {
                    return;
                }


                /*
                 * Make sure the new program
                 * has a valid ID.
                 */


                if (
                    !newProgram._id &&
                    !newProgram.id
                ) {

                    return;

                }


                state.programs.unshift(
                    newProgram
                );

            }

        );


        builder.addCase(

            createProgramThunk.rejected,

            (state, action) => {

                state.loading = false;

                state.error =
                    action.payload ||
                    "Failed to create program";

            }

        );



        // ==========================================
        // UPDATE PROGRAM
        // ==========================================

        builder.addCase(

            updateProgramThunk.pending,

            (state) => {

                state.loading = true;

                state.error = null;

            }

        );


        builder.addCase(

            updateProgramThunk.fulfilled,

            (state, action) => {

                state.loading = false;

                state.error = null;


                /*
                 * updateProgramThunk MUST return
                 * the actual program object.
                 *
                 * Example:
                 *
                 * {
                 *     _id: "...",
                 *     name: "Quality Education",
                 *     ...
                 * }
                 */


                const updatedProgram =
                    action.payload;


                if (!updatedProgram) {
                    return;
                }


                const updatedId =
                    updatedProgram._id ||
                    updatedProgram.id;


                if (!updatedId) {
                    return;
                }



                // ==========================================
                // UPDATE PROGRAM IN LIST
                // ==========================================

                const index =
                    state.programs.findIndex(

                        item => {

                            const itemId =
                                item?._id ||
                                item?.id;

                            return (
                                String(itemId) ===
                                String(updatedId)
                            );

                        }

                    );


                if (index !== -1) {

                    state.programs[index] =
                        updatedProgram;

                }

                else {

                    /*
                     * If the program isn't currently
                     * in the list, add it.
                     */

                    state.programs.unshift(
                        updatedProgram
                    );

                }



                // ==========================================
                // UPDATE SELECTED PROGRAM
                // ==========================================

                const selectedId =
                    state.selectedProgram?._id ||
                    state.selectedProgram?.id;


                if (

                    selectedId &&

                    String(selectedId) ===
                    String(updatedId)

                ) {

                    state.selectedProgram =
                        updatedProgram;

                }

            }

        );


        builder.addCase(

            updateProgramThunk.rejected,

            (state, action) => {

                state.loading = false;

                state.error =
                    action.payload ||
                    "Failed to update program";

            }

        );



        // ==========================================
        // DELETE PROGRAM
        // ==========================================

        builder.addCase(

            deleteProgramThunk.pending,

            (state) => {

                state.loading = true;

                state.error = null;

            }

        );


        builder.addCase(

            deleteProgramThunk.fulfilled,

            (state, action) => {

                state.loading = false;

                state.error = null;


                const deletedId =
                    action.payload;


                if (!deletedId) {
                    return;
                }


                /*
                 * Remove from program list.
                 */

                state.programs =
                    state.programs.filter(

                        item => {

                            const itemId =
                                item?._id ||
                                item?.id;

                            return (
                                String(itemId) !==
                                String(deletedId)
                            );

                        }

                    );


                /*
                 * Clear selected program
                 * if it was deleted.
                 */

                const selectedId =
                    state.selectedProgram?._id ||
                    state.selectedProgram?.id;


                if (

                    selectedId &&

                    String(selectedId) ===
                    String(deletedId)

                ) {

                    state.selectedProgram =
                        null;

                }

            }

        );


        builder.addCase(

            deleteProgramThunk.rejected,

            (state, action) => {

                state.loading = false;

                state.error =
                    action.payload ||
                    "Failed to delete program";

            }

        );

    }

});



// ==========================================
// EXPORT
// ==========================================

export default programSlice.reducer;
