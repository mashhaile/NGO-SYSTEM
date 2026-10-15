import {
    createSlice
} from "@reduxjs/toolkit";


import {

    getProjectsThunk,

    createProjectThunk,

    updateProjectThunk,

    deleteProjectThunk

} from "./projectThunks";


// =====================================================
// INITIAL STATE
// =====================================================

const initialState = {

    projects: [],

    pagination: null,

    loading: false,

    error: null

};


// =====================================================
// HELPERS
// =====================================================

const getPayloadData = (payload) => {

    return (
        payload?.data ??
        payload ??
        null
    );

};


// =====================================================
// SLICE
// =====================================================

const projectSlice = createSlice({

    name: "projects",

    initialState,

    reducers: {},

    extraReducers: (builder) => {


        // =================================================
        // GET PROJECTS
        // =================================================

        builder.addCase(

            getProjectsThunk.pending,

            (state) => {

                state.loading = true;

                state.error = null;

            }

        );


        builder.addCase(

            getProjectsThunk.fulfilled,

            (state, action) => {

                state.loading = false;

                state.error = null;


                const payload =
                    action.payload;


                /*
                 * Supports:
                 *
                 * {
                 *   data: [],
                 *   pagination: {}
                 * }
                 *
                 * or
                 *
                 * []
                 */

                if (
                    Array.isArray(payload)
                ) {

                    state.projects =
                        payload;

                    state.pagination =
                        null;

                    return;

                }


                state.projects =
                    Array.isArray(
                        payload?.data
                    )
                        ? payload.data
                        : [];


                state.pagination =
                    payload?.pagination ||
                    null;

            }

        );


        builder.addCase(

            getProjectsThunk.rejected,

            (state, action) => {

                state.loading = false;

                state.error =
                    action.payload ||
                    action.error?.message ||
                    "Failed to load projects";

            }

        );


        // =================================================
        // CREATE PROJECT
        // =================================================

        builder.addCase(

            createProjectThunk.pending,

            (state) => {

                state.loading = true;

                state.error = null;

            }

        );


        builder.addCase(

            createProjectThunk.fulfilled,

            (state, action) => {

                state.loading = false;

                state.error = null;


                const created =
                    getPayloadData(
                        action.payload
                    );


                if (created) {

                    state.projects.unshift(
                        created
                    );

                }

            }

        );


        builder.addCase(

            createProjectThunk.rejected,

            (state, action) => {

                state.loading = false;

                state.error =
                    action.payload ||
                    action.error?.message ||
                    "Failed to create project";

            }

        );


        // =================================================
        // UPDATE PROJECT
        // =================================================

        builder.addCase(

            updateProjectThunk.pending,

            (state) => {

                state.loading = true;

                state.error = null;

            }

        );


        builder.addCase(

            updateProjectThunk.fulfilled,

            (state, action) => {

                state.loading = false;

                state.error = null;


                const updated =
                    getPayloadData(
                        action.payload
                    );


                if (!updated) {

                    return;

                }


                /*
                 * Find the existing project.
                 *
                 * MongoDB projects normally use _id.
                 */

                const index =
                    state.projects.findIndex(
                        (item) =>
                            item?._id ===
                            updated?._id
                    );


                if (index !== -1) {

                    state.projects[index] =
                        updated;

                }

            }

        );


        builder.addCase(

            updateProjectThunk.rejected,

            (state, action) => {

                state.loading = false;

                state.error =
                    action.payload ||
                    action.error?.message ||
                    "Failed to update project";

            }

        );


        // =================================================
        // DELETE PROJECT
        // =================================================

        builder.addCase(

            deleteProjectThunk.pending,

            (state) => {

                state.loading = true;

                state.error = null;

            }

        );


        builder.addCase(

            deleteProjectThunk.fulfilled,

            (state, action) => {

                state.loading = false;

                state.error = null;


                state.projects =
                    state.projects.filter(

                        (item) =>
                            item?._id !==
                            action.payload

                    );

            }

        );


        builder.addCase(

            deleteProjectThunk.rejected,

            (state, action) => {

                state.loading = false;

                state.error =
                    action.payload ||
                    action.error?.message ||
                    "Failed to delete project";

            }

        );

    }

});


export default projectSlice.reducer;