import {
    createAsyncThunk
} from "@reduxjs/toolkit";


import {

    getProjectsService,

    createProjectService,

    updateProjectService,

    deleteProjectService,

    getProjectLookupService

} from "../services/projectService";


// =====================================================
// HELPER
// =====================================================

const getErrorMessage = (error, fallback) => {

    const responseData =
        error?.response?.data;


    if (
        responseData?.message
    ) {

        return responseData.message;

    }


    if (
        responseData?.error
    ) {

        return responseData.error;

    }


    if (
        Array.isArray(
            responseData?.errors
        )
    ) {

        return responseData.errors

            .map(
                item => {

                    if (
                        typeof item === "string"
                    ) {

                        return item;

                    }

                    return (
                        item?.message ||
                        item?.msg ||
                        item?.error
                    );

                }
            )

            .filter(Boolean)

            .join(", ");

    }


    if (
        typeof responseData === "string"
    ) {

        return responseData;

    }


    return (
        error?.message ||
        fallback
    );

};


// =====================================================
// GET PROJECTS
// =====================================================

export const getProjectsThunk = createAsyncThunk(

    "projects/getProjects",

    async (params = {}, thunkAPI) => {

        try {

            const response =
                await getProjectsService(
                    params
                );


            /*
             * Expected backend:
             *
             * {
             *   success: true,
             *   data: [],
             *   pagination: {}
             * }
             */

            return {

                data:
                    response?.data?.data ??
                    [],

                pagination:
                    response?.data?.pagination ??
                    null

            };

        }

        catch (error) {

            console.error(
                "GET PROJECTS ERROR:",
                error?.response?.data ||
                error
            );


            return thunkAPI.rejectWithValue(

                getErrorMessage(
                    error,
                    "Failed to load projects"
                )

            );

        }

    }

);


// =====================================================
// CREATE PROJECT
// =====================================================

export const createProjectThunk = createAsyncThunk(

    "projects/createProject",

    async (data, thunkAPI) => {

        try {

            if (
                !data ||
                typeof data !== "object"
            ) {

                return thunkAPI.rejectWithValue(
                    "Project data is required"
                );

            }




            const response =
                await createProjectService(
                    data
                );




            /*
             * Backend:
             *
             * {
             *   success: true,
             *   message: "...",
             *   data: { ...project }
             * }
             */

            const project =
                response?.data?.data ??
                response?.data;


            if (!project) {

                return thunkAPI.rejectWithValue(
                    "Project was created but no project data was returned"
                );

            }


            return project;

        }

        catch (error) {

            console.error(
                "CREATE PROJECT ERROR:",
                error?.response?.data ||
                error
            );


            return thunkAPI.rejectWithValue(

                getErrorMessage(
                    error,
                    "Failed to create project"
                )

            );

        }

    }

);


export const updateProjectThunk = createAsyncThunk(

    "projects/updateProject",

    async (
        {
            id,
            data
        },
        thunkAPI
    ) => {

        try {

            if (!id) {

                return thunkAPI.rejectWithValue(
                    "Project ID is required"
                );

            }


            if (
                !data ||
                typeof data !== "object"
            ) {

                return thunkAPI.rejectWithValue(
                    "Project data is required"
                );

            }




            const response =
                await updateProjectService(
                    id,
                    data
                );




            /*
             * Backend:
             *
             * {
             *   success: true,
             *   message: "...",
             *   data: { project }
             * }
             */

            const updatedProject =
                response?.data?.data ||
                response?.data ||
                response;


            if (!updatedProject) {

                return thunkAPI.rejectWithValue(
                    "Project update returned no data"
                );

            }


            return updatedProject;

        }

        catch (error) {

            console.error(
                "UPDATE PROJECT ERROR:",
                error?.response?.data ||
                error
            );


            const responseData =
                error?.response?.data;


            return thunkAPI.rejectWithValue(

                responseData?.message ||

                responseData?.error ||

                (
                    Array.isArray(
                        responseData?.errors
                    )
                        ? responseData.errors
                            .map(
                                item =>
                                    typeof item === "string"
                                        ? item
                                        : item?.message
                            )
                            .filter(Boolean)
                            .join(", ")
                        : null
                ) ||

                error?.message ||

                "Failed to update project"

            );

        }

    }

);



// =====================================================
// DELETE PROJECT
// =====================================================

export const deleteProjectThunk = createAsyncThunk(

    "projects/deleteProject",

    async (id, thunkAPI) => {

        try {

            if (!id) {

                return thunkAPI.rejectWithValue(
                    "Project ID is required"
                );

            }




            await deleteProjectService(
                id
            );


            return id;

        }

        catch (error) {

            console.error(
                "DELETE PROJECT ERROR:",
                error?.response?.data ||
                error
            );


            return thunkAPI.rejectWithValue(

                getErrorMessage(
                    error,
                    "Failed to delete project"
                )

            );

        }

    }

);


// =====================================================
// PROJECT LOOKUP
// =====================================================

export const getProjectLookupThunk = createAsyncThunk(

    "projects/getProjectLookup",

    async (_, thunkAPI) => {

        try {

            const response =
                await getProjectLookupService();




            return (
                response?.data?.data ??
                response?.data ??
                []
            );

        }

        catch (error) {

            console.error(
                "PROJECT LOOKUP ERROR:",
                error?.response?.data ||
                error
            );


            return thunkAPI.rejectWithValue(

                getErrorMessage(
                    error,
                    "Failed to load project lookup"
                )

            );

        }

    }

);