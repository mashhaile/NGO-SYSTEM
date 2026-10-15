import {

    getProgramsApi,
    getProgramByIdApi,
    createProgramApi,
    updateProgramApi,
    deleteProgramApi

} from "../api/ProgramApi";



// GET ALL PROGRAMS

export const getProgramsService = (params) => {

    return getProgramsApi(params);

};



// GET PROGRAM BY ID

export const getProgramByIdService = (id) => {

    return getProgramByIdApi(id);

};



// CREATE PROGRAM

export const createProgramService = (data) => {

    return createProgramApi(data);

};



// UPDATE PROGRAM

export const updateProgramService = (id, data) => {

    return updateProgramApi(
        id,
        data
    );

};



// DELETE PROGRAM

export const deleteProgramService = (id) => {

    return deleteProgramApi(id);

};