import axiosClient from "../../../services/axiosClient";

// ==========================================
// GET PROGRAMS
// ==========================================

export const getProgramsApi = (params) => {

    return axiosClient.get(
        "/programs",
        {
            params
        }
    );

};


// ==========================================
// GET PROGRAM BY ID
// ==========================================

export const getProgramByIdApi = (id) => {

    return axiosClient.get(
        `/programs/${id}`
    );

};


// ==========================================
// CREATE PROGRAM
// ==========================================

export const createProgramApi = (data) => {

    return axiosClient.post(
        "/programs",
        data
    );

};


// ==========================================
// UPDATE PROGRAM
// ==========================================

export const updateProgramApi = (id, data) => {

    return axiosClient.put(
        `/programs/${id}`,
        data
    );

};


// ==========================================
// DELETE PROGRAM
// ==========================================

export const deleteProgramApi = (id) => {

    return axiosClient.delete(
        `/programs/${id}`
    );

};