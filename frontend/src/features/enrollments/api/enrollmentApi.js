import axiosClient from "../../../services/axiosClient";


// ================================
// GET ALL ENROLLMENTS
// ================================

export const getEnrollmentsApi = (params)=>{

    return axiosClient.get(
        "/enrollments",
        {
            params
        }
    );

};




// ================================
// GET ONE
// ================================

export const getEnrollmentByIdApi = (id)=>{

    return axiosClient.get(
        `/enrollments/${id}`
    );

};




// ================================
// CREATE
// ================================

export const createEnrollmentApi = (data)=>{

    return axiosClient.post(
        "/enrollments",
        data
    );

};




// ================================
// UPDATE
// ================================

export const updateEnrollmentApi = (
    id,
    data
)=>{

    return axiosClient.put(
        `/enrollments/${id}`,
        data
    );

};




// ================================
// DELETE
// ================================

export const deleteEnrollmentApi = (id)=>{

    return axiosClient.delete(
        `/enrollments/${id}`
    );

};