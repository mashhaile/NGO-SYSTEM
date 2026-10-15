import axiosClient from "../../../services/axiosClient";


// =====================================================
// GET PROJECTS
// =====================================================

export const getProjectsApi = (params = {}) => {

    return axiosClient.get(
        "/projects",
        {
            params
        }
    );

};


// =====================================================
// GET PROJECT BY ID
// =====================================================

export const getProjectByIdApi = (id) => {

    return axiosClient.get(
        `/projects/${id}`
    );

};


// =====================================================
// CREATE PROJECT
// =====================================================

export const createProjectApi = (data) => {

    return axiosClient.post(
        "/projects",
        data
    );

};


// =====================================================
// UPDATE PROJECT
// =====================================================

export const updateProjectApi = (
    id,
    data
) => {

    return axiosClient.put(
        `/projects/${id}`,
        data
    );

};


// =====================================================
// DELETE PROJECT
// =====================================================

export const deleteProjectApi = (id) => {

    return axiosClient.delete(
        `/projects/${id}`
    );

};
