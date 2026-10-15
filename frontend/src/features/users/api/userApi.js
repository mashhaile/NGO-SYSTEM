import axiosClient from "../../../services/axiosClient";


// ==========================================
// GET USERS
// ==========================================

export const getUsersApi = async () => {

    const response =
        await axiosClient.get(
            "/users"
        );

    return response.data;

};


// ==========================================
// CREATE USER
// ==========================================

export const createUserApi = async (
    data
) => {

    const response =
        await axiosClient.post(
            "/users",
            data
        );

    return response.data;

};


// ==========================================
// UPDATE USER
// ==========================================

export const updateUserApi = async (
    id,
    data
) => {

    const response =
        await axiosClient.put(
            `/users/${id}`,
            data
        );

    return response.data;

};


// ==========================================
// DELETE / DEACTIVATE USER
// ==========================================

export const deleteUserApi = async (
    id
) => {

    const response =
        await axiosClient.delete(
            `/users/${id}`
        );

    return response.data;

};


// ==========================================
// USER LOOKUP
// ==========================================
//
// Backend route remains:
// GET /users/lookup/staff
//
// Kept this way for compatibility with
// existing modules.
//

export const getUserLookupApi = async () => {

    const response =
        await axiosClient.get(
            "/users/lookup/staff"
        );

    return response.data;

};


// ==========================================
// BACKWARD COMPATIBILITY
// ==========================================
//
// Existing frontend modules can still use
// getStaffLookupApi if they already import it.
//

export const getStaffLookupApi =
    getUserLookupApi;