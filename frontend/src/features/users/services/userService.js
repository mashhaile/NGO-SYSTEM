import {
    getUsersApi,
    createUserApi,
    updateUserApi,
    deleteUserApi,
    resetUserPasswordApi,
    getStaffLookupApi
} from "../api/userApi";


// ==========================================
// RESET PASSWORD
// ==========================================

export const resetUserPasswordService = async (id) => {

    return await resetUserPasswordApi(id);

};


// ==========================================
// GET USERS
// ==========================================

export const getUsersService = async () => {

    return await getUsersApi();

};


// ==========================================
// CREATE USER
// ==========================================

export const createUserService = async (data) => {

    return await createUserApi(data);

};


// ==========================================
// UPDATE USER
// ==========================================

export const updateUserService = async (
    id,
    data
) => {

    return await updateUserApi(
        id,
        data
    );

};


// ==========================================
// DELETE USER
// ==========================================

export const deleteUserService = async (id) => {

    return await deleteUserApi(id);

};


// ==========================================
// STAFF LOOKUP
// ==========================================

export const getStaffLookupService = async () => {

    return await getStaffLookupApi();

};