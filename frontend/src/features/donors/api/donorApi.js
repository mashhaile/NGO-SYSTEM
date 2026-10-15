import axiosClient from "../../../services/axiosClient";


// ==========================================
// GET ALL DONORS
// ==========================================

export const getDonorsApi = (params = {}) => {

    return axiosClient.get(
        "/donors",
        {
            params
        }
    );

};


// ==========================================
// DONOR LOOKUP
// ==========================================

export const getDonorsLookupApi = () => {

    return axiosClient.get(
        "/donors/lookup"
    );

};


// ==========================================
// GET SINGLE DONOR
// ==========================================

export const getDonorByIdApi = (id) => {

    return axiosClient.get(
        `/donors/${id}`
    );

};


// ==========================================
// CREATE DONOR
// ==========================================

export const createDonorApi = (data) => {

    return axiosClient.post(
        "/donors",
        data
    );

};


// ==========================================
// UPDATE DONOR
// ==========================================

export const updateDonorApi = (
    id,
    data
) => {

    return axiosClient.put(
        `/donors/${id}`,
        data
    );

};


// ==========================================
// DELETE DONOR
// ==========================================

export const deleteDonorApi = (id) => {

    return axiosClient.delete(
        `/donors/${id}`
    );

};