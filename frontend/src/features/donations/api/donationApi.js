import axiosClient from "../../../services/axiosClient";

// ==========================================
// GET ALL DONATIONS
// ==========================================

export const getDonationsApi = (params = {}) => {
    return axiosClient.get(
        "/donations",
        {
            params
        }
    );
};

// ==========================================
// GET SINGLE DONATION
// ==========================================

export const getDonationByIdApi = (id) => {
    return axiosClient.get(
        `/donations/${id}`
    );
};

// ==========================================
// CREATE DONATION
// ==========================================

export const createDonationApi = (data) => {
    return axiosClient.post(
        "/donations",
        data
    );
};

// ==========================================
// UPDATE DONATION
// ==========================================

export const updateDonationApi = (id, data) => {
    return axiosClient.put(
        `/donations/${id}`,
        data
    );
};

// ==========================================
// DELETE DONATION
// ==========================================

export const deleteDonationApi = (id) => {
    return axiosClient.delete(
        `/donations/${id}`
    );
};