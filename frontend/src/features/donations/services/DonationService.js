import {
    getDonationsApi,
    getDonationByIdApi,
    createDonationApi,
    updateDonationApi,
    deleteDonationApi
} from "../api/donationApi";

// ==========================================
// GET ALL
// ==========================================

export const getDonationsService = async (params = {}) => {
    const response = await getDonationsApi(params);

    return response.data;
};

// ==========================================
// GET SINGLE
// ==========================================

export const getDonationByIdService = async (id) => {
    const response = await getDonationByIdApi(id);

    return response.data;
};

// ==========================================
// CREATE
// ==========================================

export const createDonationService = async (data) => {
    const response = await createDonationApi(data);

    return response.data;
};

// ==========================================
// UPDATE
// ==========================================

export const updateDonationService = async (id, data) => {
    const response = await updateDonationApi(
        id,
        data
    );

    return response.data;
};

// ==========================================
// DELETE
// ==========================================

export const deleteDonationService = async (id) => {
    const response = await deleteDonationApi(id);

    return response.data;
};