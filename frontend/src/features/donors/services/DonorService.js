// src/features/donors/services/donorService.js


import {

    getDonorsApi,

    getDonorByIdApi,

    createDonorApi,

    updateDonorApi,

    deleteDonorApi,

    getDonorsLookupApi

} from "../api/donorApi";




// ==========================================
// GET ALL DONORS
// ==========================================

export const getDonorsService = async (
    params = {}
) => {

    const response =
        await getDonorsApi(params);

    return response.data;

};




// ==========================================
// GET DONOR LOOKUP
// ==========================================

export const getDonorsLookupService = async () => {

    const response =
        await getDonorsLookupApi();

    return response.data;

};




// ==========================================
// GET SINGLE DONOR
// ==========================================

export const getDonorByIdService = async (
    id
) => {

    const response =
        await getDonorByIdApi(id);

    return response.data;

};




// ==========================================
// CREATE DONOR
// ==========================================

export const createDonorService = async (
    data
) => {

    const response =
        await createDonorApi(data);

    return response.data;

};




// ==========================================
// UPDATE DONOR
// ==========================================

export const updateDonorService = async (

    id,

    data

) => {

    const response =
        await updateDonorApi(

            id,

            data

        );

    return response.data;

};




// ==========================================
// DELETE DONOR
// ==========================================

export const deleteDonorService = async (
    id
) => {

    const response =
        await deleteDonorApi(id);

    return response.data;

};