import {
    createAsyncThunk
} from "@reduxjs/toolkit";


import {
    createEnterpriseMemberService,
    getEnterpriseMembersService,
    getMembersByEnterpriseService,
    getEnterprisesByMemberService,
    getEnterpriseMemberByIdService,
    updateEnterpriseMemberService,
    deleteEnterpriseMemberService
} from "../services/enterpriseMemberService";



// =====================================
// CREATE ENTERPRISE MEMBER
// =====================================

export const createEnterpriseMemberThunk = createAsyncThunk(

    "enterpriseMembers/create",

    async (
        data,
        thunkAPI
    ) => {

        try {

            const response =
                await createEnterpriseMemberService(
                    data
                );

            return response;

        }

        catch (error) {

            return thunkAPI.rejectWithValue(

                error.response?.data?.message ||

                error.message ||

                "Failed creating enterprise member"

            );

        }

    }

);



// =====================================
// GET ALL ENTERPRISE MEMBERS
// =====================================
// IMPORTANT:
// This gets members from ALL enterprises.
// Use a large limit so the page does not
// only receive the first 10 records.
// =====================================

export const getEnterpriseMembersThunk = createAsyncThunk(

    "enterpriseMembers/getAll",

    async (
        params = {},
        thunkAPI
    ) => {

        try {

            const requestParams = {

                ...params,

                page:
                    params.page || 1,

                limit:
                    params.limit || 1000

            };


            const response =
                await getEnterpriseMembersService(

                    requestParams

                );


            return response;

        }

        catch (error) {

            return thunkAPI.rejectWithValue(

                error.response?.data?.message ||

                error.message ||

                "Failed loading enterprise members"

            );

        }

    }

);



// =====================================
// GET MEMBERS BY ENTERPRISE
// =====================================

export const getMembersByEnterpriseThunk = createAsyncThunk(

    "enterpriseMembers/getByEnterprise",

    async (
        {
            enterpriseId,
            params = {}
        },
        thunkAPI
    ) => {

        try {

            if (!enterpriseId) {

                return thunkAPI.rejectWithValue(
                    "Enterprise ID is required"
                );

            }


            const response =
                await getMembersByEnterpriseService(

                    enterpriseId,

                    params

                );


            /*
             * Normalize all possible API response shapes.
             *
             * Supported:
             *
             * response.data
             * response.data.data
             * response.data.rows
             * response.data.members
             * response.members
             * response.rows
             */

            const data =
                response?.data?.data ||
                response?.data?.members ||
                response?.data?.rows ||
                response?.data ||
                response?.members ||
                response?.rows ||
                [];


            return Array.isArray(data)
                ? data
                : [];


        }

        catch (error) {

            console.error(
                "Failed loading enterprise members:",
                error
            );


            return thunkAPI.rejectWithValue(

                error.response?.data?.message ||

                error.message ||

                "Failed loading enterprise members"

            );

        }

    }

);


// =====================================
// GET ENTERPRISES BY BENEFICIARY
// =====================================

export const getEnterprisesByMemberThunk = createAsyncThunk(

    "enterpriseMembers/getByBeneficiary",

    async (
        {
            beneficiaryId,
            params = {}
        },
        thunkAPI
    ) => {

        try {

            const response =
                await getEnterprisesByMemberService(

                    beneficiaryId,

                    params

                );

            return response;

        }

        catch (error) {

            return thunkAPI.rejectWithValue(

                error.response?.data?.message ||

                error.message ||

                "Failed loading beneficiary enterprises"

            );

        }

    }

);



// =====================================
// GET ENTERPRISE MEMBER BY ID
// =====================================

export const getEnterpriseMemberByIdThunk = createAsyncThunk(

    "enterpriseMembers/getById",

    async (
        id,
        thunkAPI
    ) => {

        try {

            const response =
                await getEnterpriseMemberByIdService(

                    id

                );

            return response;

        }

        catch (error) {

            return thunkAPI.rejectWithValue(

                error.response?.data?.message ||

                error.message ||

                "Failed loading enterprise member"

            );

        }

    }

);



// =====================================
// UPDATE ENTERPRISE MEMBER
// =====================================

export const updateEnterpriseMemberThunk = createAsyncThunk(

    "enterpriseMembers/update",

    async (
        {
            id,
            data
        },
        thunkAPI
    ) => {

        try {

            const response =
                await updateEnterpriseMemberService(

                    id,

                    data

                );

            return response;

        }

        catch (error) {

            return thunkAPI.rejectWithValue(

                error.response?.data?.message ||

                error.message ||

                "Failed updating enterprise member"

            );

        }

    }

);



// =====================================
// DELETE ENTERPRISE MEMBER
// =====================================

export const deleteEnterpriseMemberThunk = createAsyncThunk(

    "enterpriseMembers/delete",

    async (
        id,
        thunkAPI
    ) => {

        try {

            const response =
                await deleteEnterpriseMemberService(

                    id

                );


            return {

                id,

                response

            };

        }

        catch (error) {

            return thunkAPI.rejectWithValue(

                error.response?.data?.message ||

                error.message ||

                "Failed deleting enterprise member"

            );

        }

    }

);