import axiosClient from "../../../services/axiosClient";


export const loginApi = async (credentials) => {

    const response = await axiosClient.post(
        "/auth/login",
        credentials
    );

    return response.data;

};


export const registerOrganizationApi = async (data) => {

    const response = await axiosClient.post(
        "/auth/register-organization",
        data
    );

    return response.data;

};


export const getCurrentUserApi = async () => {

    const response = await axiosClient.get(
        "/auth/me"
    );

    return response.data;

};