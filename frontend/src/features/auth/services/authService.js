import {
    loginApi,
    registerOrganizationApi,
    getCurrentUserApi,
    changePasswordApi
} from "../api/authApi";


import {
    setToken,
    removeToken
} from "../../../services/storageService";



export const loginService = async (credentials) => {

    const response =
        await loginApi(credentials);


    if(response.success){

        setToken(
            response.data.token
        );

    }


    return response;

};



export const registerOrganizationService = async (data) => {

    return await registerOrganizationApi(data);

};



export const getCurrentUserService = async () => {

    return await getCurrentUserApi();

};



// Returns { user, token }. The old token stops working,
// so the new one is stored right away.

export const changePasswordService = async (data) => {

    const response =
        await changePasswordApi(data);

    setToken(
        response.data.token
    );

    return response.data;

};



export const logoutService = () => {

    removeToken();

};