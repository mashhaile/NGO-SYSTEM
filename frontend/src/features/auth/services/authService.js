import {
    loginApi,
    registerOrganizationApi,
    getCurrentUserApi
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



export const logoutService = () => {

    removeToken();

};