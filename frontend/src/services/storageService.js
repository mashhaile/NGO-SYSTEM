const TOKEN_KEY = "ngo_saas_token";


export const setToken = (token) => {

    localStorage.setItem(
        TOKEN_KEY,
        token
    );

};


export const getToken = () => {

    return localStorage.getItem(
        TOKEN_KEY
    );

};


export const removeToken = () => {

    localStorage.removeItem(
        TOKEN_KEY
    );

};


export const clearStorage = () => {

    removeToken();

};