import {
    getProgramsLookupApi
}
from "../api/lookupApi";



export const getProgramsLookupService = async () => {

    const response =
        await getProgramsLookupApi();

    return response?.data?.data || [];

};