import { getStaffLookupApi } from "../api/lookupApi";

export const getStaffLookupService = async () => {

    const response = await getStaffLookupApi();

    return response?.data?.data || [];

};