import { getActivityRunLookupApi } from "../api/lookupApi";

export const getActivityRunLookupService = async () => {

    const response = await getActivityRunLookupApi();

    return response?.data?.data || [];

};