import axiosClient from "../../../services/axiosClient";

export const getProgramsLookupApi = async () => {

    const response = await axiosClient.get(
        "/programs",
        {
            params: {
                page: 1,
                limit: 1000
            }
        }
    );

    return response.data;
};