import axiosClient from "../../../services/axiosClient";

export const getBeneficiariesLookupApi = async () => {

    const response = await axiosClient.get(
        "/beneficiaries",
        {
            params: {
                page: 1,
                limit: 1000
            }
        }
    );

    return response.data;
};