import axiosClient from "../../../services/axiosClient";

export const getProgramsLookupApi = () => {

    return axiosClient.get(
        "/programs/lookup"
    );

};