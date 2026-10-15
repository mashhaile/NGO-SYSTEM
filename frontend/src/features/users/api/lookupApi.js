import axiosClient from "../../../services/axiosClient";

export const getStaffLookupApi = () => {

    return axiosClient.get("/users/lookup/staff");

};