import axiosClient from "../../../services/axiosClient";

export const getActivityRunLookupApi = () => {
    return axiosClient.get("/activity-runs/lookup");
};