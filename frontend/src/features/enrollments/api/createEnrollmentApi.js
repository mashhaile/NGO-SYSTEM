import axiosClient from "../../../services/axiosClient";

export const createEnrollmentApi = async (data) => {
    const response = await axiosClient.post(
        "/enrollments",
        data
    );

    return response.data;
};