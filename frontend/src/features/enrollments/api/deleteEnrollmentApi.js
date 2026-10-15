import axiosClient from "../../../services/axiosClient";

export const deleteEnrollmentApi = async (id) => {

    const response = await axiosClient.delete(
        `/enrollments/${id}`
    );

    return response.data;

};