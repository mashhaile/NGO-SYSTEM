import axiosClient
    from "../../../services/axiosClient";


// =====================================================
// TERMS OF REFERENCE API
// =====================================================

export const getTorsApi = async (params = {}) => {

    const response =
        await axiosClient.get(
            "/tors",
            {
                params
            }
        );

    return response.data;

};


export const getTorByIdApi = async (id) => {

    const response =
        await axiosClient.get(
            `/tors/${id}`
        );

    return response.data?.data;

};


export const createTorApi = async (data) => {

    const response =
        await axiosClient.post(
            "/tors",
            data
        );

    return response.data?.data;

};


export const updateTorApi = async (id, data) => {

    const response =
        await axiosClient.put(
            `/tors/${id}`,
            data
        );

    return response.data?.data;

};


export const deleteTorApi = async (id) => {

    await axiosClient.delete(
        `/tors/${id}`
    );

};


// =====================================================
// WORKFLOW
// =====================================================

export const submitTorApi = async (id) => {

    const response =
        await axiosClient.post(
            `/tors/${id}/submit`
        );

    return response.data?.data;

};


export const approveTorApi = async (id, comment = "") => {

    const response =
        await axiosClient.post(
            `/tors/${id}/approve`,
            {
                comment
            }
        );

    return response.data?.data;

};


export const returnTorApi = async (id, comment) => {

    const response =
        await axiosClient.post(
            `/tors/${id}/return`,
            {
                comment
            }
        );

    return response.data?.data;

};


// =====================================================
// ACTIVITY (after approval)
// =====================================================

export const createActivityFromTorApi = async (id) => {

    const response =
        await axiosClient.post(
            `/tors/${id}/create-activity`
        );

    return response.data?.data;

};


export const linkActivityApi = async (id, activity) => {

    const response =
        await axiosClient.post(
            `/tors/${id}/link-activity`,
            {
                activity
            }
        );

    return response.data?.data;

};


export const updateLinkedActivityApi = async (id, data) => {

    const response =
        await axiosClient.patch(
            `/tors/${id}/activity`,
            data
        );

    return response.data?.data;

};


// =====================================================
// PDF
// =====================================================

export const downloadTorPdfApi = async (id, fileName) => {

    const response =
        await axiosClient.get(
            `/tors/${id}/pdf`,
            {
                responseType: "blob"
            }
        );

    const url =
        window.URL.createObjectURL(
            new Blob(
                [response.data],
                {
                    type: "application/pdf"
                }
            )
        );

    const link =
        document.createElement("a");

    link.href = url;
    link.download = fileName || "terms-of-reference.pdf";

    document.body.appendChild(link);
    link.click();
    link.remove();

    window.URL.revokeObjectURL(url);

};


// Readable message from an API error.

export const getApiErrorMessage = (error, fallback) => {

    const data =
        error?.response?.data;

    const details =
        Array.isArray(data?.errors)
            ? data.errors
                .map(item => item?.message)
                .filter(Boolean)
            : [];

    return (
        (details.length && data?.message === "Validation failed."
            ? details.join(" ")
            : data?.message) ||
        error?.message ||
        fallback
    );

};
