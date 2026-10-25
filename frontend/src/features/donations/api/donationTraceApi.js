import axiosClient
    from "../../../services/axiosClient";


// =====================================================
// DONATION TRACE API
// =====================================================

export const getDonationTraceApi = async (id) => {

    const response =
        await axiosClient.get(
            `/donation-trace/donations/${id}`
        );

    return response.data?.data;

};


export const getDonorTraceApi = async (id) => {

    const response =
        await axiosClient.get(
            `/donation-trace/donors/${id}`
        );

    return response.data?.data;

};


export const getUntracedSpendingApi = async (params = {}) => {

    const response =
        await axiosClient.get(
            "/donation-trace/untraced",
            {
                params
            }
        );

    return response.data?.data;

};


export const downloadDonationStatementApi = async (id, fileName) => {

    const response =
        await axiosClient.get(
            `/donation-trace/donations/${id}/statement`,
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
    link.download = fileName || "donor-statement.pdf";

    document.body.appendChild(link);
    link.click();
    link.remove();

    window.URL.revokeObjectURL(url);

};


export const formatMoney = (value, currency = "ETB") =>
    `${currency || "ETB"} ${Number(value || 0).toLocaleString("en-US", {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
    })}`;


export { formatDate } from "../../../utils/date";
