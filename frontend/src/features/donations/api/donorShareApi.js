import axios from "axios";

import axiosClient, {
    API_URL
} from "../../../services/axiosClient";


// =====================================================
// STAFF: share links
// =====================================================

export const getShareLinksApi = async (donorId) => {

    const response =
        await axiosClient.get(
            "/donor-share-links",
            {
                params: {
                    donor: donorId
                }
            }
        );

    return response.data?.data || [];

};


export const createShareLinkApi = async (data) => {

    const response =
        await axiosClient.post(
            "/donor-share-links",
            data
        );

    return response.data?.data;

};


export const revokeShareLinkApi = async (id) => {

    const response =
        await axiosClient.post(
            `/donor-share-links/${id}/revoke`
        );

    return response.data?.data;

};


// Full link the donor opens (token is only known once).

export const buildShareUrl = (token) =>
    `${window.location.origin}/share/donor/${token}`;



// =====================================================
// PUBLIC (no staff session)
// =====================================================
//
// Plain axios: no Authorization header and none of the
// staff client's redirect-on-401 behaviour.
//
// =====================================================

const publicClient =
    axios.create({
        baseURL: API_URL
    });


export const getPublicShareApi = async (token) => {

    const response =
        await publicClient.get(
            `/public/donor-share/${encodeURIComponent(token)}`
        );

    return response.data?.data;

};


export const downloadPublicStatementApi = async (
    token,
    donationId,
    fileName
) => {

    const response =
        await publicClient.get(
            `/public/donor-share/${encodeURIComponent(token)}/statement/${donationId}`,
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
