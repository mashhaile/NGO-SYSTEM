import axiosClient
    from "../../../services/axiosClient";


// =====================================================
// PROCUREMENT API (suppliers, purchase requests)
// =====================================================

// ---------------- suppliers

export const getSuppliersApi = async (params = {}) =>
    (await axiosClient.get("/suppliers", { params })).data;

export const getSupplierOptionsApi = async () =>
    (await axiosClient.get("/suppliers/options")).data?.data || [];

export const getSupplierByIdApi = async (id) =>
    (await axiosClient.get(`/suppliers/${id}`)).data?.data;

export const createSupplierApi = async (data) =>
    (await axiosClient.post("/suppliers", data)).data?.data;

export const updateSupplierApi = async (id, data) =>
    (await axiosClient.put(`/suppliers/${id}`, data)).data?.data;

export const deleteSupplierApi = async (id) =>
    (await axiosClient.delete(`/suppliers/${id}`)).data;


// ---------------- purchase requests

export const getPurchaseRequestsApi = async (params = {}) =>
    (await axiosClient.get("/purchase-requests", { params })).data;

export const getPurchaseRequestByIdApi = async (id) =>
    (await axiosClient.get(`/purchase-requests/${id}`)).data?.data;

export const createPurchaseRequestApi = async (data) =>
    (await axiosClient.post("/purchase-requests", data)).data?.data;

export const updatePurchaseRequestApi = async (id, data) =>
    (await axiosClient.put(`/purchase-requests/${id}`, data)).data?.data;

export const deletePurchaseRequestApi = async (id) =>
    (await axiosClient.delete(`/purchase-requests/${id}`)).data;

export const submitPurchaseRequestApi = async (id) =>
    (await axiosClient.post(`/purchase-requests/${id}/submit`)).data?.data;

export const approvePurchaseRequestApi = async (id, body = {}) =>
    (await axiosClient.post(`/purchase-requests/${id}/approve`, body)).data?.data;

export const returnPurchaseRequestApi = async (id, comment) =>
    (await axiosClient.post(`/purchase-requests/${id}/return`, { comment })).data?.data;

export const rejectPurchaseRequestApi = async (id, comment) =>
    (await axiosClient.post(`/purchase-requests/${id}/reject`, { comment })).data?.data;

export const cancelPurchaseRequestApi = async (id, comment) =>
    (await axiosClient.post(`/purchase-requests/${id}/cancel`, { comment })).data?.data;
