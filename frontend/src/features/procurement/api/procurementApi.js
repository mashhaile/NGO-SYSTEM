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


// ---------------- quotations and bid analysis (on a request)

const pr = (id, path) => `/purchase-requests/${id}${path}`;

export const startSourcingApi = async (id, body = {}) =>
    (await axiosClient.post(pr(id, "/sourcing/start"), body)).data?.data;

export const addQuoteApi = async (id, body) =>
    (await axiosClient.post(pr(id, "/quotes"), body)).data?.data;

export const updateQuoteApi = async (id, quoteId, body) =>
    (await axiosClient.put(pr(id, `/quotes/${quoteId}`), body)).data?.data;

export const removeQuoteApi = async (id, quoteId) =>
    (await axiosClient.delete(pr(id, `/quotes/${quoteId}`))).data?.data;

export const updateBidApi = async (id, body) =>
    (await axiosClient.put(pr(id, "/sourcing"), body)).data?.data;

export const submitBidApi = async (id) =>
    (await axiosClient.post(pr(id, "/sourcing/submit"))).data?.data;

export const approveBidApi = async (id, comment = "") =>
    (await axiosClient.post(pr(id, "/sourcing/approve"), { comment })).data?.data;

export const returnBidApi = async (id, comment) =>
    (await axiosClient.post(pr(id, "/sourcing/return"), { comment })).data?.data;

export const decideBidApi = async (id, decision, comment = "") =>
    (await axiosClient.post(pr(id, "/sourcing/decision"), { decision, comment })).data?.data;

export const issuePurchaseOrderApi = async (id, body = {}) =>
    (await axiosClient.post(pr(id, "/purchase-order"), body)).data?.data;


// ---------------- purchase orders

export const getPurchaseOrdersApi = async (params = {}) =>
    (await axiosClient.get("/purchase-orders", { params })).data;

export const getPurchaseOrderByIdApi = async (id) =>
    (await axiosClient.get(`/purchase-orders/${id}`)).data?.data;

export const updatePurchaseOrderApi = async (id, body) =>
    (await axiosClient.put(`/purchase-orders/${id}`, body)).data?.data;

export const cancelPurchaseOrderApi = async (id, comment) =>
    (await axiosClient.post(`/purchase-orders/${id}/cancel`, { comment })).data?.data;

// receiving and paying

export const recordReceiptApi = async (id, body) =>
    (await axiosClient.post(`/purchase-orders/${id}/receipts`, body)).data?.data;

export const cancelReceiptApi = async (noteId, comment) =>
    (await axiosClient.post(`/purchase-orders/receipts/${noteId}/cancel`, { comment })).data?.data;

// creates a Draft expense linked to the order; returns the expense
export const createPaymentApi = async (id, body) =>
    (await axiosClient.post(`/purchase-orders/${id}/payments`, body)).data?.data;

export const closeOrderApi = async (id, comment) =>
    (await axiosClient.post(`/purchase-orders/${id}/close`, { comment })).data?.data;

export const downloadPurchaseOrderPdfApi = async (id, fileName) => {
    const response = await axiosClient.get(`/purchase-orders/${id}/pdf`, { responseType: "blob" });
    const url = window.URL.createObjectURL(new Blob([response.data], { type: "application/pdf" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = fileName || "purchase-order.pdf";
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
};


// ---------------- setup: methods by amount, committees

export const getProcurementSettingsApi = async () =>
    (await axiosClient.get("/procurement/settings")).data?.data;

// { methods } or { reset: true }
export const updateProcurementSettingsApi = async (body) =>
    (await axiosClient.put("/procurement/settings", body)).data?.data;

export const getCommitteesApi = async (params = {}) =>
    (await axiosClient.get("/procurement/committees", { params })).data?.data || [];

export const getCommitteeMemberOptionsApi = async () =>
    (await axiosClient.get("/procurement/committees/members")).data?.data || [];

export const createCommitteeApi = async (body) =>
    (await axiosClient.post("/procurement/committees", body)).data?.data;

export const updateCommitteeApi = async (id, body) =>
    (await axiosClient.put(`/procurement/committees/${id}`, body)).data?.data;

export const deleteCommitteeApi = async (id) =>
    (await axiosClient.delete(`/procurement/committees/${id}`)).data;

export const getWaitingForMeApi = async () =>
    (await axiosClient.get("/procurement/waiting-for-me")).data?.data || [];
