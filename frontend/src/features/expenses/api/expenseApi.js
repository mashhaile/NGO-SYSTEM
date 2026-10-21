import axiosClient
    from "../../../services/axiosClient";


// =====================================================
// EXPENSES API
// =====================================================

export const getExpensesApi = async (params = {}) =>
    (await axiosClient.get("/expenses", { params })).data;

export const getExpenseByIdApi = async (id) =>
    (await axiosClient.get(`/expenses/${id}`)).data?.data;

export const createExpenseApi = async (data) =>
    (await axiosClient.post("/expenses", data)).data?.data;

export const updateExpenseApi = async (id, data) =>
    (await axiosClient.put(`/expenses/${id}`, data)).data?.data;

export const deleteExpenseApi = async (id) =>
    (await axiosClient.delete(`/expenses/${id}`)).data;

export const submitExpenseApi = async (id) =>
    (await axiosClient.post(`/expenses/${id}/submit`)).data?.data;

export const approveExpenseApi = async (id, body = {}) =>
    (await axiosClient.post(`/expenses/${id}/approve`, body)).data?.data;

export const returnExpenseApi = async (id, comment) =>
    (await axiosClient.post(`/expenses/${id}/return`, { comment })).data?.data;

export const voidExpenseApi = async (id, comment) =>
    (await axiosClient.post(`/expenses/${id}/void`, { comment })).data?.data;


// Pickers

export const getApprovedProjectBudgetsApi = async () =>
    (await axiosClient.get("/budgets", { params: { level: "project", status: "Approved", limit: 100 } })).data?.data || [];

export const getDonationOptionsApi = async () =>
    (await axiosClient.get("/donations")).data?.data || [];

export const getProjectActivitiesApi = async (project) =>
    (await axiosClient.get("/activities", { params: { project, limit: 100 } })).data?.data || [];
