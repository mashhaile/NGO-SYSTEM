import axiosClient
    from "../../../services/axiosClient";


// =====================================================
// BUDGETS API
// =====================================================

export const getBudgetsApi = async (params = {}) =>
    (await axiosClient.get("/budgets", { params })).data;

export const getBudgetByIdApi = async (id) =>
    (await axiosClient.get(`/budgets/${id}`)).data?.data;

export const createBudgetApi = async (data) =>
    (await axiosClient.post("/budgets", data)).data?.data;

export const updateBudgetApi = async (id, data) =>
    (await axiosClient.put(`/budgets/${id}`, data)).data?.data;

export const deleteBudgetApi = async (id) =>
    (await axiosClient.delete(`/budgets/${id}`)).data;

export const submitBudgetApi = async (id) =>
    (await axiosClient.post(`/budgets/${id}/submit`)).data?.data;

export const approveBudgetApi = async (id, comment = "") =>
    (await axiosClient.post(`/budgets/${id}/approve`, { comment })).data?.data;

export const returnBudgetApi = async (id, comment) =>
    (await axiosClient.post(`/budgets/${id}/return`, { comment })).data?.data;


// Revisions of approved budgets

export const startRevisionApi = async (id) =>
    (await axiosClient.post(`/budgets/${id}/revision`)).data?.data;

export const updateRevisionApi = async (id, data) =>
    (await axiosClient.put(`/budgets/${id}/revision`, data)).data?.data;

export const cancelRevisionApi = async (id) =>
    (await axiosClient.delete(`/budgets/${id}/revision`)).data?.data;

export const submitRevisionApi = async (id) =>
    (await axiosClient.post(`/budgets/${id}/revision/submit`)).data?.data;

export const approveRevisionApi = async (id, comment = "") =>
    (await axiosClient.post(`/budgets/${id}/revision/approve`, { comment })).data?.data;

export const returnRevisionApi = async (id, comment) =>
    (await axiosClient.post(`/budgets/${id}/revision/return`, { comment })).data?.data;


// Programs / projects for the pickers

export const getProgramOptionsApi = async () =>
    (await axiosClient.get("/programs/lookup")).data?.data || [];

export const getProjectOptionsApi = async () =>
    (await axiosClient.get("/projects/lookup")).data?.data || [];

// the programs and projects that already have a budget (one each)
export const getBudgetedApi = async () =>
    (await axiosClient.get("/budgets/budgeted")).data?.data || { programs: [], projects: [] };


export const getApiErrorMessage = (error, fallback) => {

    const data = error?.response?.data;

    const details =
        Array.isArray(data?.errors)
            ? data.errors.map(item => item?.message).filter(Boolean)
            : [];

    return (
        data?.message ||
        details.join(" ") ||
        error?.message ||
        fallback
    );

};
