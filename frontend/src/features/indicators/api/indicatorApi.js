import axiosClient from "../../../services/axiosClient";


// =====================================================
// M&E INDICATORS API
// =====================================================

export const getIndicatorsApi = async (params = {}) =>
    (await axiosClient.get("/indicators", { params })).data?.data || [];

export const getIndicatorApi = async (id) =>
    (await axiosClient.get(`/indicators/${id}`)).data?.data;

export const getMeasuresApi = async () =>
    (await axiosClient.get("/indicators/measures")).data?.data || [];

export const createIndicatorApi = async (data) =>
    (await axiosClient.post("/indicators", data)).data?.data;

export const updateIndicatorApi = async (id, data) =>
    (await axiosClient.put(`/indicators/${id}`, data)).data?.data;

export const deleteIndicatorApi = async (id) =>
    (await axiosClient.delete(`/indicators/${id}`)).data?.data;

export const setIndicatorValueApi = async (id, period, data) =>
    (await axiosClient.put(`/indicators/${id}/values/${period}`, data)).data?.data;

export const deleteIndicatorValueApi = async (id, period) =>
    (await axiosClient.delete(`/indicators/${id}/values/${period}`)).data?.data;

// the organization's limits: { onTrack, atRisk, defaults }
export const getMeSettingsApi = async () =>
    (await axiosClient.get("/indicators/settings")).data?.data;

// { onTrack, atRisk } or { reset: true }
export const updateMeSettingsApi = async (data) =>
    (await axiosClient.put("/indicators/settings", data)).data?.data;

export const getProgramOptionsApi = async () =>
    (await axiosClient.get("/programs/lookup")).data?.data || [];

export const getProjectOptionsApi = async () =>
    (await axiosClient.get("/projects/lookup")).data?.data || [];
