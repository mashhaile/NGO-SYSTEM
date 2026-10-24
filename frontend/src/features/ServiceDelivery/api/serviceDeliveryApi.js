import axiosClient from "../../../services/axiosClient";


// ==========================================
// GET SERVICE DELIVERIES
// ==========================================

export const getServiceDeliveriesApi = (
    params
) => {

    return axiosClient.get(
        "/service-deliveries",
        {
            params
        }
    );

};


// ==========================================
// GET SERVICE DELIVERY BY ID
// ==========================================

export const getServiceDeliveryByIdApi = (
    id
) => {

    return axiosClient.get(
        `/service-deliveries/${id}`
    );

};


// ==========================================
// CREATE SERVICE DELIVERY
// ==========================================

export const createServiceDeliveryApi = (
    data
) => {

    return axiosClient.post(
        "/service-deliveries",
        data
    );

};


// ==========================================
// UPDATE SERVICE DELIVERY
// ==========================================

export const updateServiceDeliveryApi = (
    id,
    data
) => {

    return axiosClient.put(
        `/service-deliveries/${id}`,
        data
    );

};


// ==========================================
// DELETE SERVICE DELIVERY
// ==========================================

export const deleteServiceDeliveryApi = (
    id
) => {

    return axiosClient.delete(
        `/service-deliveries/${id}`
    );

};

// ==========================================
// BOUGHT WITH AN EXPENSE (not charged twice)
// ==========================================

// The expenses an item may have been bought with (close ones first)
export const getExpenseOptionsApi = async (params) =>
    (await axiosClient.get("/service-deliveries/expense-options", { params })).data?.data || [];

// Delivery items and expenses that look like the same money
export const getDoubleCountingApi = async () =>
    (await axiosClient.get("/service-deliveries/double-counting")).data?.data || [];

// Link an item to its expense, or mark it as separate from it
export const setExpenseLinkApi = async (deliveryId, itemId, body) =>
    (await axiosClient.post(`/service-deliveries/${deliveryId}/items/${itemId}/expense-link`, body)).data?.data;
