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