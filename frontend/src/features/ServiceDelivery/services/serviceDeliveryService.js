import {
    getServiceDeliveriesApi,
    getServiceDeliveryByIdApi,
    createServiceDeliveryApi,
    updateServiceDeliveryApi,
    deleteServiceDeliveryApi
} from "../api/serviceDeliveryApi";


// =====================================================
// GET ALL SERVICE DELIVERIES
// =====================================================

export const getServiceDeliveriesService = (
    params = {}
) => {

    return getServiceDeliveriesApi(
        params
    );

};


// =====================================================
// GET SERVICE DELIVERY BY ID
// =====================================================

export const getServiceDeliveryByIdService = (
    id
) => {

    if (
        id === undefined ||
        id === null ||
        id === ""
    ) {

        throw new Error(
            "Service delivery ID is required."
        );

    }

    return getServiceDeliveryByIdApi(
        id
    );

};


// =====================================================
// CREATE SERVICE DELIVERY
// =====================================================

export const createServiceDeliveryService = (
    data
) => {

    if (
        !data ||
        typeof data !== "object"
    ) {

        throw new Error(
            "Service delivery data is required."
        );

    }

    return createServiceDeliveryApi(
        data
    );

};


// =====================================================
// UPDATE SERVICE DELIVERY
// =====================================================

export const updateServiceDeliveryService = (
    id,
    data
) => {

    if (
        id === undefined ||
        id === null ||
        id === ""
    ) {

        throw new Error(
            "Service delivery ID is required."
        );

    }

    if (
        !data ||
        typeof data !== "object"
    ) {

        throw new Error(
            "Service delivery data is required."
        );

    }

    return updateServiceDeliveryApi(
        id,
        data
    );

};


// =====================================================
// DELETE SERVICE DELIVERY
// =====================================================

export const deleteServiceDeliveryService = (
    id
) => {

    if (
        id === undefined ||
        id === null ||
        id === ""
    ) {

        throw new Error(
            "Service delivery ID is required."
        );

    }

    return deleteServiceDeliveryApi(
        id
    );

};