const {
    createServiceDelivery,
    getServiceDeliveries,
    getServiceDeliveryById,
    updateServiceDelivery,
    deleteServiceDelivery
} = require("../services/serviceDeliveryService");

const {
    createAuditLog
} = require("../services/auditLogService");


// ==========================================
// HELPERS
// ==========================================

const buildAuditMetadata = (service) => {

    const beneficiaries =
        Array.isArray(service?.beneficiaries)
            ? service.beneficiaries.map((association) => ({
                _id:
                    association?._id || null,

                beneficiary:
                    association?.beneficiary || null,

                enrollment:
                    association?.enrollment || null,

                status:
                    association?.status || null,

                quantity:
                    association?.quantity ?? null,

                remarks:
                    association?.remarks || "",

                allocations:
                    Array.isArray(
                        association?.allocations
                    )
                        ? association.allocations.map(
                            (allocation) => ({
                                _id:
                                    allocation?._id || null,

                                serviceItem:
                                    allocation?.serviceItem || null,

                                detailItem:
                                    allocation?.detailItem || null,

                                quantity:
                                    Number(
                                        allocation?.quantity ?? 0
                                    ),

                                allocatedValue:
                                    Number(
                                        allocation?.allocatedValue ?? 0
                                    ),

                                remarks:
                                    allocation?.remarks || ""
                            })
                        )
                        : []
            }))
            : [];

    return {

        deliveryNumber:
            service?.deliveryNumber || null,

        recipientType:
            service?.recipientType || null,

        allocationMethod:
            service?.allocationMethod || null,

        beneficiary:
            service?.beneficiary || null,

        beneficiaries,

        program:
            service?.program || null,

        project:
            service?.project || null,

        activity:
            service?.activity || null,

        activityRun:
            service?.activityRun || null,

        enrollment:
            service?.enrollment || null,

        fundingSource:
            service?.fundingSource || null,

        donation:
            service?.donation || null,

        // ======================================
        // SERVICE ITEMS
        // ======================================

        items:
            Array.isArray(service?.items)
                ? service.items.map((item) => ({

                    _id:
                        item?._id || null,

                    serviceCategory:
                        item?.serviceCategory || null,

                    serviceType:
                        item?.serviceType || null,

                    quantity:
                        Number(
                            item?.quantity ?? 0
                        ),

                    unit:
                        item?.unit || null,

                    unitCost:
                        Number(
                            item?.unitCost ?? 0
                        ),

                    totalCost:
                        Number(
                            item?.totalCost ?? 0
                        ),

                    // ==================================
                    // DONOR
                    // ==================================

                    donor:
                        item?.donor || null,

                    // ==================================
                    // DONATION
                    // ==================================

                    donation:
                        item?.donation || null,

                    // ==================================
                    // DETAIL ITEMS
                    // ==================================

                    detailItems:
                        Array.isArray(
                            item?.detailItems
                        )
                            ? item.detailItems.map(
                                (detailItem) => ({

                                    _id:
                                        detailItem?._id ||
                                        null,

                                    name:
                                        typeof detailItem?.name ===
                                        "string"
                                            ? detailItem.name
                                            : "",

                                    quantity:
                                        Number(
                                            detailItem?.quantity ??
                                            0
                                        ),

                                    unit:
                                        detailItem?.unit ||
                                        null,

                                    allocationUnit:
                                        detailItem?.allocationUnit ||
                                        null,

                                    allocationConversionFactor:
                                        Number(
                                            detailItem?.allocationConversionFactor ??
                                            1
                                        ),

                                    unitCost:
                                        Number(
                                            detailItem?.unitCost ??
                                            0
                                        ),

                                    totalCost:
                                        Number(
                                            detailItem?.totalCost ??
                                            0
                                        )

                                })
                            )
                            : [],

                    remarks:
                        item?.remarks || ""

                }))
                : [],

        totalAmount:
            Number(
                service?.totalAmount ?? 0
            )

    };

};


// ==========================================
// CREATE SERVICE DELIVERY
// ==========================================

const createServiceDeliveryController = async (
    req,
    res
) => {

    try {

        const service =
            await createServiceDelivery(
                req.body,
                req.user.organizationId,
                req.user.userId
            );


        await createAuditLog({

            organizationId:
                req.user.organizationId,

            userId:
                req.user.userId,

            action:
                "CREATE",

            module:
                "ServiceDelivery",

            entityType:
                "ServiceDelivery",

            entityId:
                service._id,

            description:
                "Service delivery created",

            metadata:
                buildAuditMetadata(
                    service
                ),

            ipAddress:
                req.ip,

            userAgent:
                req.headers["user-agent"]

        });


        res.status(201).json({

            success: true,

            message:
                "Service delivery created successfully",

            data:
                service

        });

    }

    catch (error) {

        res.status(400).json({

            success: false,

            message:
                error.message

        });

    }

};


// ==========================================
// GET ALL SERVICE DELIVERIES
// ==========================================

const getServiceDeliveriesController = async (
    req,
    res
) => {

    try {

        const services =
            await getServiceDeliveries(
                req.user.organizationId
            );


        res.json({

            success: true,

            message:
                "Service deliveries fetched successfully",

            data:
                services

        });

    }

    catch (error) {

        res.status(500).json({

            success: false,

            message:
                error.message

        });

    }

};


// ==========================================
// GET SINGLE SERVICE DELIVERY
// ==========================================

const getServiceDeliveryByIdController = async (
    req,
    res
) => {

    try {

        const service =
            await getServiceDeliveryById(
                req.params.id,
                req.user.organizationId
            );


        res.json({

            success: true,

            data:
                service

        });

    }

    catch (error) {

        res.status(404).json({

            success: false,

            message:
                error.message

        });

    }

};


// ==========================================
// UPDATE SERVICE DELIVERY
// ==========================================

const updateServiceDeliveryController = async (
    req,
    res
) => {

    try {

        const service =
            await updateServiceDelivery(
                req.params.id,
                req.body,
                req.user.organizationId,
                req.user.userId
            );


        await createAuditLog({

            organizationId:
                req.user.organizationId,

            userId:
                req.user.userId,

            action:
                "UPDATE",

            module:
                "ServiceDelivery",

            entityType:
                "ServiceDelivery",

            entityId:
                service._id,

            description:
                "Service delivery updated",

            metadata:
                buildAuditMetadata(
                    service
                ),

            ipAddress:
                req.ip,

            userAgent:
                req.headers["user-agent"]

        });


        res.json({

            success: true,

            message:
                "Service delivery updated successfully",

            data:
                service

        });

    }

    catch (error) {

        res.status(400).json({

            success: false,

            message:
                error.message

        });

    }

};


// ==========================================
// DELETE SERVICE DELIVERY
// ==========================================

const deleteServiceDeliveryController = async (
    req,
    res
) => {

    try {

        const service =
            await deleteServiceDelivery(
                req.params.id,
                req.user.organizationId,
                req.user.userId
            );


        await createAuditLog({

            organizationId:
                req.user.organizationId,

            userId:
                req.user.userId,

            action:
                "DELETE",

            module:
                "ServiceDelivery",

            entityType:
                "ServiceDelivery",

            entityId:
                service._id,

            description:
                "Service delivery deleted",

            metadata: {

                deliveryNumber:
                    service?.deliveryNumber ||
                    null

            },

            ipAddress:
                req.ip,

            userAgent:
                req.headers["user-agent"]

        });


        res.json({

            success: true,

            message:
                "Service delivery deleted successfully"

        });

    }

    catch (error) {

        res.status(400).json({

            success: false,

            message:
                error.message

        });

    }

};


// ==========================================
// EXPORTS
// ==========================================

module.exports = {

    createServiceDeliveryController,

    getServiceDeliveriesController,

    getServiceDeliveryByIdController,

    updateServiceDeliveryController,

    deleteServiceDeliveryController

};