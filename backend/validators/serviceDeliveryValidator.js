const Joi = require("joi");

const {
    SERVICE_DELIVERY_STATUSES,
    DEFAULT_SERVICE_DELIVERY_STATUS
} = require("../constants/serviceDeliveryStatus");


// ======================================================
// OBJECT ID VALIDATION
// ======================================================

const objectId =
    Joi.string()
        .trim()
        .pattern(/^[0-9a-fA-F]{24}$/)
        .messages({

            "string.base":
                "Value must be a valid ID.",

            "string.empty":
                "Value must be a valid ID.",

            "string.pattern.base":
                "Value must be a valid ID."

        });


// ======================================================
// DETAIL ITEM VALIDATION
// ======================================================

const detailItemSchema =
    Joi.object({

        // --------------------------------------------------
        // Existing Detail Item ID
        // --------------------------------------------------

        _id:
            objectId
                .optional()
                .messages({

                    "string.pattern.base":
                        "Detail item ID must be a valid ID."

                }),


        // --------------------------------------------------
        // Detail Item Name
        // --------------------------------------------------

        name:
            Joi.string()
                .trim()
                .max(255)
                .allow("", null)
                .default("")
                .messages({

                    "string.base":
                        "Detail item name must be text.",

                    "string.max":
                        "Detail item name cannot exceed 255 characters."

                }),


        // --------------------------------------------------
        // Quantity
        // --------------------------------------------------

        quantity:
            Joi.number()
                .integer()
                .min(1)
                .required()
                .messages({

                    "number.base":
                        "Detail item quantity must be a number.",

                    "number.integer":
                        "Detail item quantity must be a whole number.",

                    "number.min":
                        "Detail item quantity must be at least 1.",

                    "any.required":
                        "Detail item quantity is required."

                }),


        // --------------------------------------------------
        // Unit
        // --------------------------------------------------

        unit:
            objectId
                .allow(null, "")
                .default(null)
                .messages({

                    "string.pattern.base":
                        "Detail item unit ID must be a valid ID."

                }),


        // --------------------------------------------------
        // Unit Cost
        // --------------------------------------------------

        unitCost:
            Joi.number()
                .min(0)
                .required()
                .messages({

                    "number.base":
                        "Detail item unit cost must be a number.",

                    "number.min":
                        "Detail item unit cost cannot be negative.",

                    "any.required":
                        "Detail item unit cost is required."

                }),


        // --------------------------------------------------
        // Backend Calculated
        // --------------------------------------------------

        totalCost:
            Joi.any()
                .strip()

    });


// ======================================================
// SERVICE ITEM VALIDATION
// ======================================================

const serviceItemSchema =
    Joi.object({

        // --------------------------------------------------
        // Existing Service Item ID
        // --------------------------------------------------

        _id:
            objectId
                .optional()
                .messages({

                    "string.pattern.base":
                        "Service item ID must be a valid ID."

                }),


        // --------------------------------------------------
        // Service Category
        // --------------------------------------------------

        serviceCategory:
            objectId
                .required()
                .messages({

                    "any.required":
                        "Service category is required.",

                    "string.empty":
                        "Service category is required.",

                    "string.pattern.base":
                        "Service category ID must be a valid ID."

                }),


        // --------------------------------------------------
        // Service Type
        // --------------------------------------------------

        serviceType:
            objectId
                .required()
                .messages({

                    "any.required":
                        "Service type is required.",

                    "string.empty":
                        "Service type is required.",

                    "string.pattern.base":
                        "Service type ID must be a valid ID."

                }),


        // --------------------------------------------------
        // Allocation Behavior
        //
        // This is accepted for backward compatibility,
        // but the backend MUST resolve the authoritative
        // value from the selected ServiceType lookup.
        // --------------------------------------------------

        allocationBehavior:
            Joi.string()
                .valid(
                    "CONSUMPTION",
                    "PARTICIPATION"
                )
                .optional()
                .messages({

                    "any.only":
                        "Service item allocation behavior is invalid."

                }),


        // --------------------------------------------------
        // Quantity
        // --------------------------------------------------

        quantity:
            Joi.number()
                .integer()
                .min(1)
                .required()
                .messages({

                    "number.base":
                        "Service item quantity must be a number.",

                    "number.integer":
                        "Service item quantity must be a whole number.",

                    "number.min":
                        "Service item quantity must be at least 1.",

                    "any.required":
                        "Service item quantity is required."

                }),


        // --------------------------------------------------
        // Unit
        // --------------------------------------------------

        unit:
            objectId
                .required()
                .messages({

                    "any.required":
                        "Service item unit is required.",

                    "string.empty":
                        "Service item unit is required.",

                    "string.pattern.base":
                        "Service item unit ID must be a valid ID."

                }),


        // --------------------------------------------------
        // Unit Cost
        // --------------------------------------------------

        unitCost:
            Joi.number()
                .min(0)
                .required()
                .messages({

                    "number.base":
                        "Service item unit cost must be a number.",

                    "number.min":
                        "Service item unit cost cannot be negative.",

                    "any.required":
                        "Service item unit cost is required."

                }),


        // --------------------------------------------------
        // Backend Calculated
        // --------------------------------------------------

        totalCost:
            Joi.any()
                .strip(),


        // --------------------------------------------------
        // Donor
        // --------------------------------------------------

        donor:
            objectId
                .allow(null, "")
                .default(null)
                .messages({

                    "string.pattern.base":
                        "Donor ID must be a valid ID."

                }),


        // --------------------------------------------------
        // Donation
        // --------------------------------------------------

        donation:
            objectId
                .allow(null, "")
                .default(null)
                .messages({

                    "string.pattern.base":
                        "Donation ID must be a valid ID."

                }),


        // --------------------------------------------------
        // Detail Items
        // --------------------------------------------------

        detailItems:
            Joi.array()
                .items(
                    detailItemSchema
                )
                .default([])
                .messages({

                    "array.base":
                        "Detail items must be an array."

                }),


        // --------------------------------------------------
        // Remarks
        // --------------------------------------------------

        remarks:
            Joi.string()
                .trim()
                .allow("", null)
                .default("")

    });


// ======================================================
// DOCUMENT VALIDATION
// ======================================================

const documentSchema =
    Joi.object({

        documentType:
            Joi.string()
                .trim()
                .allow("", null)
                .default(""),

        fileName:
            Joi.string()
                .trim()
                .allow("", null)
                .default(""),

        fileUrl:
            Joi.string()
                .trim()
                .allow("", null)
                .default(""),

        uploadedAt:
            Joi.date()
                .default(Date.now)

    });


// ======================================================
// BENEFICIARY ALLOCATION VALIDATION
// ======================================================

const beneficiaryAllocationSchema =
    Joi.object({

        // --------------------------------------------------
        // Service Item
        // --------------------------------------------------

        serviceItem:
            objectId
                .required()
                .messages({

                    "any.required":
                        "Beneficiary allocation must reference a service item.",

                    "string.empty":
                        "Beneficiary allocation must reference a service item.",

                    "string.pattern.base":
                        "Allocated service item ID must be a valid ID."

                }),


        // --------------------------------------------------
        // Detail Item
        // --------------------------------------------------

        detailItem:
            objectId
                .allow(null, "")
                .default(null)
                .messages({

                    "string.pattern.base":
                        "Allocated detail item ID must be a valid ID."

                }),


        // --------------------------------------------------
        // Quantity
        //
        // Monetary allocations are normalized by the
        // backend to quantity = 0.
        // --------------------------------------------------

        quantity:
            Joi.number()
                .min(0)
                .default(0)
                .messages({

                    "number.base":
                        "Beneficiary allocation quantity must be a number.",

                    "number.min":
                        "Beneficiary allocation quantity must be zero or greater."

                }),


        // --------------------------------------------------
        // Allocated Value
        // --------------------------------------------------

        allocatedValue:
            Joi.number()
                .min(0)
                .default(0)
                .messages({

                    "number.base":
                        "Beneficiary allocated value must be a number.",

                    "number.min":
                        "Beneficiary allocated value must be zero or greater."

                }),


        // --------------------------------------------------
        // Remarks
        // --------------------------------------------------

        remarks:
            Joi.string()
                .trim()
                .allow("", null)
                .default("")

    })
    .custom(
        (allocation, helpers) => {

            const quantity =
                Number(
                    allocation.quantity || 0
                );

            const allocatedValue =
                Number(
                    allocation.allocatedValue || 0
                );


            if (
                quantity <= 0 &&
                allocatedValue <= 0
            ) {

                return helpers.error(
                    "any.allocationValueRequired"
                );

            }


            return allocation;

        }
    )
    .messages({

        "any.allocationValueRequired":
            "A beneficiary allocation must contain a quantity or allocated value greater than zero."

    });


// ======================================================
// BENEFICIARY ASSOCIATION VALIDATION
// ======================================================

const beneficiaryAssociationSchema =
    Joi.object({

        beneficiary:
            objectId
                .required()
                .messages({

                    "any.required":
                        "Each beneficiary record must contain a beneficiary.",

                    "string.empty":
                        "Each beneficiary record must contain a beneficiary.",

                    "string.pattern.base":
                        "Beneficiary ID must be a valid ID."

                }),


        enrollment:
            objectId
                .allow(null, "")
                .default(null)
                .messages({

                    "string.pattern.base":
                        "Beneficiary enrollment ID must be a valid ID."

                }),


        status:
            Joi.string()
                .valid(
                    "Received",
                    "Participated",
                    "Missed",
                    "Referred",
                    "Pending"
                )
                .default("Received")
                .messages({

                    "any.only":
                        "Beneficiary service status is invalid."

                }),


        quantity:
            Joi.number()
                .min(0)
                .allow(null)
                .default(null)
                .messages({

                    "number.base":
                        "Beneficiary quantity must be a number.",

                    "number.min":
                        "Beneficiary quantity must be zero or greater."

                }),


        allocations:
            Joi.array()
                .items(
                    beneficiaryAllocationSchema
                )
                .default([])
                .custom(

                    (allocations, helpers) => {

                        const seen =
                            new Set();

                        const allocationModes =
                            new Map();


                        for (
                            const allocation
                            of allocations
                        ) {

                            const serviceItemId =
                                String(
                                    allocation.serviceItem
                                );


                            const detailItemId =
                                allocation.detailItem
                                    ? String(
                                        allocation.detailItem
                                    )
                                    : null;


                            const mode =
                                detailItemId
                                    ? "DETAIL"
                                    : "PARENT";


                            const existingMode =
                                allocationModes.get(
                                    serviceItemId
                                );


                            if (
                                existingMode &&
                                existingMode !== mode
                            ) {

                                return helpers.error(
                                    "array.parentDetailMixed"
                                );

                            }


                            allocationModes.set(
                                serviceItemId,
                                mode
                            );


                            const allocationKey =
                                detailItemId
                                    ? `${serviceItemId}:${detailItemId}`
                                    : `${serviceItemId}:__DIRECT__`;


                            if (
                                seen.has(
                                    allocationKey
                                )
                            ) {

                                return helpers.error(
                                    "array.unique"
                                );

                            }


                            seen.add(
                                allocationKey
                            );

                        }


                        return allocations;

                    }
                )
                .messages({

                    "array.unique":
                        "A beneficiary cannot have duplicate allocations for the same service item and detail item.",

                    "array.parentDetailMixed":
                        "A beneficiary cannot have both a service-item allocation and detail-item allocations for the same service item."

                }),


        remarks:
            Joi.string()
                .trim()
                .allow("", null)
                .default("")

    });


// ======================================================
// BENEFICIARY LIST VALIDATION
// ======================================================

const beneficiariesSchema =
    Joi.array()
        .items(

            Joi.alternatives()
                .try(

                    objectId
                        .messages({

                            "string.pattern.base":
                                "Beneficiary ID must be a valid ID."

                        }),

                    beneficiaryAssociationSchema

                )

        )
        .custom(

            (beneficiaries, helpers) => {

                const seen =
                    new Set();


                for (
                    const record
                    of beneficiaries
                ) {

                    const beneficiaryId =
                        typeof record === "string"
                            ? record
                            : record?.beneficiary;


                    if (
                        !beneficiaryId
                    ) {

                        return helpers.error(
                            "array.beneficiaryRequired"
                        );

                    }


                    const normalizedId =
                        String(
                            beneficiaryId
                        );


                    if (
                        seen.has(
                            normalizedId
                        )
                    ) {

                        return helpers.error(
                            "array.uniqueBeneficiary"
                        );

                    }


                    seen.add(
                        normalizedId
                    );

                }


                return beneficiaries;

            }

        )
        .default([])
        .messages({

            "array.beneficiaryRequired":
                "Each beneficiary record must contain a beneficiary.",

            "array.uniqueBeneficiary":
                "A beneficiary cannot be selected more than once."

        });


// ======================================================
// CREATE FIELDS
// ======================================================

const createFields = {

    recipientType:
        Joi.string()
            .valid(
                "Individual",
                "Household",
                "Group / Community",
                "Institution"
            )
            .default("Individual")
            .messages({

                "any.only":
                    "Service delivery recipient type is invalid."

            }),


    recipientName:
        Joi.string()
            .trim()
            .allow("", null)
            .max(255)
            .default("")
            .messages({

                "string.max":
                    "Recipient name cannot exceed 255 characters."

            }),


    allocationMethod:
        Joi.string()
            .valid(
                "Individual",
                "Shared",
                "Group",
                "Unallocated"
            )
            .default("Unallocated")
            .messages({

                "any.only":
                    "Service delivery allocation method is invalid."

            }),


    beneficiary:
        objectId
            .allow(null, "")
            .default(null)
            .messages({

                "string.pattern.base":
                    "Beneficiary ID must be a valid ID."

            }),


    beneficiaries:
        beneficiariesSchema,


    enrollment:
        objectId
            .allow(null, "")
            .default(null),


    program:
        objectId
            .required()
            .messages({

                "any.required":
                    "Program is required.",

                "string.empty":
                    "Program is required.",

                "string.pattern.base":
                    "Program ID must be a valid ID."

            }),


    project:
        objectId
            .allow(null, "")
            .default(null),


    activity:
        objectId
            .allow(null, "")
            .default(null),


    activityRun:
        objectId
            .allow(null, "")
            .default(null),


    fundingSource:
        objectId
            .allow(null, "")
            .default(null),


    donation:
        objectId
            .allow(null, "")
            .default(null),


    items:
        Joi.array()
            .items(
                serviceItemSchema
            )
            .min(1)
            .required()
            .messages({

                "array.min":
                    "At least one service item is required.",

                "any.required":
                    "At least one service item is required."

            }),


    deliveryDate:
        Joi.date()
            .default(Date.now)
            .messages({

                "date.base":
                    "Delivery date must be a valid date."

            }),


    deliveryLocation:
        Joi.string()
            .trim()
            .allow("", null)
            .default(""),


    status:
        Joi.string()
            .valid(
                ...SERVICE_DELIVERY_STATUSES
            )
            .default(DEFAULT_SERVICE_DELIVERY_STATUS)
            .messages({

                "any.only":
                    "Service delivery status is invalid."

            }),


    deliveredBy:
        objectId
            .allow(null, "")
            .default(null),


    documents:
        Joi.array()
            .items(
                documentSchema
            )
            .default([])

};


// ======================================================
// SERVER CONTROLLED FIELDS
// ======================================================

const serverControlledFields = {

    deliveryNumber:
        Joi.any()
            .strip(),

    totalAmount:
        Joi.any()
            .strip(),

    organization:
        Joi.any()
            .strip(),

    createdBy:
        Joi.any()
            .strip(),

    updatedBy:
        Joi.any()
            .strip(),

    deletedBy:
        Joi.any()
            .strip(),

    deletedAt:
        Joi.any()
            .strip(),

    isDeleted:
        Joi.any()
            .strip(),

    isDeletedAt:
        Joi.any()
            .strip()

};


// ======================================================
// CREATE RECIPIENT RULES
// ======================================================

const validateCreateRecipientRules =
    (value, helpers) => {

        const recipientType =
            value.recipientType ||
            "Individual";

        const allocationMethod =
            value.allocationMethod ||
            "Unallocated";

        const recipientName =
            typeof value.recipientName === "string"
                ? value.recipientName.trim()
                : "";

        const beneficiaries =
            Array.isArray(value.beneficiaries)
                ? value.beneficiaries
                : [];

        const hasLegacyBeneficiary =
            value.beneficiary !== undefined &&
            value.beneficiary !== null &&
            value.beneficiary !== "";

        const hasBeneficiaries =
            beneficiaries.length > 0 ||
            hasLegacyBeneficiary;


        // ------------------------------------------------
        // Named recipients
        // ------------------------------------------------

        if (
            [
                "Household",
                "Group / Community",
                "Institution"
            ].includes(recipientType) &&
            !recipientName
        ) {

            return helpers.error(
                "any.recipientNameRequired"
            );

        }


        // ------------------------------------------------
        // Individual + Individual
        // ------------------------------------------------

        if (
            recipientType === "Individual" &&
            allocationMethod === "Individual" &&
            !hasBeneficiaries
        ) {

            return helpers.error(
                "any.beneficiaryRequired"
            );

        }


        // ------------------------------------------------
        // Individual + Shared
        // ------------------------------------------------

        if (
            recipientType === "Individual" &&
            allocationMethod === "Shared" &&
            !hasBeneficiaries
        ) {

            return helpers.error(
                "any.beneficiaryRequired"
            );

        }


        // ------------------------------------------------
        // Individual + Unallocated
        //
        // This is allowed only when there are no
        // beneficiaries.
        // ------------------------------------------------

        if (
            recipientType === "Individual" &&
            allocationMethod === "Unallocated" &&
            hasBeneficiaries
        ) {

            return helpers.error(
                "any.individualUnallocated"
            );

        }


        // ------------------------------------------------
        // Group / Community
        // ------------------------------------------------

        if (
            recipientType === "Group / Community" &&
            ![
                "Group",
                "Unallocated"
            ].includes(allocationMethod)
        ) {

            return helpers.error(
                "any.invalidRecipientAllocation"
            );

        }


        // ------------------------------------------------
        // Household
        // ------------------------------------------------

        if (
            recipientType === "Household" &&
            ![
                "Shared",
                "Unallocated",
                "Individual"
            ].includes(allocationMethod)
        ) {

            return helpers.error(
                "any.invalidRecipientAllocation"
            );

        }


        // ------------------------------------------------
        // Institution
        // ------------------------------------------------

        if (
            recipientType === "Institution" &&
            ![
                "Shared",
                "Unallocated",
                "Group"
            ].includes(allocationMethod)
        ) {

            return helpers.error(
                "any.invalidRecipientAllocation"
            );

        }


        return value;

    };


// ======================================================
// CREATE SCHEMA
// ======================================================

const createServiceDeliverySchema =
    Joi.object({

        ...createFields,

        ...serverControlledFields

    })
    .custom(
        validateCreateRecipientRules
    )
    .messages({

        "any.recipientNameRequired":
            "Recipient name is required for household, group/community, or institution service deliveries.",

        "any.beneficiaryRequired":
            "At least one beneficiary is required for this recipient and allocation combination.",

        "any.individualUnallocated":
            "An individual recipient with beneficiaries cannot use unallocated allocation.",

        "any.invalidRecipientAllocation":
            "The selected recipient type and allocation method are not compatible."

    });


// ======================================================
// UPDATE FIELDS
//
// IMPORTANT:
//
// DO NOT reuse the create schemas directly because
// create schemas contain defaults.
//
// Defaults on update can silently overwrite existing
// database values during PATCH operations.
//
// Every field below is intentionally optional and does
// not inherit create defaults.
// ======================================================

const updateFields = {

    recipientType:
        Joi.string()
            .valid(
                "Individual",
                "Household",
                "Group / Community",
                "Institution"
            )
            .optional()
            .messages({

                "any.only":
                    "Service delivery recipient type is invalid."

            }),


    recipientName:
        Joi.string()
            .trim()
            .allow("", null)
            .max(255)
            .optional()
            .messages({

                "string.max":
                    "Recipient name cannot exceed 255 characters."

            }),


    allocationMethod:
        Joi.string()
            .valid(
                "Individual",
                "Shared",
                "Group",
                "Unallocated"
            )
            .optional()
            .messages({

                "any.only":
                    "Service delivery allocation method is invalid."

            }),


    beneficiary:
        objectId
            .allow(null, "")
            .optional(),


    beneficiaries:
        Joi.array()
            .items(

                Joi.alternatives()
                    .try(

                        objectId,

                        beneficiaryAssociationSchema

                    )

            )
            .optional()
            .custom(

                (beneficiaries, helpers) => {

                    const seen =
                        new Set();


                    for (
                        const record
                        of beneficiaries
                    ) {

                        const beneficiaryId =
                            typeof record === "string"
                                ? record
                                : record?.beneficiary;


                        if (
                            !beneficiaryId
                        ) {

                            return helpers.error(
                                "array.beneficiaryRequired"
                            );

                        }


                        const id =
                            String(
                                beneficiaryId
                            );


                        if (
                            seen.has(id)
                        ) {

                            return helpers.error(
                                "array.uniqueBeneficiary"
                            );

                        }


                        seen.add(id);

                    }


                    return beneficiaries;

                }
            )
            .messages({

                "array.beneficiaryRequired":
                    "Each beneficiary record must contain a beneficiary.",

                "array.uniqueBeneficiary":
                    "A beneficiary cannot be selected more than once."

            }),


    enrollment:
        objectId
            .allow(null, "")
            .optional(),


    program:
        objectId
            .optional()
            .messages({

                "string.pattern.base":
                    "Program ID must be a valid ID."

            }),


    project:
        objectId
            .allow(null, "")
            .optional(),


    activity:
        objectId
            .allow(null, "")
            .optional(),


    activityRun:
        objectId
            .allow(null, "")
            .optional(),


    fundingSource:
        objectId
            .allow(null, "")
            .optional(),


    donation:
        objectId
            .allow(null, "")
            .optional(),


    items:
        Joi.array()
            .items(
                serviceItemSchema
            )
            .min(1)
            .optional()
            .messages({

                "array.min":
                    "At least one service item is required."

            }),


    deliveryDate:
        Joi.date()
            .optional()
            .messages({

                "date.base":
                    "Delivery date must be a valid date."

            }),


    deliveryLocation:
        Joi.string()
            .trim()
            .allow("", null)
            .optional(),


    status:
        Joi.string()
            .valid(
                ...SERVICE_DELIVERY_STATUSES
            )
            .optional()
            .messages({

                "any.only":
                    "Service delivery status is invalid."

            }),


    deliveredBy:
        objectId
            .allow(null, "")
            .optional(),


    documents:
        Joi.array()
            .items(
                documentSchema
            )
            .optional(),


    ...serverControlledFields

};


// ======================================================
// UPDATE SCHEMA
// ======================================================

const updateServiceDeliverySchema =
    Joi.object(
        updateFields
    )
    .min(1);


// ======================================================
// EXPORT
// ======================================================

module.exports = {

    createServiceDeliverySchema,

    updateServiceDeliverySchema

};