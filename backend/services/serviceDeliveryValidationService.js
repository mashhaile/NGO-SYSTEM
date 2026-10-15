const mongoose =
    require("mongoose");

const Beneficiary =
    require("../models/Beneficiary");

const Enrollment =
    require("../models/enrollment");

const Program =
    require("../models/Program");

const Project =
    require("../models/Project");

const Activity =
    require("../models/Activity");

const ActivityRun =
    require("../models/ActivityRun");

const Donation =
    require("../models/donation");

const Donor =
    require("../models/Donor");

const Lookup =
    require("../models/Lookup");


// ======================================================
// VALIDATE OBJECT ID
// ======================================================

const validateObjectId = (

    value,

    fieldName

) => {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return;

    }


    if (
        !mongoose.Types.ObjectId.isValid(
            value
        )
    ) {

        throw new Error(
            `${fieldName} is invalid.`
        );

    }

};


// ======================================================
// NORMALIZE ALLOCATION BEHAVIOR
// ======================================================

const normalizeAllocationBehavior = (

    value

) => {

    const normalized =
        String(
            value ?? ""
        )
            .trim()
            .toUpperCase();


    if (
        normalized ===
        "PARTICIPATION"
    ) {

        return "PARTICIPATION";

    }


    if (
        normalized ===
        "CONSUMPTION"
    ) {

        return "CONSUMPTION";

    }


    return null;

};


// ======================================================
// NORMALIZE UNIT SEMANTIC TYPE
// ======================================================

const normalizeSemanticType = (

    value

) => {

    const normalized =
        String(
            value ?? ""
        )
            .trim()
            .toLowerCase();


    if (
        normalized ===
        "monetary"
    ) {

        return "monetary";

    }


    if (
        normalized ===
        "physical"
    ) {

        return "physical";

    }


    return null;

};


// ======================================================
// NORMALIZE BENEFICIARIES
// ======================================================

const normalizeBeneficiaries = (

    data

) => {

    let records = [];


    if (
        Array.isArray(
            data.beneficiaries
        )
    ) {

        records =
            data.beneficiaries;

    }

    else if (
        data.beneficiary
    ) {

        records = [

            data.beneficiary

        ];

    }


    return records

        .filter(Boolean)

        .map((record) => {

            if (
                typeof record ===
                "string"
            ) {

                return {

                    beneficiary:
                        record,

                    enrollment:
                        null,

                    status:
                        "Received",

                    remarks:
                        "",

                    allocations:
                        []

                };

            }


            if (
                record &&
                typeof record ===
                "object"
            ) {

                return {

                    beneficiary:
                        record.beneficiary ||
                        record._id ||
                        null,

                    enrollment:
                        record.enrollment ||
                        null,

                    status:
                        record.status ||
                        "Received",

                    remarks:
                        record.remarks ||
                        "",

                    allocations:
                        Array.isArray(
                            record.allocations
                        )
                            ? record.allocations
                            : []

                };

            }


            return {

                beneficiary:
                    null,

                enrollment:
                    null,

                status:
                    "Received",

                remarks:
                    "",

                allocations:
                    []

            };

        });

};


// ======================================================
// VALIDATE BENEFICIARY RECORDS
// ======================================================

const validateBeneficiaryRecords = (

    records

) => {

    const seen =
        new Set();


    const allowedStatuses = [

        "Received",
        "Participated",
        "Missed",
        "Referred",
        "Pending"

    ];


    for (
        const record
        of records
    ) {

        if (
            !record.beneficiary
        ) {

            throw new Error(
                "Each beneficiary record must contain a beneficiary."
            );

        }


        validateObjectId(

            record.beneficiary,

            "Beneficiary"

        );


        const beneficiaryId =
            String(
                record.beneficiary
            );


        if (
            seen.has(
                beneficiaryId
            )
        ) {

            throw new Error(
                "A beneficiary cannot be selected more than once in the same service delivery."
            );

        }


        seen.add(
            beneficiaryId
        );


        if (
            !allowedStatuses.includes(
                record.status
            )
        ) {

            throw new Error(
                "Beneficiary service status is invalid."
            );

        }


        if (

            record.remarks !== undefined &&
            record.remarks !== null &&
            typeof record.remarks !== "string"

        ) {

            throw new Error(
                "Beneficiary remarks must be text."
            );

        }


        if (
            record.enrollment
        ) {

            validateObjectId(

                record.enrollment,

                "Beneficiary enrollment"

            );

        }


        if (
            !Array.isArray(
                record.allocations
            )
        ) {

            throw new Error(
                "Beneficiary allocations must be an array."
            );

        }


        const allocationModes =
            new Map();


        const allocationKeys =
            new Set();


        for (
            const allocation
            of record.allocations
        ) {

            if (
                !allocation ||
                !allocation.serviceItem
            ) {

                throw new Error(
                    "Each beneficiary allocation must reference a service item."
                );

            }


            validateObjectId(

                allocation.serviceItem,

                "Allocated service item"

            );


            const serviceItemId =
                String(
                    allocation.serviceItem
                );


            let detailItemId =
                null;


            if (
                allocation.detailItem
            ) {

                validateObjectId(

                    allocation.detailItem,

                    "Allocated detail item"

                );


                detailItemId =
                    String(
                        allocation.detailItem
                    );

            }


            const allocationMode =
                detailItemId
                    ? "DETAIL"
                    : "PARENT";


            const existingMode =
                allocationModes.get(
                    serviceItemId
                );


            if (
                existingMode &&
                existingMode !== allocationMode
            ) {

                throw new Error(
                    "A beneficiary cannot have both a service-item allocation and detail-item allocations for the same service item."
                );

            }


            allocationModes.set(
                serviceItemId,
                allocationMode
            );


            const allocationKey =
                detailItemId
                    ? `${serviceItemId}:${detailItemId}`
                    : `${serviceItemId}:PARENT`;


            if (
                allocationKeys.has(
                    allocationKey
                )
            ) {

                throw new Error(
                    detailItemId
                        ? "A beneficiary cannot have duplicate allocations for the same service detail item."
                        : "A beneficiary cannot have duplicate allocations for the same service item."
                );

            }


            allocationKeys.add(
                allocationKey
            );


            const quantity =
                Number(
                    allocation.quantity ?? 0
                );


            if (
                !Number.isFinite(
                    quantity
                ) ||
                quantity < 0
            ) {

                throw new Error(
                    "Beneficiary allocation quantity must be zero or greater."
                );

            }


            const allocatedValue =
                Number(
                    allocation.allocatedValue ?? 0
                );


            if (
                !Number.isFinite(
                    allocatedValue
                ) ||
                allocatedValue < 0
            ) {

                throw new Error(
                    "Beneficiary allocated value must be zero or greater."
                );

            }


            if (
                quantity <= 0 &&
                allocatedValue <= 0
            ) {

                throw new Error(
                    "A beneficiary allocation must contain a quantity or allocated value greater than zero."
                );

            }


            if (

                allocation.remarks !== undefined &&
                allocation.remarks !== null &&
                typeof allocation.remarks !== "string"

            ) {

                throw new Error(
                    "Allocation remarks must be text."
                );

            }

        }

    }

};


// ======================================================
// VALIDATE SERVICE DELIVERY LOOKUP
// ======================================================

const validateServiceDeliveryLookup = async (

    lookupId,

    organizationId,

    category,

    fieldName

) => {

    validateObjectId(

        lookupId,

        fieldName

    );


    const lookup =
        await Lookup.findOne({

            _id:
                lookupId,

            organization:
                organizationId,

            module:
                "ServiceDelivery",

            category,

            active:
                true

        });


    if (!lookup) {

        throw new Error(
            `${fieldName} is invalid.`
        );

    }


    return lookup;

};


// ======================================================
// VALIDATE SERVICE TYPE PARENT
// ======================================================

const validateServiceTypeParent = (

    serviceType,

    serviceCategoryId

) => {

    if (
        !serviceType.parentLookup
    ) {

        throw new Error(
            "Service type must belong to a service category."
        );

    }


    if (
        String(
            serviceType.parentLookup
        ) !==
        String(
            serviceCategoryId
        )
    ) {

        throw new Error(
            "Selected service type does not belong to the selected service category."
        );

    }

};


// ======================================================
// RESOLVE ALLOCATION BEHAVIOR
//
// ServiceType is authoritative.
// Client supplied allocationBehavior is never trusted.
// ======================================================

const resolveAllocationBehavior = (

    serviceType,

    submittedBehavior

) => {

    const serviceTypeBehavior =
        normalizeAllocationBehavior(
            serviceType?.allocationBehavior
        );


    if (
        serviceTypeBehavior
    ) {

        return serviceTypeBehavior;

    }


    const fallbackBehavior =
        normalizeAllocationBehavior(
            submittedBehavior
        );


    if (
        fallbackBehavior
    ) {

        return fallbackBehavior;

    }


    return "CONSUMPTION";

};


// ======================================================
// VALIDATE DONOR
// ======================================================

const validateDonorReference = async (

    donorId,

    organizationId,

    fieldName = "Donor"

) => {

    if (
        !donorId
    ) {

        return null;

    }


    validateObjectId(

        donorId,

        fieldName

    );


    const donor =
        await Donor.findOne({

            _id:
                donorId,

            organization:
                organizationId,

            isDeleted:
                false

        });


    if (!donor) {

        throw new Error(
            `${fieldName} not found in this organization.`
        );

    }


    return donor;

};


// ======================================================
// VALIDATE DONATION
// ======================================================

const validateDonationReference = async (

    donationId,

    organizationId,

    program,

    project,

    activityRun,

    fieldName = "Donation"

) => {

    if (
        !donationId
    ) {

        return null;

    }


    validateObjectId(

        donationId,

        fieldName

    );


    const donation =
        await Donation.findOne({

            _id:
                donationId,

            organization:
                organizationId,

            isDeleted:
                false

        });


    if (!donation) {

        throw new Error(
            `${fieldName} not found in this organization.`
        );

    }


    if (

        program &&
        donation.program &&
        String(
            donation.program
        ) !==
        String(
            program._id
        )

    ) {

        throw new Error(
            `${fieldName} does not belong to the selected program.`
        );

    }


    if (

        project &&
        donation.project &&
        String(
            donation.project
        ) !==
        String(
            project._id
        )

    ) {

        throw new Error(
            `${fieldName} does not belong to the selected project.`
        );

    }


    if (

        activityRun &&
        donation.activityRun &&
        String(
            donation.activityRun
        ) !==
        String(
            activityRun._id
        )

    ) {

        throw new Error(
            `${fieldName} does not belong to the selected activity run.`
        );

    }


    return donation;

};


// ======================================================
// VALIDATE DETAIL ITEMS
// ======================================================

const validateDetailItems = async (

    detailItems,

    organizationId,

    parentItemIndex

) => {

    if (
        detailItems === undefined ||
        detailItems === null
    ) {

        return;

    }


    if (
        !Array.isArray(
            detailItems
        )
    ) {

        throw new Error(
            `Service item ${parentItemIndex + 1} detail items must be an array.`
        );

    }


    const seenDetailItemIds =
        new Set();


    for (
        let detailIndex = 0;
        detailIndex < detailItems.length;
        detailIndex += 1
    ) {

        const detailItem =
            detailItems[
                detailIndex
            ];


        if (
            !detailItem ||
            typeof detailItem !== "object"
        ) {

            throw new Error(
                `Detail item ${detailIndex + 1} in service item ${parentItemIndex + 1} is invalid.`
            );

        }


        if (
            detailItem._id
        ) {

            validateObjectId(

                detailItem._id,

                `Detail item ${detailIndex + 1} ID`

            );


            const detailItemId =
                String(
                    detailItem._id
                );


            if (
                seenDetailItemIds.has(
                    detailItemId
                )
            ) {

                throw new Error(
                    `Duplicate detail item ID found in service item ${parentItemIndex + 1}.`
                );

            }


            seenDetailItemIds.add(
                detailItemId
            );

        }


        if (

            detailItem.name !== undefined &&
            detailItem.name !== null &&
            typeof detailItem.name !== "string"

        ) {

            throw new Error(
                `Detail item ${detailIndex + 1} name must be text.`
            );

        }


        if (

            typeof detailItem.name === "string" &&
            detailItem.name.length > 255

        ) {

            throw new Error(
                `Detail item ${detailIndex + 1} name cannot exceed 255 characters.`
            );

        }


        const quantity =
            Number(
                detailItem.quantity
            );


        if (

            !Number.isFinite(quantity) ||
            !Number.isInteger(quantity) ||
            quantity < 1

        ) {

            throw new Error(
                `Detail item ${detailIndex + 1} quantity must be a whole number of at least 1.`
            );

        }


        if (
            detailItem.unit
        ) {

            await validateServiceDeliveryLookup(

                detailItem.unit,

                organizationId,

                "Unit",

                `Detail item ${detailIndex + 1} unit`

            );

        }


        const unitCost =
            Number(
                detailItem.unitCost
            );


        if (

            !Number.isFinite(unitCost) ||
            unitCost < 0

        ) {

            throw new Error(
                `Detail item ${detailIndex + 1} unit cost cannot be negative.`
            );

        }

    }

};


// ======================================================
// VALIDATE SERVICE DELIVERY ITEM
// ======================================================

const validateServiceDeliveryItem = async (

    item,

    organizationId,

    program,

    project,

    activityRun,

    itemIndex,

    seenServiceItemIds

) => {

    if (
        !item ||
        typeof item !== "object"
    ) {

        throw new Error(
            `Service item ${itemIndex + 1} is invalid.`
        );

    }


    if (
        item._id
    ) {

        validateObjectId(

            item._id,

            `Service item ${itemIndex + 1} ID`

        );


        const serviceItemId =
            String(
                item._id
            );


        if (
            seenServiceItemIds.has(
                serviceItemId
            )
        ) {

            throw new Error(
                "Duplicate service item IDs are not allowed in the same service delivery."
            );

        }


        seenServiceItemIds.add(
            serviceItemId
        );

    }


    if (
        !item.serviceCategory
    ) {

        throw new Error(
            "Service category is required."
        );

    }


    const category =
        await validateServiceDeliveryLookup(

            item.serviceCategory,

            organizationId,

            "ServiceCategory",

            "Service category"

        );


    if (
        !item.serviceType
    ) {

        throw new Error(
            "Service type is required."
        );

    }


    const serviceType =
        await validateServiceDeliveryLookup(

            item.serviceType,

            organizationId,

            "ServiceType",

            "Service type"

        );


    validateServiceTypeParent(

        serviceType,

        category._id

    );


    // --------------------------------------------------
    // Resolve authoritative allocation behavior
    // --------------------------------------------------

    const allocationBehavior =
        resolveAllocationBehavior(

            serviceType,

            item.allocationBehavior

        );


    if (
        !allocationBehavior
    ) {

        throw new Error(
            `Service item ${itemIndex + 1} has an invalid allocation behavior.`
        );

    }


    if (
        !item.unit
    ) {

        throw new Error(
            "Unit is required."
        );

    }


    const unit =
        await validateServiceDeliveryLookup(

            item.unit,

            organizationId,

            "Unit",

            "Unit"

        );


    const semanticType =
        normalizeSemanticType(
            unit.semanticType
        );


    if (
        !semanticType
    ) {

        throw new Error(
            `Unit for service item ${itemIndex + 1} must define a valid semantic type.`
        );

    }


    const quantity =
        Number(
            item.quantity
        );


    if (

        !Number.isFinite(quantity) ||
        !Number.isInteger(quantity) ||
        quantity < 1

    ) {

        throw new Error(
            "Service item quantity must be a whole number of at least 1."
        );

    }


    const unitCost =
        Number(
            item.unitCost
        );


    if (

        !Number.isFinite(unitCost) ||
        unitCost < 0

    ) {

        throw new Error(
            "Service item unit cost cannot be negative."
        );

    }


    if (
        item.donor
    ) {

        await validateDonorReference(

            item.donor,

            organizationId,

            `Service item ${itemIndex + 1} donor`

        );

    }


    if (
        item.donation
    ) {

        await validateDonationReference(

            item.donation,

            organizationId,

            program,

            project,

            activityRun,

            `Service item ${itemIndex + 1} donation`

        );

    }


    await validateDetailItems(

        item.detailItems,

        organizationId,

        itemIndex

    );


    if (

        item.remarks !== undefined &&
        item.remarks !== null &&
        typeof item.remarks !== "string"

    ) {

        throw new Error(
            `Service item ${itemIndex + 1} remarks must be text.`
        );

    }


    // --------------------------------------------------
    // Return resolved values.
    //
    // FIX:
    // Previously "unit" was returned without being
    // declared, causing a potential ReferenceError.
    // --------------------------------------------------

    return {

        serviceType,

        unit,

        allocationBehavior,

        semanticType

    };

};


// ======================================================
// VALIDATE BENEFICIARY ALLOCATIONS
// ======================================================

const validateBeneficiaryAllocationsAgainstServiceItems =
    async (

        beneficiaryRecords,

        items,

        organizationId

    ) => {

        if (

            !Array.isArray(beneficiaryRecords) ||
            beneficiaryRecords.length === 0

        ) {

            return;

        }


        if (

            !Array.isArray(items) ||
            items.length === 0

        ) {

            return;

        }


        const serviceItemMap =
            new Map();


        const serviceTypeIds =
            new Set();


        const unitIds =
            new Set();


        // ------------------------------------------------
        // Build service item map
        // ------------------------------------------------

        for (
            const item
            of items
        ) {

            if (
                !item
            ) {

                continue;

            }


            if (
                !item._id
            ) {

                continue;

            }


            const serviceItemId =
                String(
                    item._id
                );


            serviceItemMap.set(

                serviceItemId,

                item

            );


            if (
                item.serviceType
            ) {

                serviceTypeIds.add(

                    String(
                        item.serviceType
                    )

                );

            }


            if (
                item.unit
            ) {

                unitIds.add(

                    String(
                        item.unit
                    )

                );

            }


            if (
                Array.isArray(
                    item.detailItems
                )
            ) {

                for (
                    const detailItem
                    of item.detailItems
                ) {

                    if (
                        detailItem &&
                        detailItem.unit
                    ) {

                        unitIds.add(

                            String(
                                detailItem.unit
                            )

                        );

                    }

                }

            }

        }


        // ------------------------------------------------
        // Load Service Types
        // ------------------------------------------------

        const serviceTypeLookupIds =
            Array.from(
                serviceTypeIds
            );


        let serviceTypes = [];


        if (
            serviceTypeLookupIds.length > 0
        ) {

            serviceTypes =
                await Lookup.find({

                    _id: {

                        $in:
                            serviceTypeLookupIds

                    },

                    organization:
                        organizationId,

                    module:
                        "ServiceDelivery",

                    category:
                        "ServiceType",

                    active:
                        true

                })
                .lean();

        }


        const serviceTypeMap =
            new Map();


        for (
            const serviceType
            of serviceTypes
        ) {

            serviceTypeMap.set(

                String(
                    serviceType._id
                ),

                serviceType

            );

        }


        // ------------------------------------------------
        // Load Units
        // ------------------------------------------------

        const unitLookupIds =
            Array.from(
                unitIds
            );


        let units = [];


        if (
            unitLookupIds.length > 0
        ) {

            units =
                await Lookup.find({

                    _id: {

                        $in:
                            unitLookupIds

                    },

                    organization:
                        organizationId,

                    module:
                        "ServiceDelivery",

                    category:
                        "Unit",

                    active:
                        true

                })
                .lean();

        }


        const unitMap =
            new Map();


        for (
            const unit
            of units
        ) {

            unitMap.set(

                String(
                    unit._id
                ),

                unit

            );

        }


        // ------------------------------------------------
        // Consumption totals
        // ------------------------------------------------

        const consumptionParentTotals =
            new Map();


        const consumptionDetailTotals =
            new Map();


        // ------------------------------------------------
        // Validate every allocation
        // ------------------------------------------------

        for (
            const record
            of beneficiaryRecords
        ) {

            if (
                !Array.isArray(
                    record.allocations
                )
            ) {

                continue;

            }


            for (
                const allocation
                of record.allocations
            ) {

                if (
                    !allocation ||
                    !allocation.serviceItem
                ) {

                    continue;

                }


                const serviceItemId =
                    String(
                        allocation.serviceItem
                    );


                const item =
                    serviceItemMap.get(
                        serviceItemId
                    );


                if (!item) {

                    throw new Error(
                        "One or more beneficiary allocations reference a service item that is not part of this service delivery."
                    );

                }


                // ------------------------------------------------
                // Detail item
                // ------------------------------------------------

                let detailItem =
                    null;


                let detailItemId =
                    null;


                if (
                    allocation.detailItem
                ) {

                    detailItemId =
                        String(
                            allocation.detailItem
                        );


                    const detailItems =
                        Array.isArray(
                            item.detailItems
                        )
                            ? item.detailItems
                            : [];


                    detailItem =
                        detailItems.find(

                            detail =>
                                detail &&
                                String(
                                    detail._id
                                ) ===
                                detailItemId

                        );


                    if (!detailItem) {

                        throw new Error(
                            `Allocated detail item ${detailItemId} does not belong to service item ${serviceItemId}.`
                        );

                    }

                }


                // ------------------------------------------------
                // Service type
                // ------------------------------------------------

                const serviceType =
                    serviceTypeMap.get(

                        String(
                            item.serviceType
                        )

                    );


                if (!serviceType) {

                    throw new Error(
                        `Service type for service item ${serviceItemId} could not be resolved.`
                    );

                }


                // ------------------------------------------------
                // ServiceType is authoritative
                // ------------------------------------------------

                const allocationBehavior =
                    resolveAllocationBehavior(

                        serviceType,

                        item.allocationBehavior

                    );


                // ------------------------------------------------
                // Effective unit
                // ------------------------------------------------

                const effectiveUnitId =
                    detailItem
                        ? detailItem.unit
                        : item.unit;


                const effectiveUnit =
                    effectiveUnitId
                        ? unitMap.get(
                            String(
                                effectiveUnitId
                            )
                        )
                        : null;


                if (
                    !effectiveUnit
                ) {

                    throw new Error(
                        `Unit for beneficiary allocation on service item ${serviceItemId} could not be resolved.`
                    );

                }


                const semanticType =
                    normalizeSemanticType(
                        effectiveUnit.semanticType
                    );


                if (
                    !semanticType
                ) {

                    throw new Error(
                        `Unit for beneficiary allocation on service item ${serviceItemId} has an invalid semantic type.`
                    );

                }


                const quantity =
                    Number(
                        allocation.quantity ?? 0
                    );


                const allocatedValue =
                    Number(
                        allocation.allocatedValue ?? 0
                    );


                if (

                    !Number.isFinite(quantity) ||
                    quantity < 0

                ) {

                    throw new Error(
                        "Beneficiary allocation quantity must be zero or greater."
                    );

                }


                if (

                    !Number.isFinite(allocatedValue) ||
                    allocatedValue < 0

                ) {

                    throw new Error(
                        "Beneficiary allocated value must be zero or greater."
                    );

                }


                // =================================================
                // MONETARY
                // =================================================

                if (
                    semanticType ===
                    "monetary"
                ) {

                    if (
                        quantity !== 0
                    ) {

                        throw new Error(
                            `Monetary beneficiary allocation for service item ${serviceItemId} must use quantity 0 and allocated value instead.`
                        );

                    }


                    if (
                        allocatedValue <= 0
                    ) {

                        throw new Error(
                            `Monetary beneficiary allocation for service item ${serviceItemId} must have an allocated value greater than zero.`
                        );

                    }


                    continue;

                }


                // =================================================
                // PHYSICAL
                // =================================================

                if (
                    semanticType !==
                    "physical"
                ) {

                    throw new Error(
                        `Unsupported unit semantic type for service item ${serviceItemId}.`
                    );

                }


                // ------------------------------------------------
                // Detail allocation
                // ------------------------------------------------

                if (
                    detailItem
                ) {

                    const availableQuantity =
                        Number(
                            detailItem.quantity
                        );


                    if (
                        !Number.isFinite(
                            availableQuantity
                        )
                    ) {

                        throw new Error(
                            `Detail item ${detailItemId} has an invalid quantity.`
                        );

                    }


                    // --------------------------------------------
                    // Participation
                    // --------------------------------------------

                    if (
                        allocationBehavior ===
                        "PARTICIPATION"
                    ) {

                        if (
                            quantity >
                            availableQuantity
                        ) {

                            throw new Error(
                                `Beneficiary allocation quantity for detail item ${detailItem.name || detailItemId} cannot exceed the actual detail item quantity.`
                            );

                        }


                        continue;

                    }


                    // --------------------------------------------
                    // Consumption
                    // --------------------------------------------

                    const key =
                        `${serviceItemId}:${detailItemId}`;


                    const currentTotal =
                        consumptionDetailTotals.get(
                            key
                        ) ||
                        0;


                    consumptionDetailTotals.set(

                        key,

                        currentTotal +
                        quantity

                    );


                    continue;

                }


                // =================================================
                // DIRECT PARENT ALLOCATION
                // =================================================

                const deliveredQuantity =
                    Number(
                        item.quantity
                    );


                if (
                    !Number.isFinite(
                        deliveredQuantity
                    )
                ) {

                    throw new Error(
                        `Service item ${serviceItemId} has an invalid quantity.`
                    );

                }


                // ------------------------------------------------
                // Participation
                // ------------------------------------------------

                if (
                    allocationBehavior ===
                    "PARTICIPATION"
                ) {

                    if (
                        quantity >
                        deliveredQuantity
                    ) {

                        throw new Error(
                            `Beneficiary allocation quantity for service item ${serviceItemId} cannot exceed the actual service item quantity for an individual beneficiary.`
                        );

                    }


                    continue;

                }


                // ------------------------------------------------
                // Consumption
                // ------------------------------------------------

                const currentTotal =
                    consumptionParentTotals.get(
                        serviceItemId
                    ) ||
                    0;


                consumptionParentTotals.set(

                    serviceItemId,

                    currentTotal +
                    quantity

                );

            }

        }


        // ======================================================
        // VALIDATE PARENT CONSUMPTION TOTALS
        // ======================================================

        for (
            const [
                serviceItemId,
                totalAllocatedQuantity
            ]
            of consumptionParentTotals
        ) {

            const item =
                serviceItemMap.get(
                    serviceItemId
                );


            if (!item) {

                continue;

            }


            const deliveredQuantity =
                Number(
                    item.quantity
                );


            if (
                totalAllocatedQuantity >
                deliveredQuantity
            ) {

                throw new Error(
                    "Total beneficiary allocation quantity cannot exceed the actual service item quantity."
                );

            }

        }


        // ======================================================
        // VALIDATE DETAIL CONSUMPTION TOTALS
        // ======================================================

        for (
            const [
                key,
                totalAllocatedQuantity
            ]
            of consumptionDetailTotals
        ) {

            const [
                serviceItemId,
                detailItemId
            ] =
                key.split(":");


            const item =
                serviceItemMap.get(
                    serviceItemId
                );


            if (!item) {

                continue;

            }


            const detailItems =
                Array.isArray(
                    item.detailItems
                )
                    ? item.detailItems
                    : [];


            const detailItem =
                detailItems.find(

                    detail =>
                        detail &&
                        String(
                            detail._id
                        ) ===
                        detailItemId

                );


            if (!detailItem) {

                continue;

            }


            const availableQuantity =
                Number(
                    detailItem.quantity
                );


            if (
                totalAllocatedQuantity >
                availableQuantity
            ) {

                throw new Error(
                    `Total beneficiary allocation quantity for detail item ${detailItem.name || detailItemId} cannot exceed the actual detail item quantity.`
                );

            }

        }

    };


// ======================================================
// VALIDATE SERVICE DELIVERY REFERENCES
// ======================================================

const validateServiceDeliveryReferences = async (

    data,

    organizationId

) => {

    if (!organizationId) {

        throw new Error(
            "Organization ID is required."
        );

    }


    // ==================================================
    // BENEFICIARIES
    // ==================================================

    const beneficiaryRecords =
        normalizeBeneficiaries(
            data
        );


    validateBeneficiaryRecords(
        beneficiaryRecords
    );


    const beneficiaryIds = [

        ...new Set(

            beneficiaryRecords
                .map(
                    record =>
                        String(
                            record.beneficiary
                        )
                )

        )

    ];


    let beneficiaries = [];


    if (
        beneficiaryIds.length > 0
    ) {

        beneficiaries =
            await Beneficiary.find({

                _id: {

                    $in:
                        beneficiaryIds

                },

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        if (
            beneficiaries.length !==
            beneficiaryIds.length
        ) {

            throw new Error(
                "One or more selected beneficiaries were not found in this organization."
            );

        }

    }


    const beneficiary =
        beneficiaries.length === 1
            ? beneficiaries[0]
            : null;


    // ==================================================
    // PROGRAM
    // ==================================================

    let program = null;


    if (
        data.program
    ) {

        validateObjectId(

            data.program,

            "Program"

        );


        program =
            await Program.findOne({

                _id:
                    data.program,

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        if (!program) {

            throw new Error(
                "Program not found in this organization."
            );

        }

    }


    // ==================================================
    // PROJECT
    // ==================================================

    let project = null;


    if (
        data.project
    ) {

        validateObjectId(

            data.project,

            "Project"

        );


        project =
            await Project.findOne({

                _id:
                    data.project,

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        if (!project) {

            throw new Error(
                "Project not found in this organization."
            );

        }


        if (

            program &&
            project.program &&
            String(
                project.program
            ) !==
            String(
                program._id
            )

        ) {

            throw new Error(
                "Selected project does not belong to the selected program."
            );

        }

    }


    // ==================================================
    // TOP LEVEL ENROLLMENT
    // ==================================================

    let enrollment = null;


    if (
        data.enrollment
    ) {

        validateObjectId(

            data.enrollment,

            "Enrollment"

        );


        enrollment =
            await Enrollment.findOne({

                _id:
                    data.enrollment,

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        if (!enrollment) {

            throw new Error(
                "Enrollment not found in this organization."
            );

        }


        if (

            beneficiary &&
            enrollment.beneficiary &&
            String(
                enrollment.beneficiary
            ) !==
            String(
                beneficiary._id
            )

        ) {

            throw new Error(
                "Selected enrollment does not belong to the selected beneficiary."
            );

        }


        if (

            program &&
            enrollment.program &&
            String(
                enrollment.program
            ) !==
            String(
                program._id
            )

        ) {

            throw new Error(
                "Selected enrollment does not belong to the selected program."
            );

        }

    }


    // ==================================================
    // BENEFICIARY-SPECIFIC ENROLLMENTS
    // ==================================================

    for (
        const record
        of beneficiaryRecords
    ) {

        if (
            !record.enrollment
        ) {

            continue;

        }


        validateObjectId(

            record.enrollment,

            "Beneficiary enrollment"

        );


        const beneficiaryEnrollment =
            await Enrollment.findOne({

                _id:
                    record.enrollment,

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        if (!beneficiaryEnrollment) {

            throw new Error(
                "One or more beneficiary enrollments were not found in this organization."
            );

        }


        if (

            beneficiaryEnrollment.beneficiary &&
            String(
                beneficiaryEnrollment.beneficiary
            ) !==
            String(
                record.beneficiary
            )

        ) {

            throw new Error(
                "A beneficiary-specific enrollment does not belong to its selected beneficiary."
            );

        }


        if (

            program &&
            beneficiaryEnrollment.program &&
            String(
                beneficiaryEnrollment.program
            ) !==
            String(
                program._id
            )

        ) {

            throw new Error(
                "A beneficiary-specific enrollment does not belong to the selected program."
            );

        }

    }


    // ==================================================
    // ACTIVITY
    // ==================================================

    let activity = null;


    if (
        data.activity
    ) {

        validateObjectId(

            data.activity,

            "Activity"

        );


        activity =
            await Activity.findOne({

                _id:
                    data.activity,

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        if (!activity) {

            throw new Error(
                "Activity not found in this organization."
            );

        }


        if (

            project &&
            activity.project &&
            String(
                activity.project
            ) !==
            String(
                project._id
            )

        ) {

            throw new Error(
                "Selected activity does not belong to the selected project."
            );

        }

    }


    // ==================================================
    // ACTIVITY RUN
    // ==================================================

    let activityRun = null;


    if (
        data.activityRun
    ) {

        validateObjectId(

            data.activityRun,

            "Activity run"

        );


        activityRun =
            await ActivityRun.findOne({

                _id:
                    data.activityRun,

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        if (!activityRun) {

            throw new Error(
                "Activity run not found in this organization."
            );

        }


        if (

            activity &&
            activityRun.activity &&
            String(
                activityRun.activity
            ) !==
            String(
                activity._id
            )

        ) {

            throw new Error(
                "Selected activity run does not belong to the selected activity."
            );

        }


        if (

            project &&
            activityRun.project &&
            String(
                activityRun.project
            ) !==
            String(
                project._id
            )

        ) {

            throw new Error(
                "Selected activity run does not belong to the selected project."
            );

        }


        if (

            program &&
            activityRun.program &&
            String(
                activityRun.program
            ) !==
            String(
                program._id
            )

        ) {

            throw new Error(
                "Selected activity run does not belong to the selected program."
            );

        }

    }


    // ==================================================
    // TOP LEVEL DONATION
    // ==================================================

    let donation = null;


    if (
        data.donation
    ) {

        donation =
            await validateDonationReference(

                data.donation,

                organizationId,

                program,

                project,

                activityRun,

                "Donation"

            );

    }


    // ==================================================
    // SERVICE ITEMS
    // ==================================================

    const serviceItems =
        Array.isArray(
            data.items
        )
            ? data.items
            : [];


    if (
        serviceItems.length > 0
    ) {

        const seenServiceItemIds =
            new Set();


        const validatedItems = [];


        for (
            let itemIndex = 0;
            itemIndex < serviceItems.length;
            itemIndex += 1
        ) {

            const item =
                serviceItems[
                    itemIndex
                ];


            const validatedItem =
                await validateServiceDeliveryItem(

                    item,

                    organizationId,

                    program,

                    project,

                    activityRun,

                    itemIndex,

                    seenServiceItemIds

                );


            validatedItems.push({

                ...item,

                allocationBehavior:
                    validatedItem.allocationBehavior

            });

        }


        // ------------------------------------------------
        // Use the resolved service-item behavior during
        // allocation validation.
        // ------------------------------------------------

        await validateBeneficiaryAllocationsAgainstServiceItems(

            beneficiaryRecords,

            validatedItems,

            organizationId

        );

    }


    // ==================================================
    // RETURN
    // ==================================================

    return {

        beneficiaries,

        beneficiaryRecords,

        beneficiary,

        enrollment,

        program,

        project,

        activity,

        activityRun,

        donation

    };

};


// ======================================================
// EXPORT
// ======================================================

module.exports = {

    validateServiceDeliveryReferences

};