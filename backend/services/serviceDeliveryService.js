const mongoose =
    require("mongoose");

const ServiceDelivery =
    require("../models/ServiceDelivery");

const ServiceDeliveryBeneficiary =
    require("../models/ServiceDeliveryBeneficiary");

const Beneficiary =
    require("../models/Beneficiary");

const Enrollment =
    require("../models/enrollment");

const Program =
    require("../models/program");

const Project =
    require("../models/Project");

const Activity =
    require("../models/Activity");

const ActivityRun =
    require("../models/ActivityRun");

const Donation =
    require("../models/donation");

const Lookup =
    require("../models/Lookup");

const generateSequence =
    require("../utils/generateSequence");

const {
    getUnitSemantics
} =
    require("../config/serviceDeliveryUnits");

const {
    SERVICE_DELIVERY_STATUS,
    DEFAULT_SERVICE_DELIVERY_STATUS
} = require("../constants/serviceDeliveryStatus");

const {
    runInTransaction
} = require("../utils/transaction");


// ======================================================
// DUPLICATE KEY ERRORS
// ======================================================
//
// Turns MongoDB duplicate key errors (11000) from a
// delivery save into readable messages.
//
// ======================================================

const toDuplicateKeyError = (error) => {

    if (error?.code !== 11000) {
        return error;
    }

    if (error.keyPattern?.deliveryNumber) {
        return new Error(
            "Service delivery number already exists."
        );
    }

    if (error.keyPattern?.beneficiary) {
        return new Error(
            "A beneficiary is listed more than once in this service delivery."
        );
    }

    return new Error(
        "This service delivery conflicts with an existing record."
    );

};


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
// CHECK OBJECT ID
// ======================================================

const isObjectIdLike = (
    value
) => {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {
        return false;
    }

    return mongoose.Types.ObjectId.isValid(
        value
    );

};


// ======================================================
// NORMALIZE OBJECT ID
// ======================================================

const normalizeObjectId = (
    value
) => {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {
        return null;
    }

    if (
        typeof value === "object"
    ) {

        if (
            value._id
        ) {
            return String(
                value._id
            );
        }

        if (
            value.id
        ) {
            return String(
                value.id
            );
        }

        if (
            value.value &&
            typeof value.value !== "object"
        ) {
            return String(
                value.value
            );
        }

    }

    return String(
        value
    );

};


// ======================================================
// NORMALIZE NUMBER
// ======================================================

const normalizeNumber = (
    value,
    defaultValue = 0
) => {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {
        return defaultValue;
    }

    const number =
        Number(
            value
        );

    return Number.isFinite(
        number
    )
        ? number
        : defaultValue;

};


// ======================================================
// NORMALIZE RECIPIENT NAME
// ======================================================

const normalizeRecipientName = (
    value
) => {

    if (
        value === undefined ||
        value === null
    ) {
        return "";
    }

    return String(
        value
    ).trim();

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
// RESOLVE ALLOCATION BEHAVIOR
// ======================================================

const resolveAllocationBehavior = (
    item,
    serviceType
) => {

    const itemBehavior =
        normalizeAllocationBehavior(
            item?.allocationBehavior
        );

    if (
        itemBehavior
    ) {
        return itemBehavior;
    }

    const serviceTypeBehavior =
        normalizeAllocationBehavior(
            serviceType?.allocationBehavior
        );

    if (
        serviceTypeBehavior
    ) {
        return serviceTypeBehavior;
    }

    return "CONSUMPTION";

};


// ======================================================
// RESOLVE UNIT SEMANTICS
// ======================================================

const resolveUnitSemantics = (
    unit
) => {

    if (
        !unit
    ) {
        return "unknown";
    }

    const semanticType =
        String(
            unit.semanticType ||
            ""
        )
            .trim()
            .toLowerCase();

    if (
        semanticType ===
        "monetary"
    ) {
        return "monetary";
    }

    if (
        semanticType ===
        "physical"
    ) {
        return "physical";
    }

    const candidates = [

        unit.code,
        unit.unitCode,
        unit.lookupCode,
        unit.value,
        unit.name,
        unit.label

    ];

    for (
        const candidate
        of candidates
    ) {

        if (
            !candidate ||
            typeof candidate ===
            "object"
        ) {
            continue;
        }

        const fallback =
            getUnitSemantics(
                String(
                    candidate
                )
            );

        if (
            fallback ===
            "monetary" ||
            fallback ===
            "physical"
        ) {
            return fallback;
        }

    }

    return "unknown";

};


// ======================================================
// NORMALIZE DETAIL ITEMS
// ======================================================

const normalizeDetailItems = (
    detailItems
) => {

    if (
        detailItems === undefined ||
        detailItems === null
    ) {
        return [];
    }

    if (
        !Array.isArray(
            detailItems
        )
    ) {
        throw new Error(
            "Detail items must be an array."
        );
    }

    return detailItems.map(
        (
            detailItem
        ) => {

            if (
                !detailItem ||
                typeof detailItem !==
                "object"
            ) {
                throw new Error(
                    "Each detail item must be a valid object."
                );
            }

            const incomingId =
                normalizeObjectId(
                    detailItem._id
                );

            let detailItemId = null;

            if (
                incomingId &&
                isObjectIdLike(
                    incomingId
                )
            ) {

                detailItemId =
                    incomingId;

            }

            else if (
                incomingId
            ) {

                throw new Error(
                    "Detail item ID is invalid."
                );

            }

            else {

                detailItemId =
                    new mongoose.Types.ObjectId()
                        .toString();

            }

            const quantity =
                normalizeNumber(
                    detailItem.quantity,
                    1
                );

            const unitCost =
                normalizeNumber(
                    detailItem.unitCost,
                    0
                );

            const allocationConversionFactor =
                normalizeNumber(
                    detailItem.allocationConversionFactor,
                    1
                );

            if (
                quantity < 1
            ) {
                throw new Error(
                    "Detail item quantity must be at least 1."
                );
            }

            if (
                unitCost < 0
            ) {
                throw new Error(
                    "Detail item unit cost cannot be negative."
                );
            }

            if (
                allocationConversionFactor <= 0
            ) {
                throw new Error(
                    "Detail item allocation conversion factor must be greater than 0."
                );
            }

            return {

                _id:
                    new mongoose.Types.ObjectId(
                        detailItemId
                    ),

                name:
                    typeof detailItem.name ===
                        "string"
                        ? detailItem.name.trim()
                        : "",

                quantity,

                unit:
                    normalizeObjectId(
                        detailItem.unit
                    ),

                allocationUnit:
                    normalizeObjectId(
                        detailItem.allocationUnit
                    ),

                allocationConversionFactor,

                unitCost,

                totalCost:
                    quantity *
                    unitCost

            };

        }
    );

};


// ======================================================
// CALCULATE SERVICE ITEMS
// ======================================================

const calculateItems = (
    items
) => {

    if (
        !Array.isArray(
            items
        )
    ) {
        return [];
    }

    return items.map(
        (
            item
        ) => {

            const incomingId =
                normalizeObjectId(
                    item?._id
                );

            let itemId = null;

            if (
                incomingId &&
                isObjectIdLike(
                    incomingId
                )
            ) {

                itemId =
                    incomingId;

            }

            else if (
                incomingId
            ) {

                throw new Error(
                    "Service item ID is invalid."
                );

            }

            else {

                itemId =
                    new mongoose.Types.ObjectId()
                        .toString();

            }

            const quantity =
                normalizeNumber(
                    item?.quantity,
                    0
                );

            const unitCost =
                normalizeNumber(
                    item?.unitCost,
                    0
                );

            return {

                _id:
                    new mongoose.Types.ObjectId(
                        itemId
                    ),

                serviceCategory:
                    normalizeObjectId(
                        item?.serviceCategory
                    ),

                serviceType:
                    normalizeObjectId(
                        item?.serviceType
                    ),

                allocationBehavior:
                    normalizeAllocationBehavior(
                        item?.allocationBehavior
                    ) ||
                    "CONSUMPTION",

                quantity,

                unit:
                    normalizeObjectId(
                        item?.unit
                    ),

                unitCost,

                totalCost:
                    quantity *
                    unitCost,

                donor:
                    normalizeObjectId(
                        item?.donor
                    ),

                donation:
                    normalizeObjectId(
                        item?.donation
                    ),

                detailItems:
                    normalizeDetailItems(
                        item?.detailItems
                    ),

                remarks:
                    typeof item?.remarks ===
                        "string"
                        ? item.remarks.trim()
                        : ""

            };

        }
    );

};


// ======================================================
// NORMALIZE ALLOCATION
// ======================================================

const normalizeAllocation = (
    allocation,
    unitSemantics = null
) => {

    if (
        !allocation ||
        typeof allocation !==
        "object"
    ) {
        return null;
    }

    const serviceItem =
        normalizeObjectId(
            allocation.serviceItem
        );

    if (
        !serviceItem
    ) {
        return null;
    }

    const detailItem =
        normalizeObjectId(
            allocation.detailItem
        );

    let quantity =
        normalizeNumber(
            allocation.quantity,
            0
        );

    const allocatedValue =
        normalizeNumber(
            allocation.allocatedValue,
            0
        );

    if (
        unitSemantics ===
        "monetary"
    ) {
        quantity = 0;
    }

    return {

        serviceItem,

        detailItem,

        quantity,

        allocatedValue,

        remarks:
            typeof allocation.remarks ===
                "string"
                ? allocation.remarks.trim()
                : ""

    };

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
            data?.beneficiaries
        )
    ) {

        records =
            data.beneficiaries;

    }

    else if (
        data?.beneficiary
    ) {

        records = [
            data.beneficiary
        ];

    }

    return records
        .filter(Boolean)
        .map(
            (
                record
            ) => {

                if (
                    typeof record ===
                    "string"
                ) {

                    return {

                        beneficiary:
                            normalizeObjectId(
                                record
                            ),

                        enrollment:
                            null,

                        status:
                            "Received",

                        quantity:
                            null,

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

                    const allocations =
                        Array.isArray(
                            record.allocations
                        )
                            ? record.allocations
                                .map(
                                    allocation =>
                                        normalizeAllocation(
                                            allocation
                                        )
                                )
                                .filter(Boolean)
                            : [];

                    return {

                        beneficiary:
                            normalizeObjectId(
                                record.beneficiary ||
                                record._id
                            ),

                        enrollment:
                            normalizeObjectId(
                                record.enrollment
                            ),

                        status:
                            record.status ||
                            "Received",

                        quantity:
                            record.quantity !==
                                undefined &&
                            record.quantity !==
                                null
                                ? normalizeNumber(
                                    record.quantity,
                                    0
                                )
                                : null,

                        remarks:
                            typeof record.remarks ===
                                "string"
                                ? record.remarks.trim()
                                : "",

                        allocations

                    };

                }

                return {

                    beneficiary:
                        null,

                    enrollment:
                        null,

                    status:
                        "Received",

                    quantity:
                        null,

                    remarks:
                        "",

                    allocations:
                        []

                };

            }
        );

};


// ======================================================
// GET BENEFICIARY IDS
// ======================================================

const getBeneficiaryIds = (
    records
) => {

    if (
        !Array.isArray(
            records
        )
    ) {
        return [];
    }

    const ids =
        records
            .map(
                record =>
                    record?.beneficiary
            )
            .filter(Boolean)
            .map(
                id =>
                    String(id)
            );

    return Array.from(
        new Set(
            ids
        )
    );

};


// ======================================================
// VALIDATE BENEFICIARIES
// ======================================================

const validateBeneficiaries = async (
    beneficiaryIds,
    organizationId
) => {

    if (
        !Array.isArray(
            beneficiaryIds
        ) ||
        beneficiaryIds.length === 0
    ) {
        return [];
    }

    beneficiaryIds.forEach(
        (
            beneficiaryId
        ) => {

            validateObjectId(
                beneficiaryId,
                "Beneficiary"
            );

        }
    );

    const beneficiaries =
        await Beneficiary.find({

            _id: {
                $in:
                    beneficiaryIds
            },

            organization:
                organizationId,

            isDeleted:
                false

        }).select(
            "_id"
        );

    if (
        beneficiaries.length !==
        beneficiaryIds.length
    ) {
        throw new Error(
            "One or more selected beneficiaries were not found."
        );
    }

    return beneficiaries.map(
        beneficiary =>
            beneficiary._id
    );

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

        }).select(
            "_id module category parentLookup value name code lookupCode semanticType allocationBehavior active allowedUnits"
        );

    if (
        !lookup
    ) {
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
// VALIDATE DETAIL ITEMS
// ======================================================

const validateDetailItems = async (
    detailItems,
    organizationId
) => {

    if (
        !Array.isArray(
            detailItems
        )
    ) {
        throw new Error(
            "Detail items must be an array."
        );
    }

    const seenIds =
        new Set();

    for (
        const detailItem
        of detailItems
    ) {

        if (
            !detailItem?._id
        ) {
            throw new Error(
                "Every detail item must have an ID."
            );
        }

        const detailItemId =
            String(
                detailItem._id
            );

        validateObjectId(
            detailItemId,
            "Detail item ID"
        );

        if (
            seenIds.has(
                detailItemId
            )
        ) {
            throw new Error(
                "Duplicate detail item IDs are not allowed."
            );
        }

        seenIds.add(
            detailItemId
        );

        if (
            typeof detailItem.name !==
            "string"
        ) {
            throw new Error(
                "Detail item name must be text."
            );
        }

        const quantity =
            Number(
                detailItem.quantity
            );

        if (
            !Number.isFinite(
                quantity
            ) ||
            quantity < 1
        ) {
            throw new Error(
                "Detail item quantity must be at least 1."
            );
        }

        const unitCost =
            Number(
                detailItem.unitCost
            );

        if (
            !Number.isFinite(
                unitCost
            ) ||
            unitCost < 0
        ) {
            throw new Error(
                "Detail item unit cost cannot be negative."
            );
        }

        const allocationConversionFactor =
            Number(
                detailItem.allocationConversionFactor ?? 1
            );

        if (
            !Number.isFinite(
                allocationConversionFactor
            ) ||
            allocationConversionFactor <= 0
        ) {
            throw new Error(
                "Detail item allocation conversion factor must be greater than 0."
            );
        }

        if (
            detailItem.unit
        ) {

            const unit =
                await validateServiceDeliveryLookup(
                    detailItem.unit,
                    organizationId,
                    "Unit",
                    "Detail item unit"
                );

            const semantics =
                resolveUnitSemantics(
                    unit
                );

            if (
                semantics ===
                "unknown"
            ) {
                throw new Error(
                    `Detail item unit '${unit.value || unit.name || unit.code}' does not have recognized service delivery allocation semantics.`
                );
            }

        }

        if (
            detailItem.allocationUnit
        ) {

            const allocationUnit =
                await validateServiceDeliveryLookup(
                    detailItem.allocationUnit,
                    organizationId,
                    "Unit",
                    "Detail item allocation unit"
                );

            const allocationSemantics =
                resolveUnitSemantics(
                    allocationUnit
                );

            if (
                allocationSemantics ===
                "unknown"
            ) {
                throw new Error(
                    `Detail item allocation unit '${allocationUnit.value || allocationUnit.name || allocationUnit.code}' does not have recognized service delivery allocation semantics.`
                );
            }

        }

    }

};


// ======================================================
// VALIDATE ITEM-LEVEL DONOR
// ======================================================

const validateItemDonor = async (
    donorId,
    organizationId
) => {

    if (
        !donorId
    ) {
        return;
    }

    validateObjectId(
        donorId,
        "Donor"
    );

    let Donor;

    try {

        Donor =
            mongoose.model(
                "Donor"
            );

    }
    catch (
        error
    ) {

        throw new Error(
            "Donor model is not registered."
        );

    }

    const donor =
        await Donor.findOne({

            _id:
                donorId,

            organization:
                organizationId,

            isDeleted:
                false

        }).select(
            "_id"
        );

    if (
        !donor
    ) {
        throw new Error(
            "Donor not found."
        );
    }

};


// ======================================================
// VALIDATE ITEM-LEVEL DONATION
// ======================================================

const validateItemDonation = async (
    donationId,
    organizationId
) => {

    if (
        !donationId
    ) {
        return;
    }

    validateObjectId(
        donationId,
        "Donation"
    );

    const donation =
        await Donation.findOne({

            _id:
                donationId,

            organization:
                organizationId,

            isDeleted:
                false

        }).select(
            "_id"
        );

    if (
        !donation
    ) {
        throw new Error(
            "Donation not found."
        );
    }

};


// ======================================================
// VALIDATE SERVICE ITEMS
// ======================================================

const validateServiceItems = async (
    items,
    organizationId
) => {

    if (
        !Array.isArray(
            items
        ) ||
        items.length === 0
    ) {
        throw new Error(
            "At least one service item is required."
        );
    }

    const seenIds =
        new Set();

    for (
        const item
        of items
    ) {

        if (
            !item._id
        ) {
            throw new Error(
                "Every service item must have an ID."
            );
        }

        const itemId =
            String(
                item._id
            );

        validateObjectId(
            itemId,
            "Service item ID"
        );

        if (
            seenIds.has(
                itemId
            )
        ) {
            throw new Error(
                "Duplicate service item IDs are not allowed."
            );
        }

        seenIds.add(
            itemId
        );

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

        const allocationBehavior =
            resolveAllocationBehavior(
                item,
                serviceType
            );

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

        const unitSemantics =
            resolveUnitSemantics(
                unit
            );

        if (
            unitSemantics ===
            "unknown"
        ) {
            throw new Error(
                `Unit '${unit.value || unit.name || unit.code}' does not have recognized service delivery allocation semantics.`
            );
        }

        const quantity =
            Number(
                item.quantity
            );

        if (
            !Number.isFinite(
                quantity
            ) ||
            quantity < 1
        ) {
            throw new Error(
                "Service item quantity must be at least 1."
            );
        }

        const unitCost =
            Number(
                item.unitCost
            );

        if (
            !Number.isFinite(
                unitCost
            ) ||
            unitCost < 0
        ) {
            throw new Error(
                "Service item unit cost cannot be negative."
            );
        }

        await validateDetailItems(
            Array.isArray(
                item.detailItems
            )
                ? item.detailItems
                : [],
            organizationId
        );

        await validateItemDonor(
            item.donor,
            organizationId
        );

        await validateItemDonation(
            item.donation,
            organizationId
        );

        item.allocationBehavior =
            allocationBehavior;

    }

};


// ======================================================
// VALIDATE REFERENCES
// ======================================================

const validateServiceDeliveryReferences = async (
    data,
    organizationId
) => {

    if (
        !organizationId
    ) {
        throw new Error(
            "Organization ID is required."
        );
    }

    const beneficiaryRecords =
        normalizeBeneficiaries(
            data
        );

    const beneficiaryIds =
        getBeneficiaryIds(
            beneficiaryRecords
        );

    const validatedBeneficiaries =
        await validateBeneficiaries(
            beneficiaryIds,
            organizationId
        );

    if (
        data.program
    ) {

        validateObjectId(
            data.program,
            "Program"
        );

        const program =
            await Program.findOne({

                _id:
                    data.program,

                organization:
                    organizationId,

                isDeleted:
                    false

            }).select(
                "_id"
            );

        if (
            !program
        ) {
            throw new Error(
                "Program not found."
            );
        }

    }

    if (
        data.project
    ) {

        validateObjectId(
            data.project,
            "Project"
        );

        const project =
            await Project.findOne({

                _id:
                    data.project,

                organization:
                    organizationId,

                isDeleted:
                    false

            }).select(
                "_id program"
            );

        if (
            !project
        ) {
            throw new Error(
                "Project not found."
            );
        }

        if (
            data.program &&
            project.program &&
            String(
                project.program
            ) !==
            String(
                data.program
            )
        ) {
            throw new Error(
                "Project does not belong to the selected program."
            );
        }

    }

    if (
        data.activity
    ) {

        validateObjectId(
            data.activity,
            "Activity"
        );

        const activity =
            await Activity.findOne({

                _id:
                    data.activity,

                organization:
                    organizationId,

                isDeleted:
                    false

            }).select(
                "_id project"
            );

        if (
            !activity
        ) {
            throw new Error(
                "Activity not found."
            );
        }

        if (
            data.project &&
            activity.project &&
            String(
                activity.project
            ) !==
            String(
                data.project
            )
        ) {
            throw new Error(
                "Activity does not belong to the selected project."
            );
        }

    }

    if (
        data.activityRun
    ) {

        validateObjectId(
            data.activityRun,
            "Activity run"
        );

        const activityRun =
            await ActivityRun.findOne({

                _id:
                    data.activityRun,

                organization:
                    organizationId,

                isDeleted:
                    false

            }).select(
                "_id activity project program"
            );

        if (
            !activityRun
        ) {
            throw new Error(
                "Activity run not found."
            );
        }

        if (
            data.activity &&
            activityRun.activity &&
            String(
                activityRun.activity
            ) !==
            String(
                data.activity
            )
        ) {
            throw new Error(
                "Activity run does not belong to the selected activity."
            );
        }

        if (
            data.project &&
            activityRun.project &&
            String(
                activityRun.project
            ) !==
            String(
                data.project
            )
        ) {
            throw new Error(
                "Activity run does not belong to the selected project."
            );
        }

        if (
            data.program &&
            activityRun.program &&
            String(
                activityRun.program
            ) !==
            String(
                data.program
            )
        ) {
            throw new Error(
                "Activity run does not belong to the selected program."
            );
        }

    }

    if (
        data.enrollment
    ) {

        validateObjectId(
            data.enrollment,
            "Enrollment"
        );

        const enrollment =
            await Enrollment.findOne({

                _id:
                    data.enrollment,

                organization:
                    organizationId,

                isDeleted:
                    false

            }).select(
                "_id beneficiary program"
            );

        if (
            !enrollment
        ) {
            throw new Error(
                "Enrollment not found."
            );
        }

        if (
            validatedBeneficiaries.length === 1 &&
            enrollment.beneficiary &&
            String(
                enrollment.beneficiary
            ) !==
            String(
                validatedBeneficiaries[0]
            )
        ) {
            throw new Error(
                "Enrollment does not belong to the selected beneficiary."
            );
        }

        if (
            data.program &&
            enrollment.program &&
            String(
                enrollment.program
            ) !==
            String(
                data.program
            )
        ) {
            throw new Error(
                "Enrollment does not belong to the selected program."
            );
        }

    }

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

        const enrollment =
            await Enrollment.findOne({

                _id:
                    record.enrollment,

                organization:
                    organizationId,

                isDeleted:
                    false

            }).select(
                "_id beneficiary program"
            );

        if (
            !enrollment
        ) {
            throw new Error(
                "One or more beneficiary enrollments were not found."
            );
        }

        if (
            enrollment.beneficiary &&
            String(
                enrollment.beneficiary
            ) !==
            String(
                record.beneficiary
            )
        ) {
            throw new Error(
                "A beneficiary enrollment does not belong to the selected beneficiary."
            );
        }

        if (
            data.program &&
            enrollment.program &&
            String(
                enrollment.program
            ) !==
            String(
                data.program
            )
        ) {
            throw new Error(
                "A beneficiary enrollment does not belong to the selected program."
            );
        }

    }

    if (
        data.donation
    ) {

        validateObjectId(
            data.donation,
            "Donation"
        );

        const donation =
            await Donation.findOne({

                _id:
                    data.donation,

                organization:
                    organizationId,

                isDeleted:
                    false

            }).select(
                "_id"
            );

        if (
            !donation
        ) {
            throw new Error(
                "Donation not found."
            );
        }

    }

    if (
        data.fundingSource
    ) {

        await validateServiceDeliveryLookup(
            data.fundingSource,
            organizationId,
            "FundingSource",
            "Funding source"
        );

    }

    if (
        data.items !== undefined &&
        !Array.isArray(
            data.items
        )
    ) {
        throw new Error(
            "Service items must be an array."
        );
    }

    return {

        beneficiaryIds:
            validatedBeneficiaries,

        beneficiaryRecords

    };

};


// ======================================================
// VALIDATE RECIPIENT AND ALLOCATION
//
// IMPORTANT:
// This function resolves missing/legacy allocation
// values before applying the business rules.
//
// Individual + beneficiaries:
//     allocationMethod = Individual
//
// Individual + no beneficiaries:
//     invalid
//
// Individual + explicit Unallocated:
//     repaired to Individual when beneficiaries exist
//
// This prevents legacy records or frontend omission from
// causing:
// "An individual recipient cannot use unallocated allocation."
// ======================================================

const validateRecipientAndAllocation = (
    data,
    beneficiaryRecords,
    existingServiceDelivery = null
) => {

    const rawRecipientType =
        data?.recipientType !== undefined &&
        data?.recipientType !== null &&
        data?.recipientType !== ""
            ? String(
                data.recipientType
            ).trim()
            : existingServiceDelivery?.recipientType
                ? String(
                    existingServiceDelivery.recipientType
                ).trim()
                : "Individual";

    const rawAllocationMethod =
        data?.allocationMethod !== undefined &&
        data?.allocationMethod !== null &&
        data?.allocationMethod !== ""
            ? String(
                data.allocationMethod
            ).trim()
            : existingServiceDelivery?.allocationMethod
                ? String(
                    existingServiceDelivery.allocationMethod
                ).trim()
                : null;

    const recipientType =
        rawRecipientType ||
        "Individual";

    let allocationMethod =
        rawAllocationMethod;

    const recipientName =
        data?.recipientName !== undefined
            ? normalizeRecipientName(
                data.recipientName
            )
            : normalizeRecipientName(
                existingServiceDelivery?.recipientName
            );

    const allowedRecipientTypes = [

        "Individual",
        "Household",
        "Group / Community",
        "Institution"

    ];

    const allowedAllocationMethods = [

        "Individual",
        "Shared",
        "Group",
        "Unallocated"

    ];

    if (
        !allowedRecipientTypes.includes(
            recipientType
        )
    ) {

        throw new Error(
            "Recipient type is invalid."
        );

    }

    if (
        allocationMethod !== null &&
        !allowedAllocationMethods.includes(
            allocationMethod
        )
    ) {

        throw new Error(
            "Allocation method is invalid."
        );

    }

    const beneficiaryCount =
        Array.isArray(
            beneficiaryRecords
        )
            ? beneficiaryRecords.filter(
                record =>
                    record &&
                    record.beneficiary
            ).length
            : 0;

    // ==================================================
    // INDIVIDUAL RESOLUTION
    //
    // An Individual recipient with beneficiaries is
    // always allocated by Individual.
    //
    // This also repairs old records that may have been
    // saved as Unallocated.
    // ==================================================

    if (
        recipientType ===
        "Individual"
    ) {

        if (
            beneficiaryCount >
            0
        ) {

            if (
                !allocationMethod ||
                allocationMethod ===
                "Unallocated"
            ) {
                allocationMethod =
                    "Individual";
            }

        }

        else if (
            !allocationMethod
        ) {

            allocationMethod =
                "Individual";

        }

    }

    // ==================================================
    // DEFAULT ALLOCATION
    // ==================================================

    if (
        !allocationMethod
    ) {

        allocationMethod =
            "Unallocated";

    }

    // ==================================================
    // RECIPIENT NAME REQUIREMENTS
    // ==================================================

    if (
        recipientType ===
        "Household" &&
        !recipientName
    ) {

        throw new Error(
            "Household name or identifier is required."
        );

    }

    if (
        recipientType ===
        "Group / Community" &&
        !recipientName
    ) {

        throw new Error(
            "Group or community name is required."
        );

    }

    if (
        recipientType ===
        "Institution" &&
        !recipientName
    ) {

        throw new Error(
            "Institution name is required."
        );

    }

    // ==================================================
    // INDIVIDUAL
    // ==================================================

    if (
        recipientType ===
        "Individual"
    ) {

        if (
            allocationMethod ===
            "Group"
        ) {

            throw new Error(
                "Group allocation is only valid for a group or community recipient."
            );

        }

        if (
            allocationMethod ===
            "Unallocated"
        ) {

            throw new Error(
                "An individual recipient cannot use unallocated allocation."
            );

        }

        if (
            beneficiaryCount ===
            0
        ) {

            throw new Error(
                "At least one beneficiary is required for an individual service delivery."
            );

        }

    }

    // ==================================================
    // HOUSEHOLD
    // ==================================================

    if (
        recipientType ===
        "Household" &&
        allocationMethod ===
        "Group"
    ) {

        throw new Error(
            "Group allocation is not valid for a household recipient."
        );

    }

    // ==================================================
    // GROUP / COMMUNITY
    // ==================================================

    if (
        recipientType ===
        "Group / Community"
    ) {

        if (
            allocationMethod ===
            "Individual"
        ) {

            throw new Error(
                "Individual allocation is not valid for a group or community recipient."
            );

        }

        if (
            allocationMethod ===
            "Shared"
        ) {

            throw new Error(
                "Shared allocation is not valid for a group or community recipient."
            );

        }

    }

    // ==================================================
    // INSTITUTION
    // ==================================================

    if (
        recipientType ===
        "Institution" &&
        allocationMethod ===
        "Group"
    ) {

        throw new Error(
            "Group allocation is not valid for an institution recipient."
        );

    }

    // ==================================================
    // INDIVIDUAL ALLOCATION REQUIRES BENEFICIARY
    // ==================================================

    if (
        allocationMethod ===
        "Individual" &&
        beneficiaryCount ===
        0
    ) {

        throw new Error(
            "At least one beneficiary is required for individual allocation."
        );

    }

    // ==================================================
    // SHARED + INDIVIDUAL
    // ==================================================

    if (
        allocationMethod ===
        "Shared" &&
        recipientType ===
        "Individual" &&
        beneficiaryCount ===
        0
    ) {

        throw new Error(
            "At least one beneficiary is required for shared allocation."
        );

    }

    return {

        recipientType,

        recipientName,

        allocationMethod

    };

};


// ======================================================
// VALIDATE BENEFICIARY ALLOCATIONS
// ======================================================

const validateBeneficiaryAllocations = async (
    beneficiaryRecords,
    serviceItems,
    allocationMethod,
    organizationId
) => {

    if (
        !Array.isArray(
            beneficiaryRecords
        )
    ) {
        return;
    }

    if (
        !Array.isArray(
            serviceItems
        ) ||
        serviceItems.length === 0
    ) {
        throw new Error(
            "Service items are invalid."
        );
    }

    const serviceItemMap =
        new Map();

    const unitSemanticsMap =
        new Map();

    const allocationBehaviorMap =
        new Map();

    // ==================================================
    // BUILD SERVICE ITEM MAPS
    // ==================================================

    for (
        const item
        of serviceItems
    ) {

        if (
            !item?._id
        ) {
            throw new Error(
                "Every service item must have an ID."
            );
        }

        const itemId =
            String(
                item._id
            );

        validateObjectId(
            itemId,
            "Service item ID"
        );

        if (
            serviceItemMap.has(
                itemId
            )
        ) {
            throw new Error(
                "Duplicate service item IDs are not allowed."
            );
        }

        serviceItemMap.set(
            itemId,
            item
        );

        const serviceType =
            await validateServiceDeliveryLookup(
                item.serviceType,
                organizationId,
                "ServiceType",
                "Service type"
            );

        const unit =
            await validateServiceDeliveryLookup(
                item.unit,
                organizationId,
                "Unit",
                "Unit"
            );

        const unitSemantics =
            resolveUnitSemantics(
                unit
            );

        if (
            unitSemantics ===
            "unknown"
        ) {
            throw new Error(
                `Unit '${unit.value || unit.name || unit.code}' does not have recognized service delivery allocation semantics.`
            );
        }

        const allocationBehavior =
            resolveAllocationBehavior(
                item,
                serviceType
            );

        unitSemanticsMap.set(
            itemId,
            {
                unit,
                unitSemantics
            }
        );

        allocationBehaviorMap.set(
            itemId,
            allocationBehavior
        );

        item.allocationBehavior =
            allocationBehavior;

    }

    const quantityTotals =
        new Map();

    const detailQuantityTotals =
        new Map();

    const valueTotals =
        new Map();

    // ==================================================
    // BENEFICIARY ALLOCATIONS
    // ==================================================

    for (
        const beneficiaryRecord
        of beneficiaryRecords
    ) {

        if (
            !beneficiaryRecord ||
            !beneficiaryRecord.beneficiary
        ) {
            throw new Error(
                "Every beneficiary association must contain a beneficiary."
            );
        }

        const beneficiaryId =
            String(
                beneficiaryRecord.beneficiary
            );

        const allocations =
            Array.isArray(
                beneficiaryRecord.allocations
            )
                ? beneficiaryRecord.allocations
                : [];

        const seenAllocationKeys =
            new Set();

        const seenServiceItemModes =
            new Map();

        for (
            const rawAllocation
            of allocations
        ) {

            if (
                !rawAllocation ||
                !rawAllocation.serviceItem
            ) {
                throw new Error(
                    "Each beneficiary allocation must reference a service item."
                );
            }

            const serviceItemId =
                String(
                    rawAllocation.serviceItem
                );

            validateObjectId(
                serviceItemId,
                "Allocated service item"
            );

            const serviceItem =
                serviceItemMap.get(
                    serviceItemId
                );

            if (
                !serviceItem
            ) {
                throw new Error(
                    "One or more beneficiary allocations reference a service item that does not belong to this service delivery."
                );
            }

            const unitInfo =
                unitSemanticsMap.get(
                    serviceItemId
                );

            if (
                !unitInfo
            ) {
                throw new Error(
                    `Unable to determine the allocation semantics for service item ${serviceItemId}.`
                );
            }

            const allocationBehavior =
                allocationBehaviorMap.get(
                    serviceItemId
                ) ||
                "CONSUMPTION";

            const allocation =
                normalizeAllocation(
                    rawAllocation,
                    unitInfo.unitSemantics
                );

            if (
                !allocation
            ) {
                throw new Error(
                    "Beneficiary allocation is invalid."
                );
            }

            const quantity =
                allocation.quantity;

            const allocatedValue =
                allocation.allocatedValue;

            if (
                quantity < 0
            ) {
                throw new Error(
                    "Beneficiary allocation quantity must be zero or greater."
                );
            }

            if (
                allocatedValue < 0
            ) {
                throw new Error(
                    "Beneficiary allocated value must be zero or greater."
                );
            }

            if (
                typeof allocation.remarks !==
                "string"
            ) {
                throw new Error(
                    "Beneficiary allocation remarks must be text."
                );
            }

            if (
                quantity === 0 &&
                allocatedValue === 0
            ) {
                throw new Error(
                    "A beneficiary allocation must contain a quantity or allocated value."
                );
            }

            const detailItemId =
                normalizeObjectId(
                    allocation.detailItem
                );

            let detailItem = null;

            if (
                detailItemId
            ) {

                validateObjectId(
                    detailItemId,
                    "Allocated detail item"
                );

                const detailItems =
                    Array.isArray(
                        serviceItem.detailItems
                    )
                        ? serviceItem.detailItems
                        : [];

                detailItem =
                    detailItems.find(
                        candidate =>
                            candidate &&
                            String(
                                candidate._id
                            ) ===
                            detailItemId
                    );

                if (
                    !detailItem
                ) {
                    throw new Error(
                        `Allocated detail item ${detailItemId} does not belong to service item ${serviceItemId}.`
                    );
                }

            }

            const allocationMode =
                detailItemId
                    ? "detail"
                    : "direct";

            const existingMode =
                seenServiceItemModes.get(
                    serviceItemId
                );

            if (
                existingMode &&
                existingMode !==
                allocationMode
            ) {
                throw new Error(
                    "A beneficiary cannot mix a direct service-item allocation with detail-item allocations for the same service item."
                );
            }

            seenServiceItemModes.set(
                serviceItemId,
                allocationMode
            );

            const allocationKey =
                detailItemId
                    ? `${serviceItemId}:${detailItemId}`
                    : `${serviceItemId}:__DIRECT__`;

            if (
                seenAllocationKeys.has(
                    allocationKey
                )
            ) {
                throw new Error(
                    detailItemId
                        ? "A beneficiary cannot have duplicate allocations for the same service item and detail item."
                        : "A beneficiary cannot have duplicate allocations for the same service item."
                );
            }

            seenAllocationKeys.add(
                allocationKey
            );

            // ==================================================
            // EFFECTIVE UNIT
            // ==================================================

            let effectiveUnitInfo =
                unitInfo;

            if (
                detailItem
            ) {

                if (
                    !detailItem.unit
                ) {
                    throw new Error(
                        `Detail item ${detailItem.name || detailItemId} must have a unit.`
                    );
                }

                const detailUnit =
                    await validateServiceDeliveryLookup(
                        detailItem.unit,
                        organizationId,
                        "Unit",
                        "Detail item unit"
                    );

                const detailUnitSemantics =
                    resolveUnitSemantics(
                        detailUnit
                    );

                if (
                    detailUnitSemantics ===
                    "unknown"
                ) {
                    throw new Error(
                        `Unit '${detailUnit.value || detailUnit.name || detailUnit.code}' does not have recognized service delivery allocation semantics.`
                    );
                }

                effectiveUnitInfo = {

                    unit:
                        detailUnit,

                    unitSemantics:
                        detailUnitSemantics

                };

            }

            // ==================================================
            // MONETARY
            // ==================================================

            if (
                effectiveUnitInfo.unitSemantics ===
                "monetary"
            ) {

                if (
                    quantity !== 0
                ) {
                    throw new Error(
                        `Beneficiary allocation quantity must be 0 for monetary unit '${effectiveUnitInfo.unit.value || effectiveUnitInfo.unit.name}'.`
                    );
                }

            }

            // ==================================================
            // PHYSICAL
            // ==================================================

            if (
                effectiveUnitInfo.unitSemantics ===
                "physical"
            ) {

                if (
                    detailItem
                ) {

                    const actualDetailQuantity =
                        Number(
                            detailItem.quantity
                        );

                    if (
                        Number.isFinite(
                            actualDetailQuantity
                        ) &&
                        quantity >
                            actualDetailQuantity
                    ) {
                        throw new Error(
                            `Beneficiary allocation quantity cannot exceed the actual detail item quantity for beneficiary ${beneficiaryId}.`
                        );
                    }

                    if (
                        allocationBehavior ===
                        "CONSUMPTION"
                    ) {

                        const detailQuantityKey =
                            `${serviceItemId}:${detailItemId}`;

                        detailQuantityTotals.set(
                            detailQuantityKey,
                            (
                                detailQuantityTotals.get(
                                    detailQuantityKey
                                ) || 0
                            ) +
                            quantity
                        );

                    }

                }

                else {

                    const actualQuantity =
                        Number(
                            serviceItem.quantity
                        );

                    if (
                        Number.isFinite(
                            actualQuantity
                        ) &&
                        quantity >
                            actualQuantity
                    ) {
                        throw new Error(
                            `Beneficiary allocation quantity cannot exceed the actual service item quantity for beneficiary ${beneficiaryId}.`
                        );
                    }

                    if (
                        allocationBehavior ===
                        "CONSUMPTION"
                    ) {

                        quantityTotals.set(
                            serviceItemId,
                            (
                                quantityTotals.get(
                                    serviceItemId
                                ) || 0
                            ) +
                            quantity
                        );

                    }

                }

            }

            // ==================================================
            // VALUE TOTAL
            // ==================================================

            valueTotals.set(
                serviceItemId,
                (
                    valueTotals.get(
                        serviceItemId
                    ) || 0
                ) +
                allocatedValue
            );

        }

    }

    // ======================================================
    // AGGREGATE PARENT QUANTITY CAPS
    // ======================================================

    for (
        const [
            serviceItemId,
            allocatedQuantity
        ]
        of quantityTotals.entries()
    ) {

        const serviceItem =
            serviceItemMap.get(
                serviceItemId
            );

        if (
            !serviceItem
        ) {
            continue;
        }

        const unitInfo =
            unitSemanticsMap.get(
                serviceItemId
            );

        const allocationBehavior =
            allocationBehaviorMap.get(
                serviceItemId
            ) ||
            "CONSUMPTION";

        if (
            !unitInfo ||
            unitInfo.unitSemantics !==
            "physical"
        ) {
            continue;
        }

        if (
            allocationBehavior !==
            "CONSUMPTION"
        ) {
            continue;
        }

        const actualQuantity =
            Number(
                serviceItem.quantity
            );

        if (
            Number.isFinite(
                actualQuantity
            ) &&
            allocatedQuantity >
                actualQuantity
        ) {
            throw new Error(
                "Total beneficiary allocation quantity cannot exceed the actual service item quantity."
            );
        }

    }

    // ======================================================
    // AGGREGATE DETAIL QUANTITY CAPS
    // ======================================================

    for (
        const [
            detailQuantityKey,
            allocatedQuantity
        ]
        of detailQuantityTotals.entries()
    ) {

        const [
            serviceItemId,
            detailItemId
        ] =
            detailQuantityKey.split(
                ":"
            );

        const serviceItem =
            serviceItemMap.get(
                serviceItemId
            );

        if (
            !serviceItem
        ) {
            continue;
        }

        const detailItems =
            Array.isArray(
                serviceItem.detailItems
            )
                ? serviceItem.detailItems
                : [];

        const detailItem =
            detailItems.find(
                item =>
                    item &&
                    String(
                        item._id
                    ) ===
                    detailItemId
            );

        if (
            !detailItem
        ) {
            continue;
        }

        const actualDetailQuantity =
            Number(
                detailItem.quantity
            );

        if (
            Number.isFinite(
                actualDetailQuantity
            ) &&
            allocatedQuantity >
                actualDetailQuantity
        ) {
            throw new Error(
                `Total beneficiary allocation quantity for detail item ${detailItem.name || detailItemId} cannot exceed the actual detail item quantity.`
            );
        }

    }

    // ======================================================
    // AGGREGATE VALUE CAPS
    // ======================================================

    for (
        const [
            serviceItemId,
            allocatedValue
        ]
        of valueTotals.entries()
    ) {

        const serviceItem =
            serviceItemMap.get(
                serviceItemId
            );

        if (
            !serviceItem
        ) {
            continue;
        }

        const actualItemCost =
            normalizeNumber(
                serviceItem.totalCost,
                normalizeNumber(
                    serviceItem.quantity,
                    0
                ) *
                normalizeNumber(
                    serviceItem.unitCost,
                    0
                )
            );

        if (
            allocatedValue >
            actualItemCost
        ) {
            throw new Error(
                "Total beneficiary allocated value cannot exceed the actual service item cost."
            );
        }

    }

};


// ======================================================
// BUILD BENEFICIARY ASSOCIATION RECORDS
// ======================================================
//
// Validates and builds the ServiceDeliveryBeneficiary
// rows for a delivery WITHOUT writing them, so every
// check passes before anything is saved.
//
// ======================================================

const buildBeneficiaryAssociationRecords = async (
    serviceDelivery,
    beneficiaryRecords,
    organizationId,
    userId
) => {

    if (
        !Array.isArray(
            beneficiaryRecords
        ) ||
        beneficiaryRecords.length ===
        0
    ) {
        return [];
    }

    const itemSemanticsMap =
        new Map();

    const detailSemanticsMap =
        new Map();

    for (
        const item
        of serviceDelivery.items
    ) {

        const serviceItemId =
            String(
                item._id
            );

        const unit =
            await validateServiceDeliveryLookup(
                item.unit,
                organizationId,
                "Unit",
                "Unit"
            );

        const parentSemantics =
            resolveUnitSemantics(
                unit
            );

        itemSemanticsMap.set(
            serviceItemId,
            parentSemantics
        );

        const detailItems =
            Array.isArray(
                item.detailItems
            )
                ? item.detailItems
                : [];

        for (
            const detailItem
            of detailItems
        ) {

            if (
                !detailItem?.unit ||
                !detailItem?._id
            ) {
                continue;
            }

            const detailUnit =
                await validateServiceDeliveryLookup(
                    detailItem.unit,
                    organizationId,
                    "Unit",
                    "Detail item unit"
                );

            const detailSemantics =
                resolveUnitSemantics(
                    detailUnit
                );

            detailSemanticsMap.set(
                `${serviceItemId}:${String(detailItem._id)}`,
                detailSemantics
            );

        }

    }

    const records =
        beneficiaryRecords.map(
            (
                record
            ) => {

                const allocations =
                    Array.isArray(
                        record.allocations
                    )
                        ? record.allocations
                            .map(
                                allocation => {

                                    const serviceItemId =
                                        normalizeObjectId(
                                            allocation?.serviceItem
                                        );

                                    const detailItemId =
                                        normalizeObjectId(
                                            allocation?.detailItem
                                        );

                                    let semantics =
                                        itemSemanticsMap.get(
                                            String(
                                                serviceItemId
                                            )
                                        );

                                    if (
                                        detailItemId
                                    ) {

                                        const detailSemantics =
                                            detailSemanticsMap.get(
                                                `${String(serviceItemId)}:${String(detailItemId)}`
                                            );

                                        if (
                                            detailSemantics
                                        ) {
                                            semantics =
                                                detailSemantics;
                                        }

                                    }

                                    return normalizeAllocation(
                                        allocation,
                                        semantics
                                    );

                                }
                            )
                            .filter(Boolean)
                        : [];

                return {

                    organization:
                        organizationId,

                    serviceDelivery:
                        serviceDelivery._id,

                    beneficiary:
                        record.beneficiary,

                    enrollment:
                        record.enrollment ||
                        null,

                    status:
                        record.status ||
                        "Received",

                    quantity:
                        record.quantity !==
                            undefined &&
                        record.quantity !==
                            null
                            ? record.quantity
                            : null,

                    remarks:
                        record.remarks ||
                        "",

                    allocations:
                        allocations.map(
                            allocation => ({

                                serviceItem:
                                    allocation.serviceItem,

                                detailItem:
                                    allocation.detailItem ||
                                    null,

                                quantity:
                                    normalizeNumber(
                                        allocation.quantity,
                                        0
                                    ),

                                allocatedValue:
                                    normalizeNumber(
                                        allocation.allocatedValue,
                                        0
                                    ),

                                remarks:
                                    allocation.remarks ||
                                    ""

                            })
                        ),

                    createdBy:
                        userId,

                    updatedBy:
                        userId

                };

            }
        );

    return records;

};


// ======================================================
// CREATE SERVICE DELIVERY
// ======================================================

const createServiceDelivery = async (
    data,
    organizationId,
    userId
) => {

    if (
        !organizationId
    ) {
        throw new Error(
            "Organization ID is required."
        );
    }

    const beneficiaryRecords =
        normalizeBeneficiaries(
            data
        );

    const referenceData =
        Object.assign(
            {},
            data,
            {
                beneficiaries:
                    beneficiaryRecords
            }
        );

    const referenceValidation =
        await validateServiceDeliveryReferences(
            referenceData,
            organizationId
        );

    const beneficiaryIds =
        referenceValidation.beneficiaryIds;

    const {
        recipientType,
        recipientName,
        allocationMethod
    } =
        validateRecipientAndAllocation(
            data,
            beneficiaryRecords
        );

    const deliveryNumber =
        await generateSequence(
            "ServiceDelivery",
            "SD",
            organizationId
        );

    const items =
        calculateItems(
            data.items
        );

    if (
        items.length ===
        0
    ) {
        throw new Error(
            "At least one service item is required."
        );
    }

    await validateServiceItems(
        items,
        organizationId
    );

    await validateBeneficiaryAllocations(
        beneficiaryRecords,
        items,
        allocationMethod,
        organizationId
    );

    const serviceData = {

        organization:
            organizationId,

        deliveryNumber,

        recipientType,

        recipientName,

        allocationMethod,

        beneficiary:
            beneficiaryIds.length ===
                1
                ? beneficiaryIds[0]
                : null,

        enrollment:
            data.enrollment ||
            null,

        program:
            data.program ||
            null,

        project:
            data.project ||
            null,

        activity:
            data.activity ||
            null,

        activityRun:
            data.activityRun ||
            null,

        fundingSource:
            data.fundingSource ||
            null,

        donation:
            data.donation ||
            null,

        items,

        deliveryDate:
            data.deliveryDate ||
            new Date(),

        deliveryLocation:
            data.deliveryLocation ||
            "",

        status:
            data.status ||
            DEFAULT_SERVICE_DELIVERY_STATUS,

        deliveredBy:
            data.deliveredBy ||
            userId,

        documents:
            Array.isArray(
                data.documents
            )
                ? data.documents
                : [],

        createdBy:
            userId,

        updatedBy:
            userId

    };

    const service =
        new ServiceDelivery(
            serviceData
        );

    // ==================================================
    // BUILD BENEFICIARY ROWS BEFORE WRITING ANYTHING
    // ==================================================

    const associationRecords =
        await buildBeneficiaryAssociationRecords(
            service,
            beneficiaryRecords,
            organizationId,
            userId
        );

    // ==================================================
    // SAVE DELIVERY + BENEFICIARY ROWS TOGETHER
    // ==================================================

    try {

        await runInTransaction(
            async (session) => {

                await service.save({
                    session
                });

                try {

                    if (associationRecords.length) {
                        await ServiceDeliveryBeneficiary.insertMany(
                            associationRecords,
                            {
                                session
                            }
                        );
                    }

                }
                catch (error) {

                    // Without a transaction, remove the
                    // half-created delivery and any rows
                    // inserted before the failure.

                    if (!session) {

                        await ServiceDeliveryBeneficiary.deleteMany({
                            organization:
                                organizationId,
                            serviceDelivery:
                                service._id
                        });

                        await ServiceDelivery.deleteOne({
                            _id:
                                service._id
                        });

                    }

                    throw error;

                }

            }
        );

        return service;

    }
    catch (
        error
    ) {

        throw toDuplicateKeyError(error);

    }

};


// ======================================================
// GET ALL SERVICE DELIVERIES
// ======================================================

const getServiceDeliveries = async (
    organizationId
) => {

    const services =
        await ServiceDelivery.find({

            organization:
                organizationId,

            isDeleted:
                false

        })

            .populate(
                "beneficiary",
                "beneficiaryNumber firstName middleName lastName name"
            )

            .populate(
                "enrollment",
                "status"
            )

            .populate(
                "program",
                "name"
            )

            .populate(
                "project",
                "name"
            )

            .populate(
                "activity",
                "name"
            )

            .populate(
                "activityRun",
                "name startDate endDate"
            )

            .populate(
                "donation"
            )

            .populate(
                "items.donor"
            )

            .populate(
                "items.donation"
            )

            .populate(
                "items.serviceCategory",
                "value name code lookupCode category module parentLookup active"
            )

            .populate(
                "items.serviceType",
                "value name code lookupCode category module parentLookup active allocationBehavior"
            )

            .populate(
                "items.unit",
                "value name code lookupCode category module semanticType active"
            )

            .populate(
                "items.detailItems.unit",
                "value name code lookupCode category module semanticType active"
            )

            .populate(
                "items.detailItems.allocationUnit",
                "value name code lookupCode category module semanticType active"
            )

            .populate(
                "fundingSource",
                "value name code lookupCode category module active"
            )

            .populate(
                "createdBy",
                "name"
            )

            .populate(
                "updatedBy",
                "name"
            )

            .sort({
                deliveryDate:
                    -1
            });

    const serviceIds =
        services.map(
            service =>
                service._id
        );

    const associations =
        serviceIds.length > 0

            ? await ServiceDeliveryBeneficiary.find({

                organization:
                    organizationId,

                serviceDelivery:
                    {
                        $in:
                            serviceIds
                    }

            })

                .populate(
                    "beneficiary",
                    "beneficiaryNumber firstName middleName lastName name"
                )

                .populate(
                    "enrollment",
                    "status"
                )

            : [];

    const associationMap =
        new Map();

    associations.forEach(
        (
            association
        ) => {

            const key =
                String(
                    association.serviceDelivery
                );

            if (
                !associationMap.has(
                    key
                )
            ) {

                associationMap.set(
                    key,
                    []
                );

            }

            associationMap
                .get(key)
                .push(
                    association
                );

        }
    );

    return services.map(
        (
            service
        ) => {

            const object =
                service.toObject();

            object.recipientName =
                normalizeRecipientName(
                    object.recipientName
                );

            object.beneficiaries =
                associationMap.get(
                    String(
                        service._id
                    )
                ) || [];

            return object;

        }
    );

};


// ======================================================
// GET SINGLE SERVICE DELIVERY
// ======================================================

const getServiceDeliveryById = async (
    id,
    organizationId
) => {

    validateObjectId(
        id,
        "Service delivery ID"
    );

    const service =
        await ServiceDelivery.findOne({

            _id:
                id,

            organization:
                organizationId,

            isDeleted:
                false

        })

            .populate(
                "beneficiary"
            )

            .populate(
                "enrollment"
            )

            .populate(
                "program"
            )

            .populate(
                "project"
            )

            .populate(
                "activity"
            )

            .populate(
                "activityRun"
            )

            .populate(
                "donation"
            )

            .populate(
                "fundingSource"
            )

            .populate(
                "items.donor"
            )

            .populate(
                "items.donation"
            )

            .populate(
                "items.serviceCategory"
            )

            .populate(
                "items.serviceType"
            )

            .populate(
                "items.unit"
            )

            .populate(
                "items.detailItems.unit"
            )

            .populate(
                "items.detailItems.allocationUnit"
            );

    if (
        !service
    ) {
        throw new Error(
            "Service delivery not found."
        );
    }

    const beneficiaries =
        await ServiceDeliveryBeneficiary.find({

            organization:
                organizationId,

            serviceDelivery:
                service._id

        })

            .populate(
                "beneficiary"
            )

            .populate(
                "enrollment"
            );

    const result =
        service.toObject();

    result.recipientName =
        normalizeRecipientName(
            result.recipientName
        );

    result.beneficiaries =
        beneficiaries.map(
            (
                beneficiary
            ) => {

                const object =
                    beneficiary.toObject();

                object.allocations =
                    Array.isArray(
                        object.allocations
                    )
                        ? object.allocations.map(
                            allocation => ({

                                _id:
                                    allocation._id,

                                serviceItem:
                                    allocation.serviceItem,

                                detailItem:
                                    allocation.detailItem ||
                                    null,

                                quantity:
                                    normalizeNumber(
                                        allocation.quantity,
                                        0
                                    ),

                                allocatedValue:
                                    normalizeNumber(
                                        allocation.allocatedValue,
                                        0
                                    ),

                                remarks:
                                    typeof allocation.remarks ===
                                        "string"
                                        ? allocation.remarks.trim()
                                        : ""

                            })
                        )
                        : [];

                return object;

            }
        );

    return result;

};


// ======================================================
// RESOLVE INCOMING EDIT ITEM ID
// ======================================================

const resolveIncomingEditItemId = (
    rawItem,
    existingItems,
    usedExistingIds
) => {

    const incomingId =
        normalizeObjectId(
            rawItem?._id
        );

    if (
        incomingId &&
        isObjectIdLike(
            incomingId
        )
    ) {

        const exact =
            existingItems.find(
                item =>
                    String(
                        item._id
                    ) ===
                    incomingId
            );

        if (
            exact
        ) {

            const exactId =
                String(
                    exact._id
                );

            if (
                usedExistingIds.has(
                    exactId
                )
            ) {
                throw new Error(
                    "Duplicate service item IDs are not allowed."
                );
            }

            usedExistingIds.add(
                exactId
            );

            return {

                id:
                    exactId,

                isExisting:
                    true

            };

        }

        return {

            id:
                incomingId,

            isExisting:
                false

        };

    }

    const incomingCategory =
        normalizeObjectId(
            rawItem?.serviceCategory
        );

    const incomingType =
        normalizeObjectId(
            rawItem?.serviceType
        );

    const incomingUnit =
        normalizeObjectId(
            rawItem?.unit
        );

    const candidates =
        existingItems.filter(
            item => {

                const categoryMatches =
                    incomingCategory &&
                    String(
                        item.serviceCategory
                    ) ===
                    incomingCategory;

                const typeMatches =
                    incomingType &&
                    String(
                        item.serviceType
                    ) ===
                    incomingType;

                const unitMatches =
                    incomingUnit &&
                    String(
                        item.unit
                    ) ===
                    incomingUnit;

                return (
                    categoryMatches &&
                    typeMatches &&
                    unitMatches &&
                    !usedExistingIds.has(
                        String(
                            item._id
                        )
                    )
                );

            }
        );

    if (
        candidates.length ===
        1
    ) {

        const resolvedId =
            String(
                candidates[0]._id
            );

        usedExistingIds.add(
            resolvedId
        );

        return {

            id:
                resolvedId,

            isExisting:
                true

        };

    }

    return {

        id:
            null,

        isExisting:
            false

    };

};


// ======================================================
// BUILD FINAL EDIT ITEMS
// ======================================================

const buildFinalEditItems = (
    incomingItems,
    existingItems
) => {

    if (
        !Array.isArray(
            incomingItems
        ) ||
        incomingItems.length ===
        0
    ) {
        throw new Error(
            "At least one service item is required."
        );
    }

    const usedExistingIds =
        new Set();

    const usedFinalIds =
        new Set();

    return incomingItems.map(
        (
            rawItem
        ) => {

            const resolution =
                resolveIncomingEditItemId(
                    rawItem,
                    existingItems,
                    usedExistingIds
                );

            let finalId =
                resolution.id;

            if (
                !finalId
            ) {
                finalId =
                    new mongoose.Types.ObjectId()
                        .toString();
            }

            if (
                usedFinalIds.has(
                    finalId
                )
            ) {
                throw new Error(
                    "Duplicate service item IDs are not allowed."
                );
            }

            usedFinalIds.add(
                finalId
            );

            const finalRawItem =
                Object.assign(
                    {},
                    rawItem,
                    {
                        _id:
                            finalId
                    }
                );

            return calculateItems([
                finalRawItem
            ])[0];

        }
    );

};


// ======================================================
// UPDATE SERVICE DELIVERY
// ======================================================

const updateServiceDelivery = async (
    id,
    data,
    organizationId,
    userId
) => {

    validateObjectId(
        id,
        "Service delivery ID"
    );

    if (
        !organizationId
    ) {
        throw new Error(
            "Organization ID is required."
        );
    }

    if (
        !data ||
        typeof data !== "object"
    ) {
        throw new Error(
            "Service delivery update data is required."
        );
    }

    const service =
        await ServiceDelivery.findOne({

            _id:
                id,

            organization:
                organizationId,

            isDeleted:
                false

        });

    if (
        !service
    ) {
        throw new Error(
            "Service delivery not found."
        );
    }

    // ==================================================
    // CANCELLED DELIVERIES ARE LOCKED
    //
    // A cancelled delivery can only be changed in the
    // same save that sets it back to Delivered.
    // ==================================================

    const nextStatus =
        data.status ||
        service.status;

    if (
        service.status ===
            SERVICE_DELIVERY_STATUS.CANCELLED &&
        nextStatus ===
            SERVICE_DELIVERY_STATUS.CANCELLED
    ) {
        throw new Error(
            "This service delivery is cancelled. Set its status back to Delivered to make changes."
        );
    }

    // ==================================================
    // BENEFICIARIES
    //
    // Only an explicit beneficiaries ARRAY replaces
    // beneficiary associations.
    //
    // The legacy singular beneficiary field is not
    // allowed to collapse an existing multi-beneficiary
    // delivery.
    // ==================================================

    const beneficiariesWereProvided =
        Array.isArray(
            data.beneficiaries
        );

    let beneficiaryRecords = [];

    if (
        beneficiariesWereProvided
    ) {

        beneficiaryRecords =
            normalizeBeneficiaries(
                data
            );

    }

    else {

        const existingAssociations =
            await ServiceDeliveryBeneficiary.find({

                organization:
                    organizationId,

                serviceDelivery:
                    service._id

            }).select(
                "beneficiary enrollment status quantity remarks allocations"
            );

        beneficiaryRecords =
            existingAssociations.map(
                (
                    association
                ) => ({

                    beneficiary:
                        association.beneficiary,

                    enrollment:
                        association.enrollment ||
                        null,

                    status:
                        association.status ||
                        "Received",

                    quantity:
                        association.quantity !==
                            undefined &&
                        association.quantity !==
                            null
                            ? normalizeNumber(
                                association.quantity,
                                0
                            )
                            : null,

                    remarks:
                        association.remarks ||
                        "",

                    allocations:
                        Array.isArray(
                            association.allocations
                        )
                            ? association.allocations.map(
                                allocation => ({

                                    serviceItem:
                                        allocation.serviceItem,

                                    detailItem:
                                        allocation.detailItem ||
                                        null,

                                    quantity:
                                        normalizeNumber(
                                            allocation.quantity,
                                            0
                                        ),

                                    allocatedValue:
                                        normalizeNumber(
                                            allocation.allocatedValue,
                                            0
                                        ),

                                    remarks:
                                        typeof allocation.remarks ===
                                            "string"
                                            ? allocation.remarks.trim()
                                            : ""

                                })
                            )
                            : []

                })
            );

    }

    // ==================================================
    // FINAL RECIPIENT VALUES
    //
    // Normalize incoming values first.
    // Empty/null values mean "not supplied" and therefore
    // preserve the existing value.
    // ==================================================

    const finalRecipientType =
        data.recipientType !== undefined &&
        data.recipientType !== null &&
        data.recipientType !== ""
            ? String(
                data.recipientType
            ).trim()
            : service.recipientType
                ? String(
                    service.recipientType
                ).trim()
                : "Individual";

    const finalRecipientName =
        data.recipientName !== undefined
            ? normalizeRecipientName(
                data.recipientName
            )
            : normalizeRecipientName(
                service.recipientName
            );

    let finalAllocationMethod =
        data.allocationMethod !== undefined &&
        data.allocationMethod !== null &&
        data.allocationMethod !== ""
            ? String(
                data.allocationMethod
            ).trim()
            : service.allocationMethod
                ? String(
                    service.allocationMethod
                ).trim()
                : null;

    // ==================================================
    // IMPORTANT RECOVERY RULE
    //
    // If this is an Individual recipient and there are
    // beneficiaries, Individual allocation is required.
    //
    // This repairs legacy data where allocationMethod was
    // accidentally stored as Unallocated.
    // ==================================================

    const beneficiaryCount =
        Array.isArray(
            beneficiaryRecords
        )
            ? beneficiaryRecords.filter(
                record =>
                    record &&
                    record.beneficiary
            ).length
            : 0;

    if (
        finalRecipientType ===
        "Individual" &&
        beneficiaryCount > 0 &&
        (
            !finalAllocationMethod ||
            finalAllocationMethod ===
            "Unallocated"
        )
    ) {

        finalAllocationMethod =
            "Individual";

    }

    // ==================================================
    // RESOLVE FINAL RECIPIENT VALUES THROUGH THE SAME
    // BUSINESS RULES USED BY CREATE
    // ==================================================

    const recipientValidationData =
        Object.assign(
            {},
            data,
            {

                recipientType:
                    finalRecipientType,

                recipientName:
                    finalRecipientName,

                allocationMethod:
                    finalAllocationMethod

            }
        );

    const recipientValidation =
        validateRecipientAndAllocation(
            recipientValidationData,
            beneficiaryRecords,
            service
        );

    const resolvedRecipientType =
        recipientValidation.recipientType;

    const resolvedRecipientName =
        recipientValidation.recipientName;

    const resolvedAllocationMethod =
        recipientValidation.allocationMethod;

    // ==================================================
    // FINAL SERVICE ITEMS
    // ==================================================

    let finalItems =
        service.items.map(
            item => ({

                _id:
                    item._id,

                serviceCategory:
                    normalizeObjectId(
                        item.serviceCategory
                    ),

                serviceType:
                    normalizeObjectId(
                        item.serviceType
                    ),

                allocationBehavior:
                    normalizeAllocationBehavior(
                        item.allocationBehavior
                    ) ||
                    "CONSUMPTION",

                quantity:
                    normalizeNumber(
                        item.quantity,
                        0
                    ),

                unit:
                    normalizeObjectId(
                        item.unit
                    ),

                unitCost:
                    normalizeNumber(
                        item.unitCost,
                        0
                    ),

                totalCost:
                    normalizeNumber(
                        item.quantity,
                        0
                    ) *
                    normalizeNumber(
                        item.unitCost,
                        0
                    ),

                donor:
                    normalizeObjectId(
                        item.donor
                    ),

                donation:
                    normalizeObjectId(
                        item.donation
                    ),

                detailItems:
                    normalizeDetailItems(
                        Array.isArray(
                            item.detailItems
                        )
                            ? item.detailItems
                            : []
                    ),

                remarks:
                    item.remarks ||
                    ""

            })
        );

    if (
        data.items !==
        undefined
    ) {

        finalItems =
            buildFinalEditItems(
                data.items,
                service.items
            );

    }

    const finalItemIds =
        new Set(
            finalItems.map(
                item =>
                    String(
                        item._id
                    )
            )
        );

    // ==================================================
    // VALIDATE ALLOCATION REFERENCES
    // ==================================================

    for (
        const beneficiaryRecord
        of beneficiaryRecords
    ) {

        const allocations =
            Array.isArray(
                beneficiaryRecord.allocations
            )
                ? beneficiaryRecord.allocations
                : [];

        for (
            const allocation
            of allocations
        ) {

            if (
                !allocation?.serviceItem
            ) {
                throw new Error(
                    "Each beneficiary allocation must reference a service item."
                );
            }

            const allocationItemId =
                String(
                    allocation.serviceItem
                );

            if (
                !isObjectIdLike(
                    allocationItemId
                )
            ) {
                throw new Error(
                    "Beneficiary allocation contains an invalid service item ID."
                );
            }

            if (
                !finalItemIds.has(
                    allocationItemId
                )
            ) {
                throw new Error(
                    "One or more beneficiary allocations reference a service item that does not belong to this service delivery."
                );
            }

            const detailItemId =
                normalizeObjectId(
                    allocation.detailItem
                );

            if (
                detailItemId
            ) {

                validateObjectId(
                    detailItemId,
                    "Allocated detail item"
                );

                const finalItem =
                    finalItems.find(
                        item =>
                            String(
                                item._id
                            ) ===
                            allocationItemId
                    );

                const detailItems =
                    Array.isArray(
                        finalItem?.detailItems
                    )
                        ? finalItem.detailItems
                        : [];

                const detailItemExists =
                    detailItems.some(
                        detailItem =>
                            detailItem &&
                            String(
                                detailItem._id
                            ) ===
                            detailItemId
                    );

                if (
                    !detailItemExists
                ) {
                    throw new Error(
                        `Allocated detail item ${detailItemId} does not belong to service item ${allocationItemId}.`
                    );
                }

            }

        }

    }

    // ==================================================
    // VALIDATE FINAL ITEMS
    // ==================================================

    await validateServiceItems(
        finalItems,
        organizationId
    );

    // ==================================================
    // FINAL REFERENCE VALUES
    //
    // Undefined = preserve existing value.
    // Explicit null = intentionally clear the value.
    // ==================================================

    const finalProgram =
        data.program !==
            undefined
            ? data.program
            : normalizeObjectId(
                service.program
            );

    const finalProject =
        data.project !==
            undefined
            ? data.project
            : normalizeObjectId(
                service.project
            );

    const finalActivity =
        data.activity !==
            undefined
            ? data.activity
            : normalizeObjectId(
                service.activity
            );

    const finalActivityRun =
        data.activityRun !==
            undefined
            ? data.activityRun
            : normalizeObjectId(
                service.activityRun
            );

    const finalEnrollment =
        data.enrollment !==
            undefined
            ? data.enrollment
            : normalizeObjectId(
                service.enrollment
            );

    const finalDonation =
        data.donation !==
            undefined
            ? data.donation
            : normalizeObjectId(
                service.donation
            );

    const finalFundingSource =
        data.fundingSource !==
            undefined
            ? data.fundingSource
            : normalizeObjectId(
                service.fundingSource
            );

    // ==================================================
    // VALIDATE FINAL REFERENCES
    // ==================================================

    const referenceValidationData =
        Object.assign(
            {},
            data,
            {

                beneficiaries:
                    beneficiaryRecords,

                program:
                    finalProgram,

                project:
                    finalProject,

                activity:
                    finalActivity,

                activityRun:
                    finalActivityRun,

                enrollment:
                    finalEnrollment,

                donation:
                    finalDonation,

                fundingSource:
                    finalFundingSource,

                items:
                    finalItems

            }
        );

    const referenceValidation =
        await validateServiceDeliveryReferences(
            referenceValidationData,
            organizationId
        );

    const beneficiaryIds =
        referenceValidation.beneficiaryIds;

    // ==================================================
    // VALIDATE BENEFICIARY ALLOCATIONS
    //
    // IMPORTANT:
    // Use the RESOLVED allocation method, not the raw
    // value from the request/database.
    // ==================================================

    await validateBeneficiaryAllocations(
        beneficiaryRecords,
        finalItems,
        resolvedAllocationMethod,
        organizationId
    );

    // ==================================================
    // BUILD UPDATE DATA
    // ==================================================

    const allowedFields = [

        "recipientType",
        "recipientName",
        "allocationMethod",
        "enrollment",
        "program",
        "project",
        "activity",
        "activityRun",
        "fundingSource",
        "donation",
        "items",
        "deliveryDate",
        "deliveryLocation",
        "status",
        "deliveredBy",
        "documents"

    ];

    const updateData = {};

    allowedFields.forEach(
        (
            field
        ) => {

            if (
                data[field] ===
                undefined
            ) {
                return;
            }

            if (
                field ===
                "recipientName"
            ) {

                updateData[field] =
                    normalizeRecipientName(
                        data[field]
                    );

                return;

            }

            if (
                field ===
                "items"
            ) {

                updateData.items =
                    finalItems;

                return;

            }

            if (
                field ===
                "documents"
            ) {

                if (
                    !Array.isArray(
                        data.documents
                    )
                ) {
                    throw new Error(
                        "Documents must be an array."
                    );
                }

                updateData.documents =
                    data.documents;

                return;

            }

            updateData[field] =
                data[field];

        }
    );

    // ==================================================
    // ALWAYS STORE RESOLVED RECIPIENT VALUES
    //
    // This is critical.
    //
    // We do NOT store the raw "Unallocated" value when
    // the recipient is Individual with beneficiaries.
    // ==================================================

    updateData.recipientType =
        resolvedRecipientType;

    updateData.recipientName =
        resolvedRecipientName;

    updateData.allocationMethod =
        resolvedAllocationMethod;

    // ==================================================
    // LEGACY BENEFICIARY FIELD
    //
    // Only change the singular field when the beneficiary
    // association array was explicitly replaced.
    // ==================================================

    if (
        beneficiariesWereProvided
    ) {

        updateData.beneficiary =
            beneficiaryIds.length ===
                1
                ? beneficiaryIds[0]
                : null;

    }

    // ==================================================
    // APPLY UPDATE
    //
    // Snapshot first so a failed save without a
    // transaction can be rolled back.
    // ==================================================

    const originalDelivery =
        service.toObject({
            depopulate: true
        });

    Object.assign(
        service,
        updateData
    );

    service.updatedBy =
        userId;

    // ==================================================
    // BUILD BENEFICIARY ROWS BEFORE WRITING ANYTHING
    //
    // Associations are replaced ONLY when `beneficiaries`
    // was explicitly supplied.
    // ==================================================

    const associationRecords =
        beneficiariesWereProvided
            ? await buildBeneficiaryAssociationRecords(
                service,
                beneficiaryRecords,
                organizationId,
                userId
            )
            : [];

    const associationFilter = {

        organization:
            organizationId,

        serviceDelivery:
            service._id

    };

    // ==================================================
    // SAVE DELIVERY + REPLACE BENEFICIARY ROWS TOGETHER
    // ==================================================

    try {

        await runInTransaction(
            async (session) => {

                // Without a transaction, keep the current
                // rows so they can be restored on failure.

                const previousRows =
                    !session && beneficiariesWereProvided
                        ? await ServiceDeliveryBeneficiary
                            .find(associationFilter)
                            .lean()
                        : [];

                await service.save({
                    session
                });

                if (!beneficiariesWereProvided) {
                    return;
                }

                try {

                    await ServiceDeliveryBeneficiary.deleteMany(
                        associationFilter,
                        {
                            session
                        }
                    );

                    if (associationRecords.length) {
                        await ServiceDeliveryBeneficiary.insertMany(
                            associationRecords,
                            {
                                session
                            }
                        );
                    }

                }
                catch (error) {

                    if (!session) {

                        await ServiceDeliveryBeneficiary.deleteMany(
                            associationFilter
                        );

                        if (previousRows.length) {
                            await ServiceDeliveryBeneficiary.insertMany(
                                previousRows
                            );
                        }

                        await ServiceDelivery.replaceOne(
                            {
                                _id:
                                    service._id
                            },
                            originalDelivery
                        );

                    }

                    throw error;

                }

            }
        );

    }
    catch (
        error
    ) {

        throw toDuplicateKeyError(error);

    }

    return service;

};


// ======================================================
// DELETE SERVICE DELIVERY
// ======================================================

const deleteServiceDelivery = async (
    id,
    organizationId,
    userId
) => {

    validateObjectId(
        id,
        "Service delivery ID"
    );

    const service =
        await ServiceDelivery.findOne({

            _id:
                id,

            organization:
                organizationId,

            isDeleted:
                false

        });

    if (
        !service
    ) {
        throw new Error(
            "Service delivery not found."
        );
    }

    service.isDeleted =
        true;

    service.deletedAt =
        new Date();

    service.deletedBy =
        userId;

    service.updatedBy =
        userId;

    await service.save();

    await ServiceDeliveryBeneficiary.deleteMany({

        organization:
            organizationId,

        serviceDelivery:
            service._id

    });

    return service;

};


// ======================================================
// EXPORT
// ======================================================

module.exports = {

    createServiceDelivery,

    getServiceDeliveries,

    getServiceDeliveryById,

    updateServiceDelivery,

    deleteServiceDelivery

};