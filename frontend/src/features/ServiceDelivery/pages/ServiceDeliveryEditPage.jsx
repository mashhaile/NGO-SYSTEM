import {
    useEffect,
    useRef,
    useState
} from "react";


import {
    useNavigate,
    useParams
} from "react-router-dom";


import {
    ArrowBack
} from "@mui/icons-material";


import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    LoadingState,
    InfoRow,
    AppButton
} from "../../../components/ui";


import ServiceDeliveryForm
    from "../components/serviceDeliveryForm";


import {
    getServiceDeliveryByIdService,
    updateServiceDeliveryService
} from "../services/serviceDeliveryService";


import {
    getBeneficiariesLookupService
} from "../../beneficiaries/services/beneficiaryService";


import {
    getProgramsService
} from "../../programs/services/programService";


import {
    getProjectsService
} from "../../projects/services/projectService";


import {
    getActivitiesService
} from "../../activities/services/activityService";


import {
    getActivityRunsService
} from "../../activityRuns/services/activityRunService";


import {
    getLookupOptionsService
} from "../services/lookupService";


// =====================================================
// CONSTANTS
// =====================================================

const OBJECT_ID_REGEX =
    /^[a-fA-F0-9]{24}$/;


// =====================================================
// GENERATE CLIENT-SIDE OBJECT ID
// =====================================================

const generateObjectId = () => {

    const timestamp =
        Math.floor(
            Date.now() / 1000
        )
            .toString(16)
            .padStart(
                8,
                "0"
            );


    let randomPart = "";


    for (
        let i = 0;
        i < 16;
        i += 1
    ) {

        randomPart +=
            Math.floor(
                Math.random() * 16
            ).toString(16);

    }


    return (
        timestamp +
        randomPart
    ).slice(
        0,
        24
    );

};


// =====================================================
// OBJECT ID VALIDATION
// =====================================================

const isObjectIdLike = (
    value
) => {

    return (
        typeof value === "string" &&
        OBJECT_ID_REGEX.test(
            value
        )
    );

};


// =====================================================
// RESPONSE DATA
// =====================================================

const getResponseData = (
    response
) => {

    if (
        response?.data?.data &&
        typeof response.data.data === "object" &&
        !Array.isArray(
            response.data.data
        )
    ) {

        return response.data.data;

    }


    if (
        response?.data &&
        typeof response.data === "object" &&
        !Array.isArray(
            response.data
        )
    ) {

        return response.data;

    }


    if (
        response &&
        typeof response === "object"
    ) {

        return response;

    }


    return null;

};


// =====================================================
// ARRAY NORMALIZATION
// =====================================================

const normalizeArray = (
    response
) => {

    if (
        Array.isArray(
            response
        )
    ) {

        return response;

    }


    if (
        !response ||
        typeof response !== "object"
    ) {

        return [];

    }


    const possibleArrays = [

        response?.data?.data,

        response?.data?.rows,

        response?.data?.items,

        response?.data?.options,

        response?.data?.results,

        response?.data,

        response?.rows,

        response?.items,

        response?.options,

        response?.results

    ];


    for (
        const candidate
        of possibleArrays
    ) {

        if (
            Array.isArray(
                candidate
            )
        ) {

            return candidate;

        }

    }


    return [];

};


// =====================================================
// GENERIC ID
// =====================================================

const getId = (
    value,
    depth = 0
) => {

    if (
        depth > 10
    ) {

        return "";

    }


    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return "";

    }


    if (
        typeof value === "string" ||
        typeof value === "number"
    ) {

        return String(
            value
        );

    }


    if (
        typeof value !== "object"
    ) {

        return String(
            value
        );

    }


    if (
        value?._id !== undefined &&
        value?._id !== null &&
        value?._id !== ""
    ) {

        return getId(
            value._id,
            depth + 1
        );

    }


    if (
        value?.id !== undefined &&
        value?.id !== null &&
        value?.id !== ""
    ) {

        return getId(
            value.id,
            depth + 1
        );

    }


    if (
        value?.value !== undefined &&
        value?.value !== null &&
        value?.value !== ""
    ) {

        return getId(
            value.value,
            depth + 1
        );

    }


    if (
        value?.lookupId !== undefined &&
        value?.lookupId !== null &&
        value?.lookupId !== ""
    ) {

        return getId(
            value.lookupId,
            depth + 1
        );

    }


    if (
        value?.lookup !== undefined &&
        value?.lookup !== null &&
        value?.lookup !== ""
    ) {

        return getId(
            value.lookup,
            depth + 1
        );

    }


    return "";

};


// =====================================================
// BENEFICIARY ID
// =====================================================

const getBeneficiaryId = (
    value
) => {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return "";

    }


    if (
        typeof value === "string" ||
        typeof value === "number"
    ) {

        return String(
            value
        );

    }


    if (
        value?.beneficiary
    ) {

        return getBeneficiaryId(
            value.beneficiary
        );

    }


    return getId(
        value
    );

};


// =====================================================
// DATE
// =====================================================

const normalizeDate = (
    value
) => {

    if (
        !value
    ) {

        return null;

    }


    if (
        value instanceof Date
    ) {

        return value;

    }


    return value;

};


// =====================================================
// ALLOCATION
// =====================================================

const normalizeAllocation = (
    allocation
) => {

    if (
        !allocation
    ) {

        return null;

    }


    const serviceItem =
        getId(
            allocation?.serviceItem
        );


    if (
        !serviceItem
    ) {

        return null;

    }


    // IMPORTANT:
    // Preserve detailItem when loading an existing
    // beneficiary allocation for edit.
    const detailItem =
        getId(
            allocation?.detailItem
        ) ||
        null;


    const quantity =
        Number(
            allocation?.quantity ?? 0
        );


    const allocatedValue =
        Number(
            allocation?.originalAllocatedValue ?? allocation?.allocatedValue ?? 0
        );


    return {

        serviceItem,

        detailItem,

        quantity:
            Number.isFinite(
                quantity
            )
                ? quantity
                : 0,

        allocatedValue:
            Number.isFinite(
                allocatedValue
            )
                ? allocatedValue
                : 0,

        remarks:
            allocation?.remarks ||
            ""

    };

};


// =====================================================
// BENEFICIARY ASSOCIATION
// =====================================================

const normalizeBeneficiaryAssociation = (
    value
) => {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return null;

    }


    const beneficiaryId =
        getBeneficiaryId(
            value
        );


    if (
        !beneficiaryId
    ) {

        return null;

    }


    const rawAllocations =
        Array.isArray(
            value?.allocations
        )
            ? value.allocations
            : [];


    const allocations =
        rawAllocations
            .map(
                normalizeAllocation
            )
            .filter(
                Boolean
            );


    let quantity =
        null;


    if (
        value?.quantity !== null &&
        value?.quantity !== undefined &&
        value?.quantity !== ""
    ) {

        const numericQuantity =
            Number(
                value.quantity
            );


        quantity =
            Number.isFinite(
                numericQuantity
            )
                ? numericQuantity
                : null;

    }


    return {

        beneficiary:
            beneficiaryId,

        enrollment:
            getId(
                value?.enrollment
            ) ||
            null,

        status:
            value?.status ||
            "Received",

        quantity,

        remarks:
            value?.remarks ||
            "",

        allocations

    };

};


// =====================================================
// EXISTING BENEFICIARIES
// =====================================================

const normalizeExistingBeneficiaries = (
    delivery
) => {

    if (
        Array.isArray(
            delivery?.beneficiaries
        )
    ) {

        return delivery.beneficiaries
            .map(
                normalizeBeneficiaryAssociation
            )
            .filter(
                Boolean
            );

    }


    if (
        delivery?.beneficiary
    ) {

        const beneficiary =
            normalizeBeneficiaryAssociation(
                {

                    beneficiary:
                        delivery.beneficiary,

                    enrollment:
                        delivery.enrollment,

                    status:
                        "Received",

                    quantity:
                        null,

                    remarks:
                        "",

                    allocations:
                        []

                }
            );


        return beneficiary
            ? [
                beneficiary
            ]
            : [];

    }


    return [];

};


// =====================================================
// EXISTING BENEFICIARY OBJECTS
// =====================================================

const getExistingBeneficiaryObjects = (
    delivery
) => {

    if (
        Array.isArray(
            delivery?.beneficiaries
        )
    ) {

        return delivery.beneficiaries
            .map(
                (
                    item
                ) =>
                    item?.beneficiary ||
                    item
            )
            .filter(
                Boolean
            );

    }


    if (
        delivery?.beneficiary
    ) {

        return [
            delivery.beneficiary
        ];

    }


    return [];

};


// =====================================================
// NORMALIZE DETAIL ITEMS
// =====================================================

const normalizeDetailItems = (
    detailItems
) => {

    if (
        !Array.isArray(
            detailItems
        )
    ) {

        return [];

    }


    const normalizedDetailItems =
        [];


    const usedIds =
        new Set();


    detailItems.forEach(
        (
            detailItem
        ) => {

            if (
                !detailItem ||
                typeof detailItem !== "object"
            ) {

                return;

            }


            let detailItemId =
                getId(
                    detailItem?._id
                );


            if (
                !detailItemId
            ) {

                detailItemId =
                    getId(
                        detailItem?.id
                    );

            }


            if (
                !detailItemId ||
                !isObjectIdLike(
                    detailItemId
                )
            ) {

                detailItemId =
                    generateObjectId();

            }


            let normalizedDetailItemId =
                String(
                    detailItemId
                );


            while (
                usedIds.has(
                    normalizedDetailItemId
                )
            ) {

                normalizedDetailItemId =
                    generateObjectId();

            }


            usedIds.add(
                normalizedDetailItemId
            );


            const quantity =
                Number(
                    detailItem?.quantity ?? 1
                );


            const unitCost =
                Number(
                    detailItem?.originalUnitCost ?? detailItem?.unitCost ?? 0
                );


            const safeQuantity =
                Number.isFinite(
                    quantity
                ) &&
                quantity > 0
                    ? quantity
                    : 1;


            const safeUnitCost =
                Number.isFinite(
                    unitCost
                ) &&
                unitCost >= 0
                    ? unitCost
                    : 0;


            const normalizedDetailItem =
                Object.assign(
                    {},
                    detailItem
                );


            normalizedDetailItem._id =
                normalizedDetailItemId;


            normalizedDetailItem.name =
                typeof detailItem?.name ===
                "string"
                    ? detailItem.name
                    : "";


            normalizedDetailItem.quantity =
                safeQuantity;


            normalizedDetailItem.unit =
                getId(
                    detailItem?.unit
                ) ||
                "";

            // Given out in another unit (1 Sack = 50 Kg)
            normalizedDetailItem.allocationUnit =
                getId(
                    detailItem?.allocationUnit
                ) ||
                null;

            normalizedDetailItem.allocationConversionFactor =
                normalizedDetailItem.allocationUnit &&
                Number(detailItem?.allocationConversionFactor) > 0
                    ? Number(detailItem.allocationConversionFactor)
                    : 1;


            normalizedDetailItem.unitCost =
                safeUnitCost;


            normalizedDetailItem.totalCost =
                safeQuantity *
                safeUnitCost;


            normalizedDetailItems.push(
                normalizedDetailItem
            );

        }
    );


    return normalizedDetailItems;

};


// =====================================================
// NORMALIZE DETAIL ITEMS FOR SUBMISSION
// =====================================================

const normalizeDetailItemsForSubmit = (
    detailItems
) => {

    if (
        !Array.isArray(
            detailItems
        )
    ) {

        return [];

    }


    const submittedDetailItems =
        [];


    const usedIds =
        new Set();


    detailItems.forEach(
        (
            detailItem
        ) => {

            if (
                !detailItem ||
                typeof detailItem !== "object"
            ) {

                return;

            }


            let detailItemId =
                getId(
                    detailItem?._id
                );


            if (
                !detailItemId
            ) {

                detailItemId =
                    getId(
                        detailItem?.id
                    );

            }


            if (
                !detailItemId ||
                !isObjectIdLike(
                    detailItemId
                )
            ) {

                detailItemId =
                    generateObjectId();

            }


            let normalizedDetailItemId =
                String(
                    detailItemId
                );


            while (
                usedIds.has(
                    normalizedDetailItemId
                )
            ) {

                normalizedDetailItemId =
                    generateObjectId();

            }


            usedIds.add(
                normalizedDetailItemId
            );


            const name =
                typeof detailItem?.name ===
                "string"
                    ? detailItem.name.trim()
                    : "";


            const quantity =
                Number(
                    detailItem?.quantity ?? 1
                );


            const unitCost =
                Number(
                    detailItem?.unitCost ?? 0
                );


            const safeQuantity =
                Number.isFinite(
                    quantity
                ) &&
                quantity > 0
                    ? quantity
                    : 1;


            const safeUnitCost =
                Number.isFinite(
                    unitCost
                ) &&
                unitCost >= 0
                    ? unitCost
                    : 0;


            const unit =
                getId(
                    detailItem?.unit
                ) ||
                null;


            submittedDetailItems.push({

                _id:
                    normalizedDetailItemId,

                name,
                quantity:
                    safeQuantity,
                unit,
                allocationUnit:
                    getId(
                        detailItem?.allocationUnit
                    ) ||
                    null,
                allocationConversionFactor:
                    getId(detailItem?.allocationUnit) &&
                    Number(detailItem?.allocationConversionFactor) > 0
                        ? Number(detailItem.allocationConversionFactor)
                        : 1,
                unitCost:
                    safeUnitCost,

                totalCost:
                    safeQuantity *
                    safeUnitCost

            });

        }
    );


    return submittedDetailItems;

};


// =====================================================
// NORMALIZE SERVICE ITEMS
// =====================================================

const normalizeItems = (
    items
) => {

    if (
        !Array.isArray(
            items
        )
    ) {

        return [];

    }


    const normalizedItems =
        [];


    const usedIds =
        new Set();


    items.forEach(
        (
            item
        ) => {

            if (
                !item ||
                typeof item !== "object"
            ) {

                return;

            }


            let itemId =
                getId(
                    item?._id
                );


            if (
                !itemId
            ) {

                itemId =
                    getId(
                        item?.id
                    );

            }


            if (
                !itemId ||
                !isObjectIdLike(
                    itemId
                )
            ) {

                itemId =
                    generateObjectId();

            }


            let normalizedItemId =
                String(
                    itemId
                );


            while (
                usedIds.has(
                    normalizedItemId
                )
            ) {

                normalizedItemId =
                    generateObjectId();

            }


            usedIds.add(
                normalizedItemId
            );


            const quantity =
                Number(
                    item?.quantity ?? 1
                );


            const unitCost =
                Number(
                    item?.originalUnitCost ?? item?.unitCost ?? 0
                );


            const safeQuantity =
                Number.isFinite(
                    quantity
                ) &&
                quantity > 0
                    ? quantity
                    : 1;


            const safeUnitCost =
                Number.isFinite(
                    unitCost
                ) &&
                unitCost >= 0
                    ? unitCost
                    : 0;


            const normalizedItem =
                Object.assign(
                    {},
                    item
                );


            normalizedItem._id =
                normalizedItemId;


            normalizedItem.serviceCategory =
                getId(
                    item?.serviceCategory
                ) ||
                "";


            normalizedItem.serviceType =
                getId(
                    item?.serviceType
                ) ||
                "";


            normalizedItem.unit =
                getId(
                    item?.unit
                ) ||
                "";


            normalizedItem.quantity =
                safeQuantity;


            normalizedItem.unitCost =
                safeUnitCost;


            normalizedItem.totalCost =
                safeQuantity *
                safeUnitCost;


            normalizedItem.donor =
                getId(
                    item?.donor
                ) ||
                null;


            normalizedItem.donation =
                getId(
                    item?.donation
                ) ||
                null;


            // Priced in another currency: edited as entered
            normalizedItem.currency =
                item?.currency || "ETB";

            normalizedItem.exchangeRate =
                normalizedItem.currency === "ETB"
                    ? null
                    : item?.exchangeRate ?? null;

            // ETB item paid from a foreign donation
            normalizedItem.donationRate =
                Number(item?.donationRate) > 0 ? Number(item.donationRate) : null;


            // Bought with this expense (not charged twice)
            normalizedItem.paidByExpense =
                getId(
                    item?.paidByExpense
                ) ||
                null;

            normalizedItem.separateFromExpenses =
                Array.isArray(item?.separateFromExpenses)
                    ? item.separateFromExpenses.map(value => getId(value)).filter(Boolean)
                    : [];


            normalizedItem.remarks =
                item?.remarks ||
                "";


            normalizedItem.detailItems =
                normalizeDetailItems(
                    item?.detailItems
                );


            normalizedItems.push(
                normalizedItem
            );

        }
    );


    return normalizedItems;

};


// =====================================================
// NORMALIZE ITEMS FOR SUBMISSION
// =====================================================

const normalizeItemsForSubmit = (
    items
) => {

    if (
        !Array.isArray(
            items
        )
    ) {

        return [];

    }


    const submittedItems =
        [];


    const usedIds =
        new Set();


    items.forEach(
        (
            item
        ) => {

            if (
                !item ||
                typeof item !== "object"
            ) {

                return;

            }


            let itemId =
                getId(
                    item?._id
                );


            if (
                !itemId
            ) {

                itemId =
                    getId(
                        item?.id
                    );

            }


            if (
                !itemId ||
                !isObjectIdLike(
                    itemId
                )
            ) {

                itemId =
                    generateObjectId();

            }


            let normalizedItemId =
                String(
                    itemId
                );


            while (
                usedIds.has(
                    normalizedItemId
                )
            ) {

                normalizedItemId =
                    generateObjectId();

            }


            usedIds.add(
                normalizedItemId
            );


            const serviceCategory =
                getId(
                    item?.serviceCategory
                );


            const serviceType =
                getId(
                    item?.serviceType
                );


            const unit =
                getId(
                    item?.unit
                );


            const quantity =
                Number(
                    item?.quantity ?? 1
                );


            const unitCost =
                Number(
                    item?.unitCost ?? 0
                );


            const safeQuantity =
                Number.isFinite(
                    quantity
                ) &&
                quantity > 0
                    ? quantity
                    : 1;


            const safeUnitCost =
                Number.isFinite(
                    unitCost
                ) &&
                unitCost >= 0
                    ? unitCost
                    : 0;


            const donor =
                getId(
                    item?.donor
                );


            const donation =
                getId(
                    item?.donation
                );


            const detailItems =
                normalizeDetailItemsForSubmit(
                    item?.detailItems
                );


            submittedItems.push({

                _id:
                    normalizedItemId,

                serviceCategory,

                serviceType,

                allocationBehavior:
                    item?.allocationBehavior ||
                    "CONSUMPTION",

                quantity:
                    safeQuantity,

                unit,

                unitCost:
                    safeUnitCost,

                totalCost:
                    safeQuantity *
                    safeUnitCost,

                donor:
                    donor ||
                    null,

                donation:
                    donation ||
                    null,

                currency:
                    item?.currency || "ETB",
                exchangeRate:
                    item?.exchangeRate ?? null,
                donationRate:
                    Number(item?.donationRate) > 0 ? Number(item.donationRate) : null,
                paidByExpense:
                    getId(
                        item?.paidByExpense
                    ) ||
                    null,
                separateFromExpenses:
                    Array.isArray(item?.separateFromExpenses)
                        ? item.separateFromExpenses.map(value => getId(value)).filter(Boolean)
                        : [],
                detailItems,

                remarks:
                    item?.remarks ||
                    ""

            });

        }
    );


    return submittedItems;

};


// =====================================================
// SERVICE ITEM ID SET
// =====================================================

const getServiceItemIdSet = (
    items
) => {

    const ids =
        new Set();


    if (
        !Array.isArray(
            items
        )
    ) {

        return ids;

    }


    items.forEach(
        (
            item
        ) => {

            const itemId =
                getId(
                    item?._id
                );


            if (
                itemId
            ) {

                ids.add(
                    String(
                        itemId
                    )
                );

            }

        }
    );


    return ids;

};


// =====================================================
// FIND ITEMS BY SERVICE TYPE
// =====================================================

const findItemsByServiceType = (
    items,
    serviceTypeId
) => {

    const normalizedServiceTypeId =
        getId(
            serviceTypeId
        );


    if (
        !normalizedServiceTypeId ||
        !Array.isArray(
            items
        )
    ) {

        return [];

    }


    return items.filter(
        (
            item
        ) =>
            String(
                getId(
                    item?.serviceType
                )
            ) ===
            String(
                normalizedServiceTypeId
            )
    );

};


// =====================================================
// CANONICALIZE ALLOCATIONS
// =====================================================

const canonicalizeBeneficiaryAllocations = (
    beneficiaries,
    items
) => {

    if (
        !Array.isArray(
            beneficiaries
        )
    ) {

        return {

            beneficiaries: [],

            errors: []

        };

    }


    const validItemIds =
        getServiceItemIdSet(
            items
        );


    const errors =
        [];


    const normalizedBeneficiaries =
        beneficiaries.map(
            (
                beneficiaryAssociation,
                beneficiaryIndex
            ) => {

                const allocations =
                    Array.isArray(
                        beneficiaryAssociation?.allocations
                    )
                        ? beneficiaryAssociation.allocations
                        : [];


                const normalizedAllocations =
                    allocations
                        .map(
                            (
                                allocation,
                                allocationIndex
                            ) => {

                                const originalId =
                                    getId(
                                        allocation?.serviceItem
                                    );


                                if (
                                    !originalId
                                ) {

                                    errors.push({

                                        beneficiaryIndex:
                                            beneficiaryIndex + 1,

                                        allocationIndex:
                                            allocationIndex + 1,

                                        reason:
                                            "Missing service item ID."

                                    });


                                    return null;

                                }


                                if (
                                    validItemIds.has(
                                        String(
                                            originalId
                                        )
                                    )
                                ) {

                                    const normalizedAllocation =
                                        Object.assign(
                                            {},
                                            allocation
                                        );


                                    normalizedAllocation.serviceItem =
                                        String(
                                            originalId
                                        );


                                    // Preserve detailItem exactly as an ID.
                                    normalizedAllocation.detailItem =
                                        getId(
                                            allocation?.detailItem
                                        ) ||
                                        null;


                                    return normalizedAllocation;

                                }


                                const matchingItems =
                                    findItemsByServiceType(
                                        items,
                                        originalId
                                    );


                                if (
                                    matchingItems.length ===
                                    1
                                ) {

                                    const matchedItem =
                                        matchingItems[0];


                                    const embeddedItemId =
                                        getId(
                                            matchedItem?._id
                                        );


                                    if (
                                        embeddedItemId
                                    ) {

                                        const repairedAllocation =
                                            Object.assign(
                                                {},
                                                allocation
                                            );


                                        repairedAllocation.serviceItem =
                                            String(
                                                embeddedItemId
                                            );


                                        repairedAllocation.detailItem =
                                            getId(
                                                allocation?.detailItem
                                            ) ||
                                            null;


                                        console.warn(
                                            "REPAIRED ALLOCATION SERVICE ITEM ID",
                                            {
                                                beneficiaryIndex:
                                                    beneficiaryIndex + 1,

                                                allocationIndex:
                                                    allocationIndex + 1,

                                                originalId,

                                                serviceType:
                                                    getId(
                                                        matchedItem?.serviceType
                                                    ),

                                                repairedServiceItem:
                                                    embeddedItemId,

                                                detailItem:
                                                    repairedAllocation.detailItem
                                            }
                                        );


                                        return repairedAllocation;

                                    }

                                }


                                errors.push({

                                    beneficiaryIndex:
                                        beneficiaryIndex + 1,

                                    allocationIndex:
                                        allocationIndex + 1,

                                    serviceItem:
                                        originalId,

                                    detailItem:
                                        getId(
                                            allocation?.detailItem
                                        ) ||
                                        null,

                                    reason:
                                        matchingItems.length > 1
                                            ? "Allocation matches multiple service items with the same service type."
                                            : "Allocation does not reference a service delivery item."

                                });


                                return null;

                            }
                        )
                        .filter(
                            Boolean
                        );


                const normalizedAssociation =
                    Object.assign(
                        {},
                        beneficiaryAssociation
                    );


                normalizedAssociation.allocations =
                    normalizedAllocations;


                return normalizedAssociation;

            }
        );


    return {

        beneficiaries:
            normalizedBeneficiaries,

        errors

    };

};

// =====================================================
// VALIDATE PARENT / DETAIL ALLOCATION CONFLICTS
// =====================================================

const validateParentDetailAllocationConflicts = (
    beneficiaries,
    items
) => {
    const errors = [];

    if (!Array.isArray(beneficiaries)) {
        return errors;
    }

    beneficiaries.forEach((association, beneficiaryIndex) => {
        const allocations = Array.isArray(association?.allocations)
            ? association.allocations
            : [];

        const allocationsByServiceItem = new Map();

        allocations.forEach((allocation) => {
            const serviceItemId = getId(allocation?.serviceItem);

            if (!serviceItemId) {
                return;
            }

            if (!allocationsByServiceItem.has(serviceItemId)) {
                allocationsByServiceItem.set(serviceItemId, []);
            }

            allocationsByServiceItem.get(serviceItemId).push(allocation);
        });

        allocationsByServiceItem.forEach((itemAllocations, serviceItemId) => {
            const hasParentAllocation = itemAllocations.some(
                (allocation) => !getId(allocation?.detailItem)
            );

            const hasDetailAllocation = itemAllocations.some(
                (allocation) => Boolean(getId(allocation?.detailItem))
            );

            if (hasParentAllocation && hasDetailAllocation) {
                const serviceItem = items.find(
                    (item) => getId(item?._id) === serviceItemId
                );

                errors.push({
                    beneficiaryIndex: beneficiaryIndex + 1,
                    serviceItemId,
                    serviceItemName:
                        serviceItem?.serviceType?.name ||
                        serviceItem?.name ||
                        `Service item ${serviceItemId}`,
                    reason:
                        "This beneficiary has both a parent-item allocation and a detail-item allocation for the same service item."
                });
            }
        });
    });

    return errors;
};

// =====================================================
// VALIDATE ALLOCATION ITEM IDS
// =====================================================

const validateBeneficiaryAllocationItemIds = (
    beneficiaries,
    items
) => {

    const validItemIds =
        getServiceItemIdSet(
            items
        );


    const invalidAllocations =
        [];


    if (
        !Array.isArray(
            beneficiaries
        )
    ) {

        return invalidAllocations;

    }


    beneficiaries.forEach(
        (
            beneficiaryAssociation,
            beneficiaryIndex
        ) => {

            const allocations =
                Array.isArray(
                    beneficiaryAssociation?.allocations
                )
                    ? beneficiaryAssociation.allocations
                    : [];


            allocations.forEach(
                (
                    allocation,
                    allocationIndex
                ) => {

                    const allocationItemId =
                        getId(
                            allocation?.serviceItem
                        );


                    if (
                        !allocationItemId ||
                        !validItemIds.has(
                            String(
                                allocationItemId
                            )
                        )
                    ) {

                        invalidAllocations.push({

                            beneficiaryIndex:
                                beneficiaryIndex + 1,

                            allocationIndex:
                                allocationIndex + 1,

                            serviceItem:
                                allocationItemId ||
                                null,

                            detailItem:
                                getId(
                                    allocation?.detailItem
                                ) ||
                                null

                        });

                    }

                }
            );

        }
    );


    return invalidAllocations;

};


// =====================================================
// DOCUMENTS
// =====================================================

const normalizeDocuments = (
    documents
) => {

    if (
        !Array.isArray(
            documents
        )
    ) {

        return [];

    }


    return documents.map(
        (
            document
        ) => {

            if (
                typeof document === "string"
            ) {

                return document;

            }


            return Object.assign(
                {},
                document
            );

        }
    );

};


// =====================================================
// SERVICE DELIVERY EDIT STATE SEMANTICS
// =====================================================

const normalizeRecipientType = (
    value
) => {

    return (
        value ||
        "Individual"
    );

};


const normalizeAllocationMethod = (
    value
) => {

    return (
        value ||
        "Individual"
    );

};


// =====================================================
// CLEAR BENEFICIARY STATE
// =====================================================

const clearBeneficiaryState = (
    state
) => {

    const next =
        Object.assign(
            {},
            state
        );


    next.beneficiaries =
        [];


    next.beneficiary =
        "";


    next.enrollment =
        null;


    return next;

};


// =====================================================
// CLEAR BENEFICIARY ALLOCATIONS ONLY
// =====================================================

const clearBeneficiaryAllocations = (
    state
) => {

    const next =
        Object.assign(
            {},
            state
        );


    if (
        Array.isArray(
            next.beneficiaries
        )
    ) {

        next.beneficiaries =
            next.beneficiaries.map(
                (
                    association
                ) => {

                    return Object.assign(
                        {},
                        association,
                        {
                            allocations:
                                []
                        }
                    );

                }
            );

    }


    return next;

};


// =====================================================
// APPLY RECIPIENT TYPE TRANSITION
// =====================================================

const applyRecipientTypeTransition = (
    previous,
    next
) => {

    const previousRecipientType =
        normalizeRecipientType(
            previous?.recipientType
        );


    const nextRecipientType =
        normalizeRecipientType(
            next?.recipientType
        );


    if (
        previousRecipientType ===
        nextRecipientType
    ) {

        return next;

    }


    return clearBeneficiaryState(
        next
    );

};


// =====================================================
// APPLY ALLOCATION METHOD TRANSITION
// =====================================================

const applyAllocationMethodTransition = (
    previous,
    next
) => {

    const previousAllocationMethod =
        normalizeAllocationMethod(
            previous?.allocationMethod
        );


    const nextAllocationMethod =
        normalizeAllocationMethod(
            next?.allocationMethod
        );


    if (
        previousAllocationMethod ===
        nextAllocationMethod
    ) {

        return next;

    }


    if (
        nextAllocationMethod ===
        "Group"
    ) {

        return clearBeneficiaryState(
            next
        );

    }


    if (
        nextAllocationMethod ===
        "Unallocated"
    ) {

        return clearBeneficiaryState(
            next
        );

    }


    if (
        nextAllocationMethod ===
        "Shared"
    ) {

        return clearBeneficiaryAllocations(
            next
        );

    }


    if (
        nextAllocationMethod ===
        "Individual"
    ) {

        return next;

    }


    return next;

};


// =====================================================
// APPLY FULL SEMANTIC TRANSITION
// =====================================================

const applyServiceDeliveryStateSemantics = (
    previous,
    next
) => {

    let result =
        Object.assign(
            {},
            next
        );


    result =
        applyRecipientTypeTransition(
            previous,
            result
        );


    result =
        applyAllocationMethodTransition(
            previous,
            result
        );


    const finalAllocationMethod =
        normalizeAllocationMethod(
            result?.allocationMethod
        );


    if (
        finalAllocationMethod ===
            "Group" ||
        finalAllocationMethod ===
            "Unallocated"
    ) {

        if (
            Array.isArray(
                result?.beneficiaries
            )
        ) {

            result.beneficiaries =
                result.beneficiaries.map(
                    (
                        association
                    ) =>
                        Object.assign(
                            {},
                            association,
                            {
                                allocations:
                                    []
                            }
                        )
                );

        }

    }


    return result;

};


// =====================================================
// PAGE
// =====================================================

import useDuplicateCheck
    from "../components/useDuplicateCheck";


const ServiceDeliveryEditPage = () => {

    // humanitarian module: the same people, the same service, the same period
    const [saveChecked, duplicateDialog] =
        useDuplicateCheck();

    const {
        id
    } = useParams();


    const navigate =
        useNavigate();


    const [
        loading,
        setLoading
    ] = useState(
        true
    );


    const [
        saving,
        setSaving
    ] = useState(
        false
    );


    const [
        formData,
        setFormData
    ] = useState(
        null
    );


    const [
        beneficiaries,
        setBeneficiaries
    ] = useState(
        []
    );


    const [
        programs,
        setPrograms
    ] = useState(
        []
    );


    const [
        projects,
        setProjects
    ] = useState(
        []
    );


    const [
        activities,
        setActivities
    ] = useState(
        []
    );


    const [
        activityRuns,
        setActivityRuns
    ] = useState(
        []
    );


    const [
        serviceCategories,
        setServiceCategories
    ] = useState(
        []
    );


    const [
        units,
        setUnits
    ] = useState(
        []
    );


    // =================================================
    // EDIT FORM STATE WRAPPER
    // =================================================

    const handleFormDataChange = (
        update
    ) => {

        setFormData(
            (
                previous
            ) => {

                if (
                    typeof update ===
                    "function"
                ) {

                    const next =
                        update(
                            previous
                        );


                    if (
                        !next
                    ) {

                        return next;

                    }


                    return applyServiceDeliveryStateSemantics(
                        previous,
                        next
                    );

                }


                if (
                    !update
                ) {

                    return update;

                }


                return applyServiceDeliveryStateSemantics(
                    previous,
                    update
                );

            }
        );

    };


    // =================================================
    // LOAD BENEFICIARIES
    // =================================================

    // a project: only the people enrolled in it (and those already on
    // the delivery); only a program: anyone enrolled in its projects
    const loadBeneficiariesByProgram = async (
        programId,
        keepSelected = [],
        projectId = ""
    ) => {

        if (
            !programId
        ) {

            setBeneficiaries(
                []
            );

            return;

        }


        try {

            const response =
                await getBeneficiariesLookupService(
                    programId,
                    [],
                    projectId ? String(projectId) : ""
                );


            const lookupBeneficiaries =
                normalizeArray(
                    response
                );


            const existingObjects =
                Array.isArray(
                    keepSelected
                )
                    ? keepSelected
                        .map(
                            (
                                item
                            ) =>
                                item?.beneficiary ||
                                item
                        )
                        .filter(
                            Boolean
                        )
                    : [];


            const lookupIds =
                new Set(
                    lookupBeneficiaries
                        .map(
                            getBeneficiaryId
                        )
                        .filter(
                            Boolean
                        )
                        .map(
                            (
                                value
                            ) =>
                                String(
                                    value
                                )
                        )
                );


            const missingObjects =
                existingObjects.filter(
                    (
                        item
                    ) => {

                        const beneficiaryId =
                            getBeneficiaryId(
                                item
                            );


                        return (
                            beneficiaryId &&
                            !lookupIds.has(
                                String(
                                    beneficiaryId
                                )
                            )
                        );

                    }
                );


            const mergedBeneficiaries =
                lookupBeneficiaries.concat(
                    missingObjects
                );


            const uniqueBeneficiaries =
                [];


            const seenIds =
                new Set();


            mergedBeneficiaries.forEach(
                (
                    item
                ) => {

                    const beneficiaryId =
                        getBeneficiaryId(
                            item
                        );


                    if (
                        !beneficiaryId
                    ) {

                        return;

                    }


                    const normalizedId =
                        String(
                            beneficiaryId
                        );


                    if (
                        seenIds.has(
                            normalizedId
                        )
                    ) {

                        return;

                    }


                    seenIds.add(
                        normalizedId
                    );


                    uniqueBeneficiaries.push(
                        item
                    );

                }
            );


            setBeneficiaries(
                uniqueBeneficiaries
            );

        }

        catch (
            error
        ) {

            console.error(
                "Failed loading beneficiaries:",
                error
            );


            setBeneficiaries(
                []
            );

        }

    };


    // =================================================
    // LOAD DATA
    // =================================================

    const loadData = async () => {

        try {

            setLoading(
                true
            );


            const [
                deliveryResponse,
                programResponse,
                projectResponse,
                activityResponse,
                activityRunResponse,
                categoryResponse,
                unitResponse
            ] = await Promise.all([

                getServiceDeliveryByIdService(
                    id
                ),

                getProgramsService(),

                getProjectsService(),

                getActivitiesService(),

                getActivityRunsService(),

                getLookupOptionsService(
                    "ServiceCategory"
                ),

                getLookupOptionsService(
                    "Unit"
                )

            ]);


            const delivery =
                getResponseData(
                    deliveryResponse
                );


            if (
                !delivery
            ) {

                setFormData(
                    null
                );

                return;

            }








            // =============================================
            // IDS
            // =============================================

            const programId =
                getId(
                    delivery?.program
                );


            const projectId =
                getId(
                    delivery?.project
                );


            const activityId =
                getId(
                    delivery?.activity
                );


            const activityRunId =
                getId(
                    delivery?.activityRun
                );


            const enrollmentId =
                getId(
                    delivery?.enrollment
                );


            const fundingSourceId =
                getId(
                    delivery?.fundingSource
                );


            const donationId =
                getId(
                    delivery?.donation
                );


            const deliveredById =
                getId(
                    delivery?.deliveredBy
                );


            // =============================================
            // ITEMS
            // =============================================

            const rawItems =
                Array.isArray(
                    delivery?.items
                )
                    ? delivery.items
                    : [];


            const normalizedItems =
                normalizeItems(
                    rawItems
                );






            // =============================================
            // EXISTING BENEFICIARIES
            // =============================================

            const existingBeneficiaryAssociations =
                normalizeExistingBeneficiaries(
                    delivery
                );


            const existingBeneficiaryObjects =
                getExistingBeneficiaryObjects(
                    delivery
                );


            if (
                programId
            ) {

                await loadBeneficiariesByProgram(
                    programId,
                    existingBeneficiaryObjects,
                    delivery?.project?._id || delivery?.project || ""
                );

            }


            // =============================================
            // LOOKUPS
            // =============================================

            const normalizedCategories =
                normalizeArray(
                    categoryResponse
                );


            const normalizedUnits =
                normalizeArray(
                    unitResponse
                );






            // =============================================
            // NORMALIZED DELIVERY
            // =============================================

            const normalizedDelivery =
                Object.assign(
                    {},
                    delivery
                );


            normalizedDelivery._id =
                getId(
                    delivery?._id
                ) ||
                id;


            normalizedDelivery.deliveryNumber =
                delivery?.deliveryNumber ||
                "";


            normalizedDelivery.recipientType =
                delivery?.recipientType ||
                "Individual";


            normalizedDelivery.recipientName =
                typeof delivery?.recipientName ===
                "string"
                    ? delivery.recipientName
                    : "";


            normalizedDelivery.allocationMethod =
                delivery?.allocationMethod ||
                "Individual";


            normalizedDelivery.program =
                programId;


            normalizedDelivery.project =
                projectId;


            normalizedDelivery.activity =
                activityId;


            normalizedDelivery.activityRun =
                activityRunId;


            normalizedDelivery.beneficiaries =
                existingBeneficiaryAssociations;


            normalizedDelivery.beneficiary =
                getBeneficiaryId(
                    delivery?.beneficiary
                ) ||
                "";


            normalizedDelivery.enrollment =
                enrollmentId ||
                null;


            normalizedDelivery.fundingSource =
                fundingSourceId ||
                null;


            normalizedDelivery.donation =
                donationId ||
                null;


            normalizedDelivery.deliveryDate =
                normalizeDate(
                    delivery?.deliveryDate
                );


            normalizedDelivery.region =
                delivery?.region ||
                "";

            normalizedDelivery.regionCode =
                delivery?.regionCode ||
                "";

            normalizedDelivery.zone =
                delivery?.zone ||
                "";

            normalizedDelivery.zoneCode =
                delivery?.zoneCode ||
                "";

            normalizedDelivery.woreda =
                delivery?.woreda ||
                "";

            normalizedDelivery.woredaCode =
                delivery?.woredaCode ||
                "";

            normalizedDelivery.deliveryLocation =
                delivery?.deliveryLocation ||
                "";


            normalizedDelivery.status =
                delivery?.status ||
                "Delivered";


            normalizedDelivery.deliveredBy =
                deliveredById ||
                null;


            normalizedDelivery.documents =
                normalizeDocuments(
                    delivery?.documents
                );


            normalizedDelivery.items =
                normalizedItems;


            normalizedDelivery.totalAmount =
                Number(
                    delivery?.totalAmount ?? 0
                );


            setPrograms(
                normalizeArray(
                    programResponse
                )
            );


            setProjects(
                normalizeArray(
                    projectResponse
                )
            );


            setActivities(
                normalizeArray(
                    activityResponse
                )
            );


            setActivityRuns(
                normalizeArray(
                    activityRunResponse
                )
            );


            setServiceCategories(
                normalizedCategories
            );


            setUnits(
                normalizedUnits
            );


            setFormData(
                normalizedDelivery
            );

        }

        catch (
            error
        ) {

            console.error(
                "Failed loading service delivery:",
                error
            );


            console.error(
                "Backend response:",
                error?.response?.data
            );


            setFormData(
                null
            );

        }

        finally {

            setLoading(
                false
            );

        }

    };


    // =================================================
    // LOAD
    // =================================================

    useEffect(
        () => {

            if (
                !id
            ) {

                setLoading(
                    false
                );

                return;

            }


            loadData();

        },
        [
            id
        ]
    );


    // another project chosen: offer the people enrolled in it,
    // keeping those already on the delivery
    const lastProject =
        useRef(null);

    useEffect(
        () => {

            const projectId =
                String(formData?.project || "");

            if (loading) return;

            if (lastProject.current === null) {
                lastProject.current = projectId;
                return;
            }

            if (lastProject.current === projectId) return;

            lastProject.current = projectId;

            const chosen =
                new Set((formData?.beneficiaries || []).map(record => String(record?.beneficiary?._id || record?.beneficiary || record?._id || record || "")));

            if (formData?.program) {
                loadBeneficiariesByProgram(
                    formData.program,
                    beneficiaries.filter(person => chosen.has(String(person?._id))),
                    projectId
                );
            }

        },
        // eslint-disable-next-line react-hooks/exhaustive-deps
        [
            formData?.project,
            loading
        ]
    );


    // =================================================
    // PROGRAM CHANGE
    // =================================================

    const handleProgramChange = async (
        programId
    ) => {

        const normalizedProgramId =
            getId(
                programId
            );


        handleFormDataChange(
            (
                previous
            ) => {

                if (
                    !previous
                ) {

                    return previous;

                }


                const next =
                    Object.assign(
                        {},
                        previous
                    );


                next.program =
                    normalizedProgramId;


                next.beneficiaries =
                    [];


                next.beneficiary =
                    "";


                next.enrollment =
                    null;


                next.project =
                    "";


                next.activity =
                    "";


                next.activityRun =
                    "";


                return next;

            }
        );


        await loadBeneficiariesByProgram(
            normalizedProgramId
        );

    };


    // =================================================
    // SUBMIT
    // =================================================

    const handleSubmit = async (
        data
    ) => {

        try {

            setSaving(
                true
            );


            const recipientType =
                data?.recipientType ||
                "Individual";


            const recipientName =
                typeof data?.recipientName ===
                "string"
                    ? data.recipientName.trim()
                    : "";


            const allocationMethod =
                data?.allocationMethod ||
                "Individual";


            // =============================================
            // RECIPIENT IDENTITY
            // =============================================

            const recipientNameRequired =
                recipientType ===
                    "Household" ||
                recipientType ===
                    "Group / Community" ||
                recipientType ===
                    "Institution";


            if (
                recipientNameRequired &&
                !recipientName
            ) {

                const label =
                    recipientType ===
                        "Household"
                        ? "Household name or identifier"
                        : recipientType ===
                            "Group / Community"
                            ? "Group / Community name"
                            : "Institution name";


                alert(
                    `Please enter the ${label}.`
                );


                return;

            }


            // =============================================
            // BENEFICIARIES
            // =============================================

            const rawBeneficiaryAssociations =
                Array.isArray(
                    data?.beneficiaries
                )
                    ? data.beneficiaries
                        .map(
                            normalizeBeneficiaryAssociation
                        )
                        .filter(
                            Boolean
                        )
                    : [];


            // =============================================
            // ITEMS
            // =============================================

            const items =
                normalizeItemsForSubmit(
                    data?.items
                );






            if (
                items.length === 0
            ) {

                alert(
                    "At least one service item is required."
                );


                return;

            }


            // =============================================
            // DETAIL ITEM VALIDATION
            // =============================================

            const invalidDetailItem =
                items.find(
                    (
                        item
                    ) => {

                        const detailItems =
                            Array.isArray(
                                item?.detailItems
                            )
                                ? item.detailItems
                                : [];


                        return detailItems.some(
                            (
                                detailItem
                            ) => {

                                return (

                                    !String(
                                        detailItem?.name ||
                                        ""
                                    ).trim() ||

                                    !Number.isFinite(
                                        Number(
                                            detailItem?.quantity
                                        )
                                    ) ||

                                    Number(
                                        detailItem?.quantity
                                    ) < 1 ||

                                    !Number.isFinite(
                                        Number(
                                            detailItem?.unitCost
                                        )
                                    ) ||

                                    Number(
                                        detailItem?.unitCost
                                    ) < 0

                                );

                            }
                        );

                    }
                );


            if (
                invalidDetailItem
            ) {

                alert(
                    "Every detail item requires a name, valid quantity, and valid unit cost."
                );


                console.error(
                    "INVALID DETAIL ITEM:",
                    invalidDetailItem
                );


                return;

            }


            // =============================================
            // ITEM VALIDATION
            // =============================================

            const invalidItem =
                items.find(
                    (
                        item
                    ) => {

                        return (

                            !item.serviceCategory ||

                            !item.serviceType ||

                            !item.unit ||

                            !Number.isFinite(
                                item.quantity
                            ) ||

                            item.quantity < 1 ||

                            !Number.isFinite(
                                item.unitCost
                            ) ||

                            item.unitCost < 0

                        );

                    }
                );


            if (
                invalidItem
            ) {

                alert(
                    "Every service item requires a valid category, service type, unit, quantity, and unit cost."
                );


                console.error(
                    "INVALID ITEM:",
                    invalidItem
                );


                return;

            }


            // =============================================
            // ITEM ID VALIDATION
            // =============================================

            const invalidObjectIdItem =
                items.find(
                    (
                        item
                    ) =>
                        !isObjectIdLike(
                            getId(
                                item?._id
                            )
                        )
                );


            if (
                invalidObjectIdItem
            ) {

                alert(
                    "One or more service items do not have a valid item ID. Please refresh the page and try again."
                );


                console.error(
                    "INVALID SERVICE ITEM OBJECT ID:",
                    invalidObjectIdItem
                );


                return;

            }


            const itemIds =
                getServiceItemIdSet(
                    items
                );


            if (
                itemIds.size !==
                items.length
            ) {

                console.error(
                    "SERVICE ITEM ID INTEGRITY ERROR:",
                    {
                        itemCount:
                            items.length,

                        uniqueItemIdCount:
                            itemIds.size,

                        items
                    }
                );


                alert(
                    "The service item data contains duplicate IDs. Please reload the edit page before saving."
                );


                return;

            }


            // =============================================
            // CANONICALIZE ALLOCATIONS
            // =============================================

            const canonicalizedAllocationResult =
                canonicalizeBeneficiaryAllocations(
                    rawBeneficiaryAssociations,
                    items
                );


            if (
                canonicalizedAllocationResult.errors.length >
                0
            ) {

                console.error(
                    "COULD NOT CANONICALIZE BENEFICIARY ALLOCATIONS:",
                    {

                        errors:
                            canonicalizedAllocationResult.errors,

                        items,

                        beneficiaries:
                            rawBeneficiaryAssociations

                    }
                );


                alert(
                    "One or more beneficiary allocations cannot be matched safely to a service item in this delivery."
                );


                return;

            }


            const beneficiaryAssociations =
                canonicalizedAllocationResult.beneficiaries;




// =============================================
// PARENT / DETAIL ALLOCATION VALIDATION
// =============================================

const allocationConflicts =
    validateParentDetailAllocationConflicts(
        beneficiaryAssociations,
        items
    );

if (allocationConflicts.length > 0) {
    console.error(
        "PARENT / DETAIL ALLOCATION CONFLICTS:",
        allocationConflicts
    );

    const conflictMessages = allocationConflicts.map(
        (conflict) =>
            `Beneficiary ${conflict.beneficiaryIndex}: ${conflict.serviceItemName}`
    );

    alert(
        "Cannot save this service delivery because one or more beneficiaries have both a parent-item allocation and detail-item allocations for the same service item.\n\n" +
        conflictMessages.join("\n") +
        "\n\nOpen the beneficiary allocation section and keep either the parent allocation or the detail allocations for that service item. The delivered quantity and cost will not be changed."
    );

    return;
}

            // =============================================
            // FINAL ALLOCATION VALIDATION
            // =============================================

            const invalidAllocations =
                validateBeneficiaryAllocationItemIds(
                    beneficiaryAssociations,
                    items
                );


            if (
                invalidAllocations.length > 0
            ) {

                console.error(
                    "INVALID BENEFICIARY ALLOCATION ITEM IDS:",
                    {

                        invalidAllocations,

                        validItemIds:
                            Array.from(
                                itemIds
                            ),

                        beneficiaries:
                            beneficiaryAssociations,

                        items

                    }
                );


                alert(
                    "One or more beneficiary allocations reference a service item that is no longer part of this delivery."
                );


                return;

            }


            // =============================================
            // BENEFICIARY REQUIREMENT
            // =============================================

            const requiresBeneficiaries =
                recipientType ===
                    "Individual" &&
                (
                    allocationMethod ===
                        "Individual" ||
                    allocationMethod ===
                        "Shared"
                );


            if (
                requiresBeneficiaries &&
                beneficiaryAssociations.length === 0
            ) {

                alert(
                    "At least one beneficiary is required for individual recipient delivery."
                );


                return;

            }


            // =============================================
            // PAYLOAD
            // =============================================

            const payload = {

                recipientType,

                recipientName,

                allocationMethod,

                beneficiaries:
                    beneficiaryAssociations,

                beneficiary:
                    getBeneficiaryId(
                        data?.beneficiary
                    ) ||
                    null,

                enrollment:
                    getId(
                        data?.enrollment
                    ) ||
                    null,

                program:
                    getId(
                        data?.program
                    ),

                project:
                    getId(
                        data?.project
                    ) ||
                    null,

                activity:
                    getId(
                        data?.activity
                    ) ||
                    null,

                activityRun:
                    getId(
                        data?.activityRun
                    ) ||
                    null,

                fundingSource:
                    getId(
                        data?.fundingSource
                    ) ||
                    null,

                donation:
                    getId(
                        data?.donation
                    ) ||
                    null,

                deliveryDate:
                    data?.deliveryDate ||
                    null,

                region:
                    data?.region ||
                    "",

                regionCode:
                    data?.regionCode ||
                    "",

                zone:
                    data?.zone ||
                    "",

                zoneCode:
                    data?.zoneCode ||
                    "",

                woreda:
                    data?.woreda ||
                    "",

                woredaCode:
                    data?.woredaCode ||
                    "",

                deliveryLocation:
                    data?.deliveryLocation ||
                    "",

                status:
                    data?.status ||
                    "Delivered",

                deliveredBy:
                    getId(
                        data?.deliveredBy
                    ) ||
                    null,

                documents:
                    Array.isArray(
                        data?.documents
                    )
                        ? data.documents
                        : [],

                items

            };




            // =============================================
            // PROGRAM
            // =============================================

            if (
                !payload.program
            ) {

                alert(
                    "Program is required."
                );


                return;

            }


            // =============================================
            // UPDATE
            // =============================================

            await saveChecked(
                (body) => updateServiceDeliveryService(id, body),
                payload
            );


            // =============================================
            // SUCCESS
            // =============================================

            navigate(
                `/service-deliveries/${id}`
            );

        }

        catch (
            error
        ) {

            // went back from the duplicate check: nothing to report
            if (error?.cancelled) return;

            console.error(
                "Failed updating service delivery:",
                error
            );


            console.error(
                "FULL BACKEND RESPONSE:",
                error?.response?.data
            );


            console.error(
                "VALIDATION ERRORS:",
                error?.response?.data?.errors
            );


            alert(
                error?.response?.data?.message ||
                error?.message ||
                "Failed to update service delivery."
            );

        }

        finally {

            setSaving(
                false
            );

        }

    };


    // =================================================
    // LOADING
    // =================================================

    if (
        loading
    ) {

        return (

            <PageContainer>

                <PageHeader
                    title="Edit Service Delivery"
                    subtitle="Loading service delivery information"
                />

                <LoadingState
                    message="Loading service delivery..."
                />

            </PageContainer>

        );

    }


    // =================================================
    // NOT FOUND
    // =================================================

    if (
        !formData
    ) {

        return (

            <PageContainer>

                <PageHeader
                    title="Edit Service Delivery"
                    subtitle="Service delivery record could not be found."
                />

                <PageCard>

                    <FormSection
                        title="Record Not Found"
                    >

                        <InfoRow
                            label="Service Delivery"
                            value="No service delivery information available."
                        />

                    </FormSection>

                </PageCard>


                <AppButton

                    type="button"

                    variant="outlined"

                    startIcon={
                        <ArrowBack />
                    }

                    onClick={
                        () =>
                            navigate(
                                "/service-deliveries"
                            )
                    }

                    sx={{
                        mt:
                            3,

                        mb:
                            5
                    }}

                >

                    Back to Service Deliveries

                </AppButton>

            </PageContainer>

        );

    }


    // =================================================
    // PAGE
    // =================================================

    return (

        <PageContainer>

            <PageHeader

                title="Edit Service Delivery"

                subtitle={
                    formData.deliveryNumber ||
                    "Update service delivery record"
                }

                action={() =>
                    navigate(
                        `/service-deliveries/${id}`
                    )
                }

                actionLabel="Back"

                actionIcon={
                    <ArrowBack />
                }

            />


            <PageCard>

                <FormSection
                    title="Service Delivery Information"
                >

                    <InfoRow
                        label="Delivery Number"
                        value={
                            formData.deliveryNumber ||
                            "-"
                        }
                    />


                    <InfoRow
                        label="Recipient Type"
                        value={
                            formData.recipientType ||
                            "Individual"
                        }
                    />


                    <InfoRow
                        label="Recipient Identity"
                        value={
                            formData.recipientName ||
                            (
                                formData.recipientType ===
                                "Individual"
                                    ? "Beneficiary-based"
                                    : "-"
                            )
                        }
                    />


                    <InfoRow
                        label="Allocation Method"
                        value={
                            formData.allocationMethod ||
                            "Individual"
                        }
                    />


                    <InfoRow
                        label="Status"
                        value={
                            formData.status ||
                            "Delivered"
                        }
                    />

                </FormSection>

            </PageCard>


            <PageCard>

                <ServiceDeliveryForm

                    formData={
                        formData
                    }

                    setFormData={
                        handleFormDataChange
                    }

                    beneficiaries={
                        beneficiaries
                    }

                    programs={
                        programs
                    }

                    projects={
                        projects
                    }

                    activities={
                        activities
                    }

                    activityRuns={
                        activityRuns
                    }

                    serviceCategories={
                        serviceCategories
                    }

                    units={
                        units
                    }

                    onProgramChange={
                        handleProgramChange
                    }

                    onSubmit={
                        handleSubmit
                    }

                    loading={
                        saving
                    }

                />

            </PageCard>

            {duplicateDialog}

        </PageContainer>

    );

};


export default ServiceDeliveryEditPage;