import {
    useMemo
} from "react";

import {
    Box,
    Typography,
    Divider,
    TextField,
    Paper
} from "@mui/material";

import {
    AppButton
} from "../../../components/ui";


// =====================================================
// MONETARY UNIT CODES
// =====================================================

const MONETARY_UNIT_CODES = [

    "AMOUNT",

    "ETB",

    "BIRR",

    "MONEY",

    "CASH"

];


// =====================================================
// PHYSICAL UNIT CODES
// =====================================================

const PHYSICAL_UNIT_CODES = [

    "PIECE",

    "PCS",

    "BOX",

    "KG",

    "KILOGRAM",

    "LITER",

    "LITRE",

    "METER",

    "SESSION",

    "DAY",

    "HOUR",

    "PACK",

    "PAIR",

    "SET",

    "UNIT"

];


// =====================================================
// ALLOCATION BEHAVIORS
// =====================================================

const CONSUMPTION =
    "CONSUMPTION";

const PARTICIPATION =
    "PARTICIPATION";


// =====================================================
// NORMALIZE TEXT
// =====================================================

const normalizeText = (
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
    )
        .trim()
        .toUpperCase();

};


// =====================================================
// NORMALIZE ALLOCATION BEHAVIOR
// =====================================================

const normalizeAllocationBehavior = (
    value
) => {

    const normalized =
        normalizeText(
            value
        );

    if (
        normalized ===
        PARTICIPATION
    ) {

        return PARTICIPATION;

    }

    return CONSUMPTION;

};


// =====================================================
// OBJECT ID CHECK
// =====================================================

const isObjectIdLike = (
    value
) => {

    if (
        value === undefined ||
        value === null
    ) {

        return false;

    }

    const text =
        String(
            value
        ).trim();

    return /^[a-fA-F0-9]{24}$/.test(
        text
    );

};


// =====================================================
// NORMALIZE ID
// =====================================================

const normalizeId = (
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
        typeof value === "object"
    ) {

        return String(
            value?._id ??
            value?.id ??
            value?.value ??
            value?.lookupId ??
            ""
        );

    }

    return String(
        value
    );

};


// =====================================================
// GET BENEFICIARY ID
// =====================================================

const getBeneficiaryId = (
    beneficiary
) => {

    if (
        !beneficiary
    ) {

        return "";

    }

    if (
        typeof beneficiary === "string"
    ) {

        return beneficiary;

    }

    return normalizeId(
        beneficiary?.beneficiary ??
        beneficiary?._id ??
        beneficiary?.id ??
        beneficiary?.value
    );

};


// =====================================================
// GET BENEFICIARY NAME
// =====================================================

const getBeneficiaryName = (
    beneficiary,
    beneficiaryOptions
) => {

    const beneficiaryId =
        getBeneficiaryId(
            beneficiary
        );

    const options =
        Array.isArray(
            beneficiaryOptions
        )
            ? beneficiaryOptions
            : [];

    const option =
        options.find(
            (
                item
            ) =>
                String(
                    normalizeId(
                        item
                    )
                ) ===
                String(
                    beneficiaryId
                )
        );

    if (
        option?.label
    ) {

        return String(
            option.label
        );

    }

    if (
        typeof beneficiary ===
        "object"
    ) {

        const actualBeneficiary =
            beneficiary?.beneficiary &&
            typeof beneficiary.beneficiary ===
            "object"
                ? beneficiary.beneficiary
                : beneficiary;

        const fullName =
            [
                actualBeneficiary?.firstName,
                actualBeneficiary?.middleName,
                actualBeneficiary?.lastName
            ]
                .filter(
                    Boolean
                )
                .join(
                    " "
                );

        if (
            fullName
        ) {

            return fullName;

        }

        return (
            actualBeneficiary?.fullName ||
            actualBeneficiary?.beneficiaryNumber ||
            actualBeneficiary?.name ||
            "Beneficiary"
        );

    }

    return "Beneficiary";

};


// =====================================================
// GET SERVICE ITEM ID
// =====================================================

const getServiceItemId = (
    item
) => {

    if (
        !item
    ) {

        return "";

    }

    return normalizeId(
        item?._id ??
        item?.id ??
        ""
    );

};


// =====================================================
// GET ALLOCATION SERVICE ITEM ID
// =====================================================

const getAllocationServiceItemId = (
    allocation
) => {

    return normalizeId(
        allocation?.serviceItem
    );

};


// =====================================================
// GET ALLOCATION DETAIL ITEM ID
// =====================================================

const getAllocationDetailItemId = (
    allocation
) => {

    return normalizeId(
        allocation?.detailItem
    );

};


// =====================================================
// GET DIRECT ALLOCATION
// =====================================================

const getDirectAllocation = (
    beneficiary,
    serviceItemId
) => {

    if (
        !beneficiary ||
        !Array.isArray(
            beneficiary?.allocations
        )
    ) {

        return null;

    }

    return (
        beneficiary.allocations.find(
            (
                allocation
            ) =>
                String(
                    getAllocationServiceItemId(
                        allocation
                    )
                ) ===
                String(
                    serviceItemId
                ) &&
                !getAllocationDetailItemId(
                    allocation
                )
        ) ||
        null
    );

};


// =====================================================
// GET DETAIL ALLOCATION
// =====================================================

const getDetailAllocation = (
    beneficiary,
    serviceItemId,
    detailItemId
) => {

    if (
        !beneficiary ||
        !Array.isArray(
            beneficiary?.allocations
        )
    ) {

        return null;

    }

    return (
        beneficiary.allocations.find(
            (
                allocation
            ) =>
                String(
                    getAllocationServiceItemId(
                        allocation
                    )
                ) ===
                String(
                    serviceItemId
                ) &&
                String(
                    getAllocationDetailItemId(
                        allocation
                    )
                ) ===
                String(
                    detailItemId
                )
        ) ||
        null
    );

};


// =====================================================
// GET SERVICE ITEM ALLOCATIONS
// =====================================================

const getServiceItemAllocations = (
    beneficiary,
    serviceItemId
) => {

    if (
        !beneficiary ||
        !Array.isArray(
            beneficiary?.allocations
        )
    ) {

        return [];

    }

    return beneficiary.allocations.filter(
        (
            allocation
        ) =>
            String(
                getAllocationServiceItemId(
                    allocation
                )
            ) ===
            String(
                serviceItemId
            )
    );

};


// =====================================================
// GET DIRECT SERVICE ITEM ALLOCATIONS ONLY
// =====================================================
//
// IMPORTANT:
// Detail Item allocations must NOT be counted as
// parent Service Item allocations.
//
// Parent allocation:
//   serviceItem = X
//   detailItem  = null
//
// Detail allocation:
//   serviceItem = X
//   detailItem  = Y
//
// These are intentionally kept separate.
//

const getDirectServiceItemAllocations = (
    beneficiary,
    serviceItemId
) => {

    if (
        !beneficiary ||
        !Array.isArray(
            beneficiary?.allocations
        )
    ) {

        return [];

    }

    return beneficiary.allocations.filter(
        (
            allocation
        ) =>
            String(
                getAllocationServiceItemId(
                    allocation
                )
            ) ===
            String(
                serviceItemId
            ) &&
            !getAllocationDetailItemId(
                allocation
            )
    );

};


// =====================================================
// GET LOOKUP DISPLAY VALUE
// =====================================================

const getLookupDisplayValue = (
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
        typeof value === "object"
    ) {

        const displayValue =
            value?.label ??
            value?.name ??
            value?.text ??
            value?.value ??
            value?.code ??
            "";

        if (
            typeof displayValue === "object"
        ) {

            return getLookupDisplayValue(
                displayValue
            );

        }

        return String(
            displayValue
        );

    }

    return String(
        value
    );

};


// =====================================================
// GET LOOKUP ID
// =====================================================

const getLookupId = (
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
        typeof value === "object"
    ) {

        return normalizeId(
            value?._id ??
            value?.id ??
            value?.lookupId ??
            value?.value
        );

    }

    return String(
        value
    );

};


// =====================================================
// SERVICE TYPE CANDIDATES
// =====================================================

const getServiceTypeCandidates = (
    serviceType
) => {

    if (
        serviceType === undefined ||
        serviceType === null ||
        serviceType === ""
    ) {

        return [];

    }

    if (
        typeof serviceType === "object"
    ) {

        return [

            serviceType?.code,

            serviceType?.value,

            serviceType?.name,

            serviceType?.label,

            serviceType?.text

        ]
            .map(
                normalizeText
            )
            .filter(
                Boolean
            );

    }

    return [

        normalizeText(
            serviceType
        )

    ]
        .filter(
            Boolean
        );

};


// =====================================================
// FIND SERVICE TYPE OPTION
// =====================================================

const findServiceTypeOption = (
    serviceItem,
    serviceTypeOptions
) => {

    const serviceType =
        serviceItem?.serviceType;

    if (
        serviceType === undefined ||
        serviceType === null ||
        serviceType === ""
    ) {

        return null;

    }

    const options =
        Array.isArray(
            serviceTypeOptions
        )
            ? serviceTypeOptions
            : [];

    const serviceTypeId =
        getLookupId(
            serviceType
        );

    if (
        serviceTypeId &&
        isObjectIdLike(
            serviceTypeId
        )
    ) {

        const idMatch =
            options.find(
                (
                    option
                ) =>
                    String(
                        getLookupId(
                            option
                        )
                    ) ===
                    String(
                        serviceTypeId
                    )
            );

        if (
            idMatch
        ) {

            return idMatch;

        }

    }

    const candidates =
        getServiceTypeCandidates(
            serviceType
        );

    if (
        candidates.length ===
        0
    ) {

        return null;

    }

    return (
        options.find(
            (
                option
            ) => {

                const optionCandidates =
                    getServiceTypeCandidates(
                        option
                    );

                return optionCandidates.some(
                    (
                        candidate
                    ) =>
                        candidates.includes(
                            candidate
                        )
                );

            }
        ) ||
        null
    );

};


// =====================================================
// GET SERVICE ITEM DISPLAY NAME
// =====================================================

const getServiceItemDisplayName = (
    serviceItem,
    serviceTypeOptions
) => {

    if (
        !serviceItem
    ) {

        return "Service Item";

    }

    const storedLabel =
        String(
            serviceItem?.serviceTypeLabel ||
            ""
        )
            .trim();

    if (
        storedLabel &&
        !isObjectIdLike(
            storedLabel
        )
    ) {

        return storedLabel;

    }

    const directServiceType =
        getLookupDisplayValue(
            serviceItem?.serviceType
        );

    if (
        directServiceType &&
        !isObjectIdLike(
            directServiceType
        )
    ) {

        return directServiceType;

    }

    const resolvedServiceType =
        findServiceTypeOption(
            serviceItem,
            serviceTypeOptions
        );

    const resolvedDisplay =
        getLookupDisplayValue(
            resolvedServiceType
        );

    if (
        resolvedDisplay &&
        !isObjectIdLike(
            resolvedDisplay
        )
    ) {

        return resolvedDisplay;

    }

    return "Service Item";

};


// =====================================================
// GET SERVICE ITEM ALLOCATION BEHAVIOR
// =====================================================

const getServiceItemAllocationBehavior = (
    serviceItem,
    serviceTypeOptions
) => {

    if (
        serviceItem?.allocationBehavior !==
        undefined &&
        serviceItem?.allocationBehavior !==
        null &&
        String(
            serviceItem.allocationBehavior
        ).trim() !== ""
    ) {

        return normalizeAllocationBehavior(
            serviceItem.allocationBehavior
        );

    }

    const resolvedServiceType =
        findServiceTypeOption(
            serviceItem,
            serviceTypeOptions
        );

    if (
        resolvedServiceType?.allocationBehavior
    ) {

        return normalizeAllocationBehavior(
            resolvedServiceType.allocationBehavior
        );

    }

    return CONSUMPTION;

};


// =====================================================
// UNIT HELPERS
// =====================================================

const getUnitOptionId = (
    unit
) => {

    if (
        !unit
    ) {

        return "";

    }

    if (
        typeof unit === "object"
    ) {

        return normalizeId(
            unit?._id ??
            unit?.id ??
            unit?.lookupId ??
            unit?.value
        );

    }

    return normalizeId(
        unit
    );

};


const getUnitCandidates = (
    unit
) => {

    if (
        !unit
    ) {

        return [];

    }

    if (
        typeof unit === "object"
    ) {

        return [

            unit?.code,

            unit?.unitCode,

            unit?.lookupCode,

            unit?.value,

            unit?.name,

            unit?.label,

            unit?.text

        ]
            .map(
                normalizeText
            )
            .filter(
                Boolean
            );

    }

    return [

        normalizeText(
            unit
        )

    ]
        .filter(
            Boolean
        );

};


const findUnitOption = (
    serviceItem,
    unitOptions
) => {

    const unit =
        serviceItem?.unit;

    if (
        unit === undefined ||
        unit === null ||
        unit === ""
    ) {

        return null;

    }

    const options =
        Array.isArray(
            unitOptions
        )
            ? unitOptions
            : [];

    const rawUnitId =
        getUnitOptionId(
            unit
        );

    if (
        rawUnitId &&
        isObjectIdLike(
            rawUnitId
        )
    ) {

        const idMatch =
            options.find(
                (
                    option
                ) =>
                    String(
                        getUnitOptionId(
                            option
                        )
                    ) ===
                    String(
                        rawUnitId
                    )
            );

        if (
            idMatch
        ) {

            return idMatch;

        }

    }

    const candidates =
        getUnitCandidates(
            unit
        );

    if (
        candidates.length
    ) {

        const valueMatch =
            options.find(
                (
                    option
                ) => {

                    const optionCandidates =
                        getUnitCandidates(
                            option
                        );

                    return optionCandidates.some(
                        (
                            candidate
                        ) =>
                            candidates.includes(
                                candidate
                            )
                    );

                }
            );

        if (
            valueMatch
        ) {

            return valueMatch;

        }

    }

    if (
        typeof unit === "object"
    ) {

        return unit;

    }

    return null;

};


// =====================================================
// GET UNIT SEMANTICS
// =====================================================

const getUnitSemantics = (
    serviceItem,
    unitOptions
) => {

    const resolvedUnit =
        findUnitOption(
            serviceItem,
            unitOptions
        );

    const semanticType =
        normalizeText(
            resolvedUnit?.semanticType
        );

    if (
        semanticType ===
        "MONETARY"
    ) {

        return "monetary";

    }

    if (
        semanticType ===
        "PHYSICAL"
    ) {

        return "physical";

    }

    const candidates =
        getUnitCandidates(
            resolvedUnit
        );

    if (
        candidates.some(
            (
                code
            ) =>
                MONETARY_UNIT_CODES.includes(
                    code
                )
        )
    ) {

        return "monetary";

    }

    if (
        candidates.some(
            (
                code
            ) =>
                PHYSICAL_UNIT_CODES.includes(
                    code
                )
        )
    ) {

        return "physical";

    }

    const rawCandidates =
        getUnitCandidates(
            serviceItem?.unit
        );

    if (
        rawCandidates.some(
            (
                code
            ) =>
                MONETARY_UNIT_CODES.includes(
                    code
                )
        )
    ) {

        return "monetary";

    }

    if (
        rawCandidates.some(
            (
                code
            ) =>
                PHYSICAL_UNIT_CODES.includes(
                    code
                )
        )
    ) {

        return "physical";

    }

    return "unknown";

};


// =====================================================
// GET UNIT DISPLAY
// =====================================================

const getUnitDisplay = (
    unit,
    unitOptions
) => {

    const fakeItem = {
        unit
    };

    const resolvedUnit =
        findUnitOption(
            fakeItem,
            unitOptions
        );

    if (
        resolvedUnit
    ) {

        const display =
            [

                resolvedUnit?.label,

                resolvedUnit?.name,

                resolvedUnit?.text,

                resolvedUnit?.value,

                resolvedUnit?.code,

                resolvedUnit?.unitCode

            ].find(
                (
                    candidate
                ) =>
                    candidate &&
                    !isObjectIdLike(
                        candidate
                    )
            );

        if (
            display
        ) {

            return String(
                display
            );

        }

    }

    if (
        typeof unit === "object"
    ) {

        const display =
            [

                unit?.label,

                unit?.name,

                unit?.text,

                unit?.value,

                unit?.code,

                unit?.unitCode

            ].find(
                (
                    candidate
                ) =>
                    candidate &&
                    !isObjectIdLike(
                        candidate
                    )
            );

        if (
            display
        ) {

            return String(
                display
            );

        }

    }

    if (
        unit &&
        !isObjectIdLike(
            unit
        )
    ) {

        return String(
            unit
        );

    }

    return "Unit";

};


// =====================================================
// GET SERVICE ITEM UNIT
// =====================================================

const getServiceItemUnit = (
    serviceItem,
    unitOptions
) => {

    return getUnitDisplay(
        serviceItem?.unit,
        unitOptions
    );

};


// =====================================================
// IS MONETARY
// =====================================================

const isAmountUnit = (
    serviceItem,
    unitOptions
) => {

    return (
        getUnitSemantics(
            serviceItem,
            unitOptions
        ) ===
        "monetary"
    );

};


// =====================================================
// SAFE NUMBER
// =====================================================

const getSafeNumber = (
    value
) => {

    const number =
        Number(
            value
        );

    if (
        !Number.isFinite(
            number
        )
    ) {

        return 0;

    }

    return Math.max(
        0,
        number
    );

};


// =====================================================
// FORMAT MONEY
// =====================================================

const formatMoney = (
    value
) => {

    const number =
        Number(
            value
        );

    if (
        !Number.isFinite(
            number
        )
    ) {

        return "0.00";

    }

    return number.toLocaleString(
        undefined,
        {
            minimumFractionDigits:
                2,

            maximumFractionDigits:
                2
        }
    );

};


// =====================================================
// ITEM TOTAL
// =====================================================

const getItemTotal = (
    serviceItem
) => {

    const quantity =
        getSafeNumber(
            serviceItem?.quantity
        );

    const unitCost =
        getSafeNumber(
            serviceItem?.unitCost
        );

    return (
        quantity *
        unitCost
    );

};


// =====================================================
// DETAIL ITEM TOTAL
// =====================================================

const getDetailItemTotal = (
    detailItem
) => {

    const quantity =
        getSafeNumber(
            detailItem?.quantity
        );

    const unitCost =
        getSafeNumber(
            detailItem?.unitCost
        );

    const storedTotal =
        getSafeNumber(
            detailItem?.totalCost
        );

    if (
        storedTotal > 0
    ) {

        return storedTotal;

    }

    return (
        quantity *
        unitCost
    );

};


// =====================================================
// GET ALL DIRECT PARENT ALLOCATIONS
// =====================================================
//
// IMPORTANT FIX:
// Only allocations without detailItem belong to the
// parent Service Item.
//
// Detail allocations are handled by getDetailAggregate().
//

const getAllServiceItemAllocations = (
    beneficiaries,
    serviceItemId,
    excludeBeneficiaryIndex = -1
) => {

    const result = {

        quantity: 0,

        allocatedValue: 0

    };

    if (
        !Array.isArray(
            beneficiaries
        )
    ) {

        return result;

    }

    beneficiaries.forEach(
        (
            beneficiary,
            index
        ) => {

            if (
                index ===
                excludeBeneficiaryIndex
            ) {

                return;

            }

            const allocations =
                getDirectServiceItemAllocations(
                    beneficiary,
                    serviceItemId
                );

            allocations.forEach(
                (
                    allocation
                ) => {

                    result.quantity +=
                        getSafeNumber(
                            allocation?.quantity
                        );

                    result.allocatedValue +=
                        getSafeNumber(
                            allocation?.allocatedValue
                        );

                }
            );

        }
    );

    return result;

};


// =====================================================
// GET DETAIL AGGREGATE
// =====================================================

const getDetailAggregate = (
    beneficiaries,
    serviceItemId,
    detailItemId,
    excludeBeneficiaryIndex = -1
) => {

    let quantity = 0;

    let allocatedValue = 0;

    if (
        !Array.isArray(
            beneficiaries
        )
    ) {

        return {

            quantity,

            allocatedValue

        };

    }

    beneficiaries.forEach(
        (
            beneficiary,
            index
        ) => {

            if (
                index ===
                excludeBeneficiaryIndex
            ) {

                return;

            }

            const allocation =
                getDetailAllocation(
                    beneficiary,
                    serviceItemId,
                    detailItemId
                );

            if (
                !allocation
            ) {

                return;

            }

            quantity +=
                getSafeNumber(
                    allocation?.quantity
                );

            allocatedValue +=
                getSafeNumber(
                    allocation?.allocatedValue
                );

        }
    );

    return {

        quantity,

        allocatedValue

    };

};


// =====================================================
// COMPONENT
// =====================================================

const ServiceDeliveryAllocations = ({

    items = [],

    beneficiaries = [],

    beneficiaryOptions = [],

    serviceTypeOptions = [],

    allocationMethod = "Individual",

    unitOptions = [],

    setFormData

}) => {

    const safeItems =
        Array.isArray(
            items
        )
            ? items
            : [];

    const safeBeneficiaries =
        Array.isArray(
            beneficiaries
        )
            ? beneficiaries
            : [];

    const safeUnitOptions =
        Array.isArray(
            unitOptions
        )
            ? unitOptions
            : [];

    const safeServiceTypeOptions =
        Array.isArray(
            serviceTypeOptions
        )
            ? serviceTypeOptions
            : [];


    const validItems =
        useMemo(
            () =>
                safeItems.filter(
                    (
                        item
                    ) =>
                        item &&
                        typeof item ===
                        "object" &&
                        isObjectIdLike(
                            getServiceItemId(
                                item
                            )
                        )
                ),
            [
                safeItems
            ]
        );


    if (
        allocationMethod !==
        "Individual" &&
        allocationMethod !==
        "Shared"
    ) {

        return null;

    }


    if (
        safeBeneficiaries.length ===
        0
    ) {

        return (

            <Box
                sx={{
                    mt: 2
                }}
            >

                <Paper
                    variant="outlined"
                    sx={{
                        p: 2
                    }}
                >

                    <Typography
                        variant="body2"
                        color="text.secondary"
                    >
                        Select beneficiaries to configure
                        service allocations.
                    </Typography>

                </Paper>

            </Box>

        );

    }


    if (
        validItems.length ===
        0
    ) {

        return (

            <Box
                sx={{
                    mt: 2
                }}
            >

                <Paper
                    variant="outlined"
                    sx={{
                        p: 2
                    }}
                >

                    <Typography
                        variant="body2"
                        color="text.secondary"
                    >
                        Add service items before configuring
                        beneficiary allocations.
                    </Typography>

                </Paper>

            </Box>

        );

    }

// ===================================================
// UPDATE ALLOCATION
// ===================================================

const updateAllocation = (
    beneficiaryIndex,
    serviceItem,
    detailItem,
    field,
    value
) => {
    if (typeof setFormData !== "function") {
        return;
    }

    if (
        field !== "quantity" &&
        field !== "allocatedValue" &&
        field !== "remarks"
    ) {
        return;
    }

    const serviceItemId = getServiceItemId(serviceItem);

    if (!isObjectIdLike(serviceItemId)) {
        return;
    }

    const detailItemId = detailItem
        ? normalizeId(detailItem?._id ?? detailItem?.id)
        : "";

    if (detailItem && !detailItemId) {
        return;
    }

    const monetary = detailItem
        ? getUnitSemantics(
              { unit: detailItem.unit },
              safeUnitOptions
          ) === "monetary"
        : isAmountUnit(serviceItem, safeUnitOptions);

    const allocationBehavior =
        getServiceItemAllocationBehavior(
            serviceItem,
            safeServiceTypeOptions
        );

    setFormData((prev) => {
        const currentBeneficiaries = Array.isArray(
            prev?.beneficiaries
        )
            ? prev.beneficiaries
            : [];

        const currentBeneficiary =
            currentBeneficiaries[beneficiaryIndex];

        if (!currentBeneficiary) {
            return prev;
        }

        const currentAllocation = detailItem
            ? getDetailAllocation(
                  currentBeneficiary,
                  serviceItemId,
                  detailItemId
              )
            : getDirectAllocation(
                  currentBeneficiary,
                  serviceItemId
              );

        const numericValue = Number(value);

        let nextValue =
            Number.isFinite(numericValue)
                ? Math.max(0, numericValue)
                : 0;

        // ==========================================
        // QUANTITY
        // ==========================================

        if (field === "quantity") {
            if (monetary) {
                nextValue = 0;
            } else {
                const deliveredQuantity = getSafeNumber(
                    detailItem
                        ? detailItem.quantity
                        : serviceItem.quantity
                );

                if (
                    allocationBehavior === CONSUMPTION
                ) {
                    const aggregate = detailItem
                        ? getDetailAggregate(
                              currentBeneficiaries,
                              serviceItemId,
                              detailItemId,
                              beneficiaryIndex
                          )
                        : getAllServiceItemAllocations(
                              currentBeneficiaries,
                              serviceItemId,
                              beneficiaryIndex
                          );

                    // Aggregate excludes this beneficiary.
                    // Do not subtract their current allocation again.
                    const remaining = Math.max(
                        0,
                        deliveredQuantity -
                            aggregate.quantity
                    );

                    nextValue = Math.min(
                        nextValue,
                        remaining
                    );
                } else {
                    nextValue = Math.min(
                        nextValue,
                        deliveredQuantity
                    );
                }
            }
        }

        // ==========================================
        // ALLOCATED VALUE
        // ==========================================

        if (field === "allocatedValue") {
            const itemTotal = detailItem
                ? getDetailItemTotal(detailItem)
                : getItemTotal(serviceItem);

            const aggregate = detailItem
                ? getDetailAggregate(
                      currentBeneficiaries,
                      serviceItemId,
                      detailItemId,
                      beneficiaryIndex
                  )
                : getAllServiceItemAllocations(
                      currentBeneficiaries,
                      serviceItemId,
                      beneficiaryIndex
                  );

            // Aggregate excludes this beneficiary.
            const remaining = Math.max(
                0,
                itemTotal - aggregate.allocatedValue
            );

            nextValue = Math.min(
                nextValue,
                remaining
            );
        }

        // ==========================================
        // BUILD UPDATED ALLOCATION
        // ==========================================

        const updatedAllocation = {
            ...(currentAllocation || {}),
            serviceItem: serviceItemId,
            detailItem: detailItemId || null,
            quantity: getSafeNumber(
                currentAllocation?.quantity
            ),
            allocatedValue: getSafeNumber(
                currentAllocation?.allocatedValue
            ),
            remarks: currentAllocation?.remarks || ""
        };

        updatedAllocation[field] = nextValue;

        if (monetary) {
            updatedAllocation.quantity = 0;
        }

        const resultingQuantity = getSafeNumber(
            updatedAllocation.quantity
        );

        const resultingValue = getSafeNumber(
            updatedAllocation.allocatedValue
        );

        // ==========================================
        // UPDATE ONLY THIS BENEFICIARY
        // ==========================================

        const nextBeneficiaries =
            currentBeneficiaries.map(
                (beneficiary, index) => {
                    if (index !== beneficiaryIndex) {
                        return beneficiary;
                    }

                    const allocations = Array.isArray(
                        beneficiary?.allocations
                    )
                        ? beneficiary.allocations
                        : [];

                    const sameService = (allocation) =>
                        String(
                            getAllocationServiceItemId(
                                allocation
                            )
                        ) === String(serviceItemId);

                    const isDirect = (allocation) =>
                        !getAllocationDetailItemId(
                            allocation
                        );

                    const isTargetAllocation = (
                        allocation
                    ) => {
                        if (!sameService(allocation)) {
                            return false;
                        }

                        const allocationDetail =
                            getAllocationDetailItemId(
                                allocation
                            );

                        return detailItem
                            ? String(allocationDetail) ===
                                  String(detailItemId)
                            : !allocationDetail;
                    };

                    // Empty target: remove only the target
                    // allocation. Do not switch allocation type
                    // just because a field was cleared.
                    if (
                        resultingQuantity === 0 &&
                        resultingValue === 0
                    ) {
                        return {
                            ...beneficiary,
                            allocations: allocations.filter(
                                (allocation) =>
                                    !isTargetAllocation(
                                        allocation
                                    )
                            )
                        };
                    }

                    // When a non-empty detail allocation is
                    // entered, remove this beneficiary's direct
                    // parent allocation for the same service.
                    //
                    // When a non-empty direct allocation is
                    // entered, remove this beneficiary's detail
                    // allocations for the same service.
                    const filteredAllocations =
                        allocations.filter((allocation) => {
                            if (!sameService(allocation)) {
                                return true;
                            }

                            return detailItem
                                ? !isDirect(allocation)
                                : isDirect(allocation);
                        });

                    const targetIndex =
                        filteredAllocations.findIndex(
                            isTargetAllocation
                        );

                    const nextAllocations =
                        [...filteredAllocations];

                    if (targetIndex >= 0) {
                        nextAllocations[targetIndex] =
                            updatedAllocation;
                    } else {
                        nextAllocations.push(
                            updatedAllocation
                        );
                    }

                    return {
                        ...beneficiary,
                        allocations: nextAllocations
                    };
                }
            );

        return {
            ...prev,
            beneficiaries: nextBeneficiaries
        };
    });
};


// ===================================================
// APPLY FULL ALLOCATION
// ===================================================

const applyFullAllocation = (
    beneficiaryIndex,
    serviceItem,
    detailItem = null
) => {
    if (typeof setFormData !== "function") {
        return;
    }

    const serviceItemId = getServiceItemId(serviceItem);

    if (!isObjectIdLike(serviceItemId)) {
        return;
    }

    const detailItemId = detailItem
        ? normalizeId(detailItem?._id ?? detailItem?.id)
        : "";

    if (detailItem && !detailItemId) {
        return;
    }

    setFormData((prev) => {
        const currentBeneficiaries = Array.isArray(
            prev?.beneficiaries
        )
            ? prev.beneficiaries
            : [];

        const currentBeneficiary =
            currentBeneficiaries[beneficiaryIndex];

        if (!currentBeneficiary) {
            return prev;
        }

        const monetary = detailItem
            ? getUnitSemantics(
                  { unit: detailItem.unit },
                  safeUnitOptions
              ) === "monetary"
            : isAmountUnit(serviceItem, safeUnitOptions);

        const allocationBehavior =
            getServiceItemAllocationBehavior(
                serviceItem,
                safeServiceTypeOptions
            );

        const existingAllocation = detailItem
            ? getDetailAllocation(
                  currentBeneficiary,
                  serviceItemId,
                  detailItemId
              )
            : getDirectAllocation(
                  currentBeneficiary,
                  serviceItemId
              );

        const deliveryQuantity = getSafeNumber(
            detailItem
                ? detailItem.quantity
                : serviceItem.quantity
        );

        const itemTotal = detailItem
            ? getDetailItemTotal(detailItem)
            : getItemTotal(serviceItem);

        const aggregate = detailItem
            ? getDetailAggregate(
                  currentBeneficiaries,
                  serviceItemId,
                  detailItemId,
                  beneficiaryIndex
              )
            : getAllServiceItemAllocations(
                  currentBeneficiaries,
                  serviceItemId,
                  beneficiaryIndex
              );

        // Aggregate excludes this beneficiary, so the
        // remaining amount is the maximum available to them.
        const remainingQuantity = Math.max(
            0,
            deliveryQuantity - aggregate.quantity
        );

        const remainingValue = Math.max(
            0,
            itemTotal - aggregate.allocatedValue
        );

        let nextQuantity = 0;

        if (!monetary) {
            nextQuantity =
                allocationBehavior === PARTICIPATION
                    ? deliveryQuantity
                    : remainingQuantity;
        }

        const updatedAllocation = {
            ...(existingAllocation || {}),
            serviceItem: serviceItemId,
            detailItem: detailItemId || null,
            quantity: monetary ? 0 : nextQuantity,
            allocatedValue: remainingValue,
            remarks: existingAllocation?.remarks || ""
        };

        // ==========================================
        // UPSERT AND ENFORCE EXCLUSIVITY
        // ==========================================

        const nextBeneficiaries =
            currentBeneficiaries.map(
                (beneficiary, index) => {
                    if (index !== beneficiaryIndex) {
                        return beneficiary;
                    }

                    const allocations = Array.isArray(
                        beneficiary?.allocations
                    )
                        ? beneficiary.allocations
                        : [];

                    const sameService = (allocation) =>
                        String(
                            getAllocationServiceItemId(
                                allocation
                            )
                        ) === String(serviceItemId);

                    const isDirect = (allocation) =>
                        !getAllocationDetailItemId(
                            allocation
                        );

                    const isTargetAllocation = (
                        allocation
                    ) => {
                        if (!sameService(allocation)) {
                            return false;
                        }

                        const allocationDetail =
                            getAllocationDetailItemId(
                                allocation
                            );

                        return detailItem
                            ? String(allocationDetail) ===
                                  String(detailItemId)
                            : !allocationDetail;
                    };

                    // Keep unrelated service items untouched.
                    // For this service item, keep only allocations
                    // matching the selected allocation level.
                    const filteredAllocations =
                        allocations.filter((allocation) => {
                            if (!sameService(allocation)) {
                                return true;
                            }

                            return detailItem
                                ? !isDirect(allocation)
                                : isDirect(allocation);
                        });

                    const targetIndex =
                        filteredAllocations.findIndex(
                            isTargetAllocation
                        );

                    const nextAllocations =
                        [...filteredAllocations];

                    if (targetIndex >= 0) {
                        nextAllocations[targetIndex] =
                            updatedAllocation;
                    } else {
                        nextAllocations.push(
                            updatedAllocation
                        );
                    }

                    return {
                        ...beneficiary,
                        allocations: nextAllocations
                    };
                }
            );

        return {
            ...prev,
            beneficiaries: nextBeneficiaries
        };
    });
};



    // ===================================================
    // GET SERVICE ITEM SUMMARY
    // ===================================================

    const getItemAllocationSummary = (
        serviceItem
    ) => {

        const serviceItemId =
            getServiceItemId(
                serviceItem
            );

        const deliveryQuantity =
            getSafeNumber(
                serviceItem.quantity
            );

        const itemTotal =
            getItemTotal(
                serviceItem
            );

        const monetary =
            isAmountUnit(
                serviceItem,
                safeUnitOptions
            );

        const allocationBehavior =
            getServiceItemAllocationBehavior(
                serviceItem,
                safeServiceTypeOptions
            );


        let allocatedQuantity = 0;

        let allocatedValue = 0;


        safeBeneficiaries.forEach(
            (
                beneficiary
            ) => {

                // IMPORTANT:
                // Only direct parent allocations are counted
                // in the parent Service Item summary.
                //
                // Detail Item allocations are summarized
                // separately below.

                const allocations =
                    getDirectServiceItemAllocations(
                        beneficiary,
                        serviceItemId
                    );

                allocations.forEach(
                    (
                        allocation
                    ) => {

                        allocatedQuantity +=
                            getSafeNumber(
                                allocation?.quantity
                            );

                        allocatedValue +=
                            getSafeNumber(
                                allocation?.allocatedValue
                            );

                    }
                );

            }
        );


        if (
            monetary
        ) {

            allocatedQuantity =
                0;

        }


        const cappedAllocatedValue =
            Math.min(
                itemTotal,
                allocatedValue
            );


        const unallocatedQuantity =
            monetary ||
            allocationBehavior ===
            PARTICIPATION
                ? 0
                : Math.max(
                    0,
                    deliveryQuantity -
                    Math.min(
                        deliveryQuantity,
                        allocatedQuantity
                    )
                );


        return {

            monetary,

            allocationBehavior,

            deliveryQuantity,

            allocatedQuantity,

            unallocatedQuantity,

            itemTotal,

            allocatedValue:
                cappedAllocatedValue,

            unallocatedValue:
                Math.max(
                    0,
                    itemTotal -
                    cappedAllocatedValue
                )

        };

    };


    // ===================================================
    // RENDER
    // ===================================================

    return (

        <Box
            sx={{
                mt: 3
            }}
        >

            <Typography
                variant="h6"
                sx={{
                    mb: 1
                }}
            >
                Beneficiary Allocation
            </Typography>


            <Typography
                variant="body2"
                color="text.secondary"
                sx={{
                    mb: 3
                }}
            >
                Declare which service items or supporting detail
                items are attributable to each beneficiary. Actual
                delivery cost remains separate from beneficiary
                attribution.
            </Typography>


            {/* =================================================
                BENEFICIARIES
            ================================================= */}

            {
                safeBeneficiaries.map(
                    (
                        beneficiary,
                        beneficiaryIndex
                    ) => {

                        const beneficiaryId =
                            getBeneficiaryId(
                                beneficiary
                            );


                        return (

                            <Paper
                                key={
                                    `${beneficiaryId || "beneficiary"}-${beneficiaryIndex}`
                                }
                                variant="outlined"
                                sx={{
                                    mb: 3,
                                    p: 2
                                }}
                            >

                                <Typography
                                    variant="subtitle1"
                                    fontWeight={600}
                                    sx={{
                                        mb: 2
                                    }}
                                >
                                    {
                                        getBeneficiaryName(
                                            beneficiary,
                                            beneficiaryOptions
                                        )
                                    }
                                </Typography>


                                <Divider
                                    sx={{
                                        mb: 3
                                    }}
                                />


                                {
                                    validItems.map(
                                        (
                                            serviceItem
                                        ) => {

                                            const serviceItemId =
                                                getServiceItemId(
                                                    serviceItem
                                                );

                                            const serviceItemLabel =
                                                getServiceItemDisplayName(
                                                    serviceItem,
                                                    safeServiceTypeOptions
                                                );

                                            const parentUnit =
                                                getServiceItemUnit(
                                                    serviceItem,
                                                    safeUnitOptions
                                                );

                                            const monetary =
                                                isAmountUnit(
                                                    serviceItem,
                                                    safeUnitOptions
                                                );

                                            const allocationBehavior =
                                                getServiceItemAllocationBehavior(
                                                    serviceItem,
                                                    safeServiceTypeOptions
                                                );

                                            const deliveryQuantity =
                                                getSafeNumber(
                                                    serviceItem.quantity
                                                );

                                            const itemTotal =
                                                getItemTotal(
                                                    serviceItem
                                                );

                                            const directAllocation =
                                                getDirectAllocation(
                                                    beneficiary,
                                                    serviceItemId
                                                );

                                            const detailItems =
                                                Array.isArray(
                                                    serviceItem?.detailItems
                                                )
                                                    ? serviceItem.detailItems
                                                    : [];


                                            return (

                                                <Box
                                                    key={
                                                        serviceItemId
                                                    }
                                                    sx={{
                                                        mb: 4
                                                    }}
                                                >

                                                    {/* =========================================
                                                        PARENT SERVICE ITEM HEADER
                                                    ========================================= */}

                                                    <Typography
                                                        variant="body1"
                                                        fontWeight={600}
                                                    >
                                                        {
                                                            serviceItemLabel
                                                        }
                                                    </Typography>


                                                    <Typography
                                                        variant="caption"
                                                        color="text.secondary"
                                                        sx={{
                                                            display:
                                                                "block",
                                                            mb: 2
                                                        }}
                                                    >

                                                        {
                                                            monetary
                                                                ? (
                                                                    <>
                                                                        Delivery amount:
                                                                        {" "}
                                                                        ETB{" "}
                                                                        {
                                                                            formatMoney(
                                                                                itemTotal
                                                                            )
                                                                        }
                                                                    </>
                                                                )
                                                                : (
                                                                    <>
                                                                        Delivery quantity:
                                                                        {" "}
                                                                        {
                                                                            deliveryQuantity
                                                                        }
                                                                        {" "}
                                                                        {
                                                                            parentUnit
                                                                        }
                                                                    </>
                                                                )
                                                        }

                                                        {" "}•
                                                        Unit cost:
                                                        {" "}
                                                        ETB{" "}
                                                        {
                                                            formatMoney(
                                                                serviceItem.unitCost
                                                            )
                                                        }

                                                        {" "}•
                                                        Item total:
                                                        {" "}
                                                        ETB{" "}
                                                        {
                                                            formatMoney(
                                                                itemTotal
                                                            )
                                                        }

                                                    </Typography>


                                                    {
                                                        !monetary
                                                            ? (

                                                                <Typography
                                                                    variant="caption"
                                                                    color="text.secondary"
                                                                    sx={{
                                                                        display:
                                                                            "block",
                                                                        mb: 2
                                                                    }}
                                                                >

                                                                    Allocation behavior:
                                                                    {" "}
                                                                    {
                                                                        allocationBehavior ===
                                                                        PARTICIPATION
                                                                            ? "Participation"
                                                                            : "Consumption"
                                                                    }

                                                                </Typography>

                                                            )
                                                            : null
                                                    }


                                                    {/* =========================================
                                                        DIRECT PARENT ALLOCATION
                                                    ========================================= */}

                                                    {
                                                        !detailItems.length
                                                            ? (

                                                                <Box
                                                                    sx={{
                                                                        display:
                                                                            "grid",
                                                                        gridTemplateColumns:
                                                                            {
                                                                                xs:
                                                                                    "1fr",
                                                                                sm:
                                                                                    monetary
                                                                                        ? "1fr"
                                                                                        : "1fr 1fr"
                                                                            },
                                                                        gap:
                                                                            2
                                                                    }}
                                                                >

                                                                    {
                                                                        !monetary
                                                                            ? (

                                                                                <TextField
                                                                                    fullWidth
                                                                                    type="number"
                                                                                    label={
                                                                                        `Allocated Quantity (${parentUnit})`
                                                                                    }
                                                                                    value={
                                                                                        getSafeNumber(
                                                                                            directAllocation?.quantity
                                                                                        )
                                                                                    }
                                                                                    inputProps={{
                                                                                        min:
                                                                                            0,
                                                                                        max:
                                                                                            deliveryQuantity,
                                                                                        step:
                                                                                            "any"
                                                                                    }}
                                                                                    onChange={
                                                                                        (
                                                                                            event
                                                                                        ) =>
                                                                                            updateAllocation(
                                                                                                beneficiaryIndex,
                                                                                                serviceItem,
                                                                                                null,
                                                                                                "quantity",
                                                                                                event.target.value
                                                                                            )
                                                                                    }
                                                                                />

                                                                            )
                                                                            : null
                                                                    }


                                                                    <TextField
                                                                        fullWidth
                                                                        type="number"
                                                                        label={
                                                                            monetary
                                                                                ? "Allocated Amount (ETB)"
                                                                                : "Allocated Value (ETB)"
                                                                        }
                                                                        value={
                                                                            getSafeNumber(
                                                                                directAllocation?.allocatedValue
                                                                            )
                                                                        }
                                                                        inputProps={{
                                                                            min:
                                                                                0,
                                                                            max:
                                                                                itemTotal,
                                                                            step:
                                                                                "any"
                                                                        }}
                                                                        onChange={
                                                                            (
                                                                                event
                                                                            ) =>
                                                                                updateAllocation(
                                                                                    beneficiaryIndex,
                                                                                    serviceItem,
                                                                                    null,
                                                                                    "allocatedValue",
                                                                                    event.target.value
                                                                                )
                                                                        }
                                                                    />

                                                                </Box>

                                                            )
                                                            : null
                                                    }


                                                    {/* =========================================
                                                        DETAIL ITEMS
                                                    ========================================= */}

                                                    {
                                                        detailItems.length
                                                            ? (

                                                                <Box
                                                                    sx={{
                                                                        mt: 2,
                                                                        pl: {
                                                                            xs:
                                                                                0,
                                                                            sm:
                                                                                2
                                                                        },
                                                                        borderLeft:
                                                                            {
                                                                                xs:
                                                                                    "none",
                                                                                sm:
                                                                                    "2px solid"
                                                                            },
                                                                        borderColor:
                                                                            "divider"
                                                                    }}
                                                                >

                                                                    <Typography
                                                                        variant="subtitle2"
                                                                        fontWeight={600}
                                                                        sx={{
                                                                            mb: 2
                                                                        }}
                                                                    >
                                                                        Supporting Detail Items
                                                                    </Typography>


                                                                    {
                                                                        detailItems.map(
                                                                            (
                                                                                detailItem,
                                                                                detailIndex
                                                                            ) => {

                                                                                const detailItemId =
                                                                                    normalizeId(
                                                                                        detailItem?._id ??
                                                                                        detailItem?.id
                                                                                    );

                                                                                if (
                                                                                    !detailItemId
                                                                                ) {

                                                                                    return null;

                                                                                }


                                                                                const detailAllocation =
                                                                                    getDetailAllocation(
                                                                                        beneficiary,
                                                                                        serviceItemId,
                                                                                        detailItemId
                                                                                    );


                                                                                const detailUnit =
                                                                                    getUnitDisplay(
                                                                                        detailItem.unit,
                                                                                        safeUnitOptions
                                                                                    );


                                                                                const detailSemantics =
                                                                                    getUnitSemantics(
                                                                                        {
                                                                                            unit:
                                                                                                detailItem.unit
                                                                                        },
                                                                                        safeUnitOptions
                                                                                    );


                                                                                const detailQuantity =
                                                                                    getSafeNumber(
                                                                                        detailItem.quantity
                                                                                    );


                                                                                const detailTotal =
                                                                                    getDetailItemTotal(
                                                                                        detailItem
                                                                                    );


                                                                                const detailMonetary =
                                                                                    detailSemantics ===
                                                                                    "monetary";


                                                                                return (

                                                                                    <Box
                                                                                        key={
                                                                                            detailItemId
                                                                                        }
                                                                                        sx={{
                                                                                            mb:
                                                                                                3
                                                                                        }}
                                                                                    >

                                                                                        <Typography
                                                                                            variant="body2"
                                                                                            fontWeight={600}
                                                                                        >
                                                                                            {
                                                                                                detailItem?.name ||
                                                                                                `Detail Item ${detailIndex + 1}`
                                                                                            }
                                                                                        </Typography>


                                                                                        <Typography
                                                                                            variant="caption"
                                                                                            color="text.secondary"
                                                                                            sx={{
                                                                                                display:
                                                                                                    "block",
                                                                                                mb:
                                                                                                    1.5
                                                                                            }}
                                                                                        >

                                                                                            Delivered:
                                                                                            {" "}
                                                                                            {
                                                                                                detailQuantity
                                                                                            }
                                                                                            {" "}
                                                                                            {
                                                                                                detailUnit
                                                                                            }

                                                                                            {" "}•
                                                                                            Unit cost:
                                                                                            {" "}
                                                                                            ETB{" "}
                                                                                            {
                                                                                                formatMoney(
                                                                                                    detailItem.unitCost
                                                                                                )
                                                                                            }

                                                                                            {" "}•
                                                                                            Total:
                                                                                            {" "}
                                                                                            ETB{" "}
                                                                                            {
                                                                                                formatMoney(
                                                                                                    detailTotal
                                                                                                )
                                                                                            }

                                                                                        </Typography>


                                                                                        <Box
                                                                                            sx={{
                                                                                                display:
                                                                                                    "grid",
                                                                                                gridTemplateColumns:
                                                                                                    {
                                                                                                        xs:
                                                                                                            "1fr",
                                                                                                        sm:
                                                                                                            detailMonetary
                                                                                                                ? "1fr"
                                                                                                                : "1fr 1fr"
                                                                                                    },
                                                                                                gap:
                                                                                                    2
                                                                                            }}
                                                                                        >

                                                                                            {
                                                                                                !detailMonetary
                                                                                                    ? (

                                                                                                        <TextField
                                                                                                            fullWidth
                                                                                                            type="number"
                                                                                                            label={
                                                                                                                `Allocated Quantity (${detailUnit})`
                                                                                                            }
                                                                                                            value={
                                                                                                                getSafeNumber(
                                                                                                                    detailAllocation?.quantity
                                                                                                                )
                                                                                                            }
                                                                                                            inputProps={{
                                                                                                                min:
                                                                                                                    0,
                                                                                                                max:
                                                                                                                    detailQuantity,
                                                                                                                step:
                                                                                                                    "any"
                                                                                                            }}
                                                                                                            onChange={
                                                                                                                (
                                                                                                                    event
                                                                                                                ) =>
                                                                                                                    updateAllocation(
                                                                                                                        beneficiaryIndex,
                                                                                                                        serviceItem,
                                                                                                                        detailItem,
                                                                                                                        "quantity",
                                                                                                                        event.target.value
                                                                                                                    )
                                                                                                            }
                                                                                                        />

                                                                                                    )
                                                                                                    : null
                                                                                            }


                                                                                            <TextField
                                                                                                fullWidth
                                                                                                type="number"
                                                                                                label={
                                                                                                    detailMonetary
                                                                                                        ? "Allocated Amount (ETB)"
                                                                                                        : "Allocated Value (ETB)"
                                                                                                }
                                                                                                value={
                                                                                                    getSafeNumber(
                                                                                                        detailAllocation?.allocatedValue
                                                                                                    )
                                                                                                }
                                                                                                inputProps={{
                                                                                                    min:
                                                                                                        0,
                                                                                                    max:
                                                                                                        detailTotal,
                                                                                                    step:
                                                                                                        "any"
                                                                                                }}
                                                                                                onChange={
                                                                                                    (
                                                                                                        event
                                                                                                    ) =>
                                                                                                        updateAllocation(
                                                                                                            beneficiaryIndex,
                                                                                                            serviceItem,
                                                                                                            detailItem,
                                                                                                            "allocatedValue",
                                                                                                            event.target.value
                                                                                                        )
                                                                                                }
                                                                                            />

                                                                                        </Box>


                                                                                        <Box
                                                                                            sx={{
                                                                                                mt:
                                                                                                    1,
                                                                                                display:
                                                                                                    "flex",
                                                                                                justifyContent:
                                                                                                    "flex-end"
                                                                                            }}
                                                                                        >

                                                                                            <AppButton
                                                                                                type="button"
                                                                                                variant="outlined"
                                                                                                size="small"
                                                                                                onClick={
                                                                                                    () =>
                                                                                                        applyFullAllocation(
                                                                                                            beneficiaryIndex,
                                                                                                            serviceItem,
                                                                                                            detailItem
                                                                                                        )
                                                                                                }
                                                                                            >
                                                                                                Apply Full Detail Item
                                                                                            </AppButton>

                                                                                        </Box>

                                                                                    </Box>

                                                                                );

                                                                            }
                                                                        )
                                                                    }

                                                                </Box>

                                                            )
                                                            : null
                                                    }


                                                    {/* =========================================
                                                        APPLY FULL PARENT
                                                    ========================================= */}

                                                    {
                                                        !detailItems.length
                                                            ? (

                                                                <Box
                                                                    sx={{
                                                                        mt:
                                                                            1,
                                                                        display:
                                                                            "flex",
                                                                        justifyContent:
                                                                            "flex-end"
                                                                    }}
                                                                >

                                                                    <AppButton
                                                                        type="button"
                                                                        variant="outlined"
                                                                        size="small"
                                                                        onClick={
                                                                            () =>
                                                                                applyFullAllocation(
                                                                                    beneficiaryIndex,
                                                                                    serviceItem
                                                                                )
                                                                        }
                                                                    >
                                                                        Apply Full Item
                                                                    </AppButton>

                                                                </Box>

                                                            )
                                                            : null
                                                    }

                                                </Box>

                                            );

                                        }
                                    )
                                }

                            </Paper>

                        );

                    }
                )
            }


            {/* =================================================
                ALLOCATION SUMMARY
            ================================================= */}

            <Box
                sx={{
                    mt: 2
                }}
            >

                <Typography
                    variant="h6"
                    sx={{
                        mb: 2
                    }}
                >
                    Allocation Summary
                </Typography>


                {
                    validItems.map(
                        (
                            serviceItem
                        ) => {

                            const serviceItemId =
                                getServiceItemId(
                                    serviceItem
                                );

                            const summary =
                                getItemAllocationSummary(
                                    serviceItem
                                );

                            const unitLabel =
                                getServiceItemUnit(
                                    serviceItem,
                                    safeUnitOptions
                                );

                            const serviceItemLabel =
                                getServiceItemDisplayName(
                                    serviceItem,
                                    safeServiceTypeOptions
                                );

                            const detailItems =
                                Array.isArray(
                                    serviceItem?.detailItems
                                )
                                    ? serviceItem.detailItems
                                    : [];


                            return (

                                <Paper
                                    key={
                                        `summary-${serviceItemId}`
                                    }
                                    variant="outlined"
                                    sx={{
                                        mb: 2,
                                        p: 2
                                    }}
                                >

                                    <Typography
                                        variant="subtitle1"
                                        fontWeight={600}
                                        sx={{
                                            mb: 1
                                        }}
                                    >
                                        {
                                            serviceItemLabel
                                        }
                                    </Typography>


                                    {
                                        summary.monetary
                                            ? (

                                                <Box>

                                                    <Typography
                                                        variant="body2"
                                                    >
                                                        Actual Delivery Cost:
                                                        {" "}
                                                        ETB{" "}
                                                        {
                                                            formatMoney(
                                                                summary.itemTotal
                                                            )
                                                        }
                                                    </Typography>


                                                    <Typography
                                                        variant="body2"
                                                    >
                                                        Explicitly Allocated Value:
                                                        {" "}
                                                        ETB{" "}
                                                        {
                                                            formatMoney(
                                                                summary.allocatedValue
                                                            )
                                                        }
                                                    </Typography>


                                                    <Typography
                                                        variant="body2"
                                                        fontWeight={600}
                                                        sx={{
                                                            mt:
                                                                0.5
                                                        }}
                                                    >
                                                        Unallocated Delivery Cost:
                                                        {" "}
                                                        ETB{" "}
                                                        {
                                                            formatMoney(
                                                                summary.unallocatedValue
                                                            )
                                                        }
                                                    </Typography>


                                                    <Typography
                                                        variant="caption"
                                                        color="text.secondary"
                                                        sx={{
                                                            display:
                                                                "block",
                                                            mt:
                                                                1
                                                        }}
                                                    >
                                                        Physical quantity is not applicable
                                                        to monetary items.
                                                    </Typography>

                                                </Box>

                                            )
                                            : (

                                                <Box>

                                                    <Typography
                                                        variant="body2"
                                                    >
                                                        Allocation Behavior:
                                                        {" "}
                                                        {
                                                            summary.allocationBehavior ===
                                                            PARTICIPATION
                                                                ? "Participation"
                                                                : "Consumption"
                                                        }
                                                    </Typography>


                                                    <Typography
                                                        variant="body2"
                                                        sx={{
                                                            mt:
                                                                0.5
                                                        }}
                                                    >
                                                        Delivered Quantity:
                                                        {" "}
                                                        {
                                                            summary.deliveryQuantity
                                                        }
                                                        {" "}
                                                        {
                                                            unitLabel
                                                        }
                                                    </Typography>


                                                    <Typography
                                                        variant="body2"
                                                        sx={{
                                                            mt:
                                                                0.5
                                                        }}
                                                    >
                                                        {
                                                            summary.allocationBehavior ===
                                                            PARTICIPATION
                                                                ? "Total Participation"
                                                                : "Explicitly Allocated Quantity"
                                                        }
                                                        :
                                                        {" "}
                                                        {
                                                            summary.allocatedQuantity
                                                        }
                                                        {" "}
                                                        {
                                                            unitLabel
                                                        }
                                                    </Typography>


                                                    {
                                                        summary.allocationBehavior ===
                                                        CONSUMPTION
                                                            ? (

                                                                <Typography
                                                                    variant="body2"
                                                                    fontWeight={600}
                                                                    sx={{
                                                                        mt:
                                                                            0.5
                                                                    }}
                                                                >
                                                                    Unallocated Quantity:
                                                                    {" "}
                                                                    {
                                                                        summary.unallocatedQuantity
                                                                    }
                                                                    {" "}
                                                                    {
                                                                        unitLabel
                                                                    }
                                                                </Typography>

                                                            )
                                                            : (

                                                                <Typography
                                                                    variant="caption"
                                                                    color="text.secondary"
                                                                    sx={{
                                                                        display:
                                                                            "block",
                                                                        mt:
                                                                            0.5
                                                                    }}
                                                                >
                                                                    Participation is beneficiary-based;
                                                                    aggregate participation may exceed
                                                                    the actual delivered quantity.
                                                                </Typography>

                                                            )
                                                    }


                                                    <Divider
                                                        sx={{
                                                            my:
                                                                1.5
                                                        }}
                                                    />


                                                    <Typography
                                                        variant="body2"
                                                    >
                                                        Actual Delivery Cost:
                                                        {" "}
                                                        ETB{" "}
                                                        {
                                                            formatMoney(
                                                                summary.itemTotal
                                                            )
                                                        }
                                                    </Typography>


                                                    <Typography
                                                        variant="body2"
                                                        sx={{
                                                            mt:
                                                                0.5
                                                        }}
                                                    >
                                                        Explicitly Allocated Value:
                                                        {" "}
                                                        ETB{" "}
                                                        {
                                                            formatMoney(
                                                                summary.allocatedValue
                                                            )
                                                        }
                                                    </Typography>


                                                    <Typography
                                                        variant="body2"
                                                        fontWeight={600}
                                                        sx={{
                                                            mt:
                                                                0.5
                                                        }}
                                                    >
                                                        Unallocated Delivery Cost:
                                                        {" "}
                                                        ETB{" "}
                                                        {
                                                            formatMoney(
                                                                summary.unallocatedValue
                                                            )
                                                        }
                                                    </Typography>


                                                    {/* =====================================
                                                        DETAIL BREAKDOWN
                                                    ===================================== */}

                                                    {
                                                        detailItems.length
                                                            ? (

                                                                <Box
                                                                    sx={{
                                                                        mt:
                                                                            2
                                                                    }}
                                                                >

                                                                    <Divider
                                                                        sx={{
                                                                            mb:
                                                                                1.5
                                                                        }}
                                                                    />


                                                                    <Typography
                                                                        variant="subtitle2"
                                                                        fontWeight={600}
                                                                        sx={{
                                                                            mb:
                                                                                1
                                                                        }}
                                                                    >
                                                                        Detail Item Allocation Breakdown
                                                                    </Typography>


                                                                    {
                                                                        detailItems.map(
                                                                            (
                                                                                detailItem
                                                                            ) => {

                                                                                const detailItemId =
                                                                                    normalizeId(
                                                                                        detailItem?._id ??
                                                                                        detailItem?.id
                                                                                    );

                                                                                if (
                                                                                    !detailItemId
                                                                                ) {

                                                                                    return null;

                                                                                }


                                                                                const detailUnit =
                                                                                    getUnitDisplay(
                                                                                        detailItem.unit,
                                                                                        safeUnitOptions
                                                                                    );


                                                                                const detailQuantity =
                                                                                    getSafeNumber(
                                                                                        detailItem.quantity
                                                                                    );


                                                                                const detailTotal =
                                                                                    getDetailItemTotal(
                                                                                        detailItem
                                                                                    );


                                                                                const aggregate =
                                                                                    getDetailAggregate(
                                                                                        safeBeneficiaries,
                                                                                        serviceItemId,
                                                                                        detailItemId
                                                                                    );


                                                                                const detailSemantics =
                                                                                    getUnitSemantics(
                                                                                        {
                                                                                            unit:
                                                                                                detailItem.unit
                                                                                        },
                                                                                        safeUnitOptions
                                                                                    );


                                                                                const detailMonetary =
                                                                                    detailSemantics ===
                                                                                    "monetary";


                                                                                const detailAllocatedQuantity =
                                                                                    detailMonetary
                                                                                        ? 0
                                                                                        : Math.min(
                                                                                            detailQuantity,
                                                                                            aggregate.quantity
                                                                                        );


                                                                                const detailUnallocatedQuantity =
                                                                                    detailMonetary
                                                                                        ? 0
                                                                                        : summary.allocationBehavior ===
                                                                                          PARTICIPATION
                                                                                            ? 0
                                                                                            : Math.max(
                                                                                                0,
                                                                                                detailQuantity -
                                                                                                detailAllocatedQuantity
                                                                                            );


                                                                                const detailAllocatedValue =
                                                                                    Math.min(
                                                                                        detailTotal,
                                                                                        aggregate.allocatedValue
                                                                                    );


                                                                                return (

                                                                                    <Box
                                                                                        key={
                                                                                            detailItemId
                                                                                        }
                                                                                        sx={{
                                                                                            mb:
                                                                                                1.5
                                                                                        }}
                                                                                    >

                                                                                        <Typography
                                                                                            variant="body2"
                                                                                            fontWeight={600}
                                                                                        >
                                                                                            {
                                                                                                detailItem?.name ||
                                                                                                "Detail Item"
                                                                                            }
                                                                                        </Typography>


                                                                                        <Typography
                                                                                            variant="body2"
                                                                                            color="text.secondary"
                                                                                        >

                                                                                            Delivered:
                                                                                            {" "}
                                                                                            {
                                                                                                detailQuantity
                                                                                            }
                                                                                            {" "}
                                                                                            {
                                                                                                detailUnit
                                                                                            }

                                                                                            {" "}•
                                                                                            Allocated:
                                                                                            {" "}
                                                                                            {
                                                                                                detailAllocatedQuantity
                                                                                            }
                                                                                            {" "}
                                                                                            {
                                                                                                detailUnit
                                                                                            }

                                                                                            {
                                                                                                !detailMonetary &&
                                                                                                summary.allocationBehavior ===
                                                                                                CONSUMPTION
                                                                                                    ? (
                                                                                                        <>
                                                                                                            {" "}•
                                                                                                            Unallocated:
                                                                                                            {" "}
                                                                                                            {
                                                                                                                detailUnallocatedQuantity
                                                                                                            }
                                                                                                            {" "}
                                                                                                            {
                                                                                                                detailUnit
                                                                                                            }
                                                                                                        </>
                                                                                                    )
                                                                                                    : null
                                                                                            }

                                                                                        </Typography>


                                                                                        <Typography
                                                                                            variant="body2"
                                                                                            color="text.secondary"
                                                                                        >

                                                                                            Actual Detail Cost:
                                                                                            {" "}
                                                                                            ETB{" "}
                                                                                            {
                                                                                                formatMoney(
                                                                                                    detailTotal
                                                                                                )
                                                                                            }

                                                                                            {" "}•
                                                                                            Explicitly Allocated Value:
                                                                                            {" "}
                                                                                            ETB{" "}
                                                                                            {
                                                                                                formatMoney(
                                                                                                    detailAllocatedValue
                                                                                                )
                                                                                            }

                                                                                        </Typography>

                                                                                    </Box>

                                                                                );

                                                                            }
                                                                        )
                                                                    }

                                                                </Box>

                                                            )
                                                            : null
                                                    }

                                                </Box>

                                            )
                                    }

                                </Paper>

                            );

                        }
                    )
                }

            </Box>

        </Box>

    );

};


export default ServiceDeliveryAllocations;