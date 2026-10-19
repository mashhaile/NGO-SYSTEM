import {
    useEffect,
    useState
} from "react";


import {
    useNavigate,
    useParams
} from "react-router-dom";


import {
    Box,
    Grid,
    Paper,
    Stack,
    Typography,
    Divider,
    Chip
} from "@mui/material";


import {
    Edit,
    People,
    Inventory2,
    Payments,
    Numbers,
    LocationOn,
    CalendarMonth
} from "@mui/icons-material";


import {
    getServiceDeliveryByIdService
} from "../services/serviceDeliveryService";


import {
    PageContainer,
    PageHeader,
    LoadingState,
    AppButton,
    StatusChip
} from "../../../components/ui";

// funding source 

const getFundingText = (value) => {
    if (!value) return "";

    if (typeof value === "string") {
        return value.trim();
    }

    return (
        value.name ||
        value.value ||
        value.title ||
        value.donationCode ||
        value.code ||
        ""
    );
};

const getItemFunding = (item) => {
    const donor = getFundingText(item?.donor);

    const donation =
        item?.donation && typeof item.donation === "object"
            ? [
                item.donation.donationCode,
                item.donation.title,
            ].filter(Boolean).join(" — ")
            : getFundingText(item?.donation);

    const currency = item?.donation?.currency || "";
    const fundingSource = getFundingText(
        item?.donation?.fundingSource
    );

    return {
        donor,
        donation,
        currency,
        fundingSource,
    };
};
// =====================================================
// LEGACY MONETARY UNIT CODES
// =====================================================

const MONETARY_UNIT_CODES = [
    "AMOUNT",
    "ETB",
    "BIRR",
    "MONEY",
    "CASH"
];


// =====================================================
// NORMALIZE UNIT CODE
// =====================================================

const normalizeUnitCode = (
    value
) => {

    if (
        value === null ||
        value === undefined ||
        value === ""
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
// GET UNIT CODE
// =====================================================

const getUnitCode = (
    unit
) => {

    if (
        unit === null ||
        unit === undefined ||
        unit === ""
    ) {

        return "";

    }

    if (
        typeof unit === "object"
    ) {

        return normalizeUnitCode(
            unit?.code ??
            unit?.unitCode ??
            unit?.lookupCode ??
            unit?.value ??
            unit?.label ??
            unit?.name ??
            unit?.text ??
            ""
        );

    }

    return normalizeUnitCode(
        unit
    );

};


// =====================================================
// NORMALIZE SEMANTIC TYPE
// =====================================================

const normalizeSemanticType = (
    value
) => {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {

        return null;

    }

    const normalized =
        String(
            value
        )
            .trim()
            .toLowerCase();

    if (
        normalized === "monetary"
    ) {

        return "monetary";

    }

    if (
        normalized === "physical"
    ) {

        return "physical";

    }

    return null;

};


// =====================================================
// GET UNIT SEMANTIC TYPE
// =====================================================

const getUnitSemanticType = (
    unit
) => {

    if (
        unit &&
        typeof unit === "object"
    ) {

        const semanticType =
            normalizeSemanticType(
                unit?.semanticType
            );

        if (
            semanticType
        ) {

            return semanticType;

        }

    }

    const unitCode =
        getUnitCode(
            unit
        );

    if (
        MONETARY_UNIT_CODES.includes(
            unitCode
        )
    ) {

        return "monetary";

    }

    return "physical";

};


// =====================================================
// CHECK MONETARY UNIT
// =====================================================

const isMonetaryUnit = (
    unit
) => {

    return (
        getUnitSemanticType(
            unit
        ) === "monetary"
    );

};


// =====================================================
// NORMALIZE ALLOCATION BEHAVIOR
// =====================================================

const normalizeAllocationBehavior = (
    value
) => {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {

        return null;

    }

    const normalized =
        String(
            value
        )
            .trim()
            .toUpperCase();

    if (
        normalized === "PARTICIPATION"
    ) {

        return "PARTICIPATION";

    }

    if (
        normalized === "CONSUMPTION"
    ) {

        return "CONSUMPTION";

    }

    return null;

};


// =====================================================
// GET ALLOCATION BEHAVIOR
// =====================================================

const getAllocationBehavior = (
    serviceItem
) => {

    const directBehavior =
        normalizeAllocationBehavior(
            serviceItem?.allocationBehavior
        );

    if (
        directBehavior
    ) {

        return directBehavior;

    }

    const serviceTypeBehavior =
        normalizeAllocationBehavior(
            serviceItem?.serviceType?.allocationBehavior
        );

    if (
        serviceTypeBehavior
    ) {

        return serviceTypeBehavior;

    }

    return "CONSUMPTION";

};


// =====================================================
// RESPONSE DATA
// =====================================================

const getResponseData = (
    response
) => {

    const root =
        response?.data ??
        response ??
        null;

    if (
        root &&
        typeof root === "object"
    ) {

        if (
            root?.data &&
            typeof root.data === "object" &&
            !Array.isArray(
                root.data
            )
        ) {

            if (
                root.data._id ||
                root.data.items ||
                root.data.deliveryNumber
            ) {

                return root.data;

            }

            if (
                root.data.data &&
                typeof root.data.data === "object" &&
                !Array.isArray(
                    root.data.data
                )
            ) {

                return root.data.data;

            }

        }

        if (
            root?._id ||
            root?.items ||
            root?.deliveryNumber
        ) {

            return root;

        }

    }

    return null;

};


// =====================================================
// SERVICE ITEMS
// =====================================================

const normalizeServiceItems = (
    delivery
) => {

    if (
        Array.isArray(
            delivery?.items
        )
    ) {

        return delivery.items;

    }

    if (
        Array.isArray(
            delivery?.serviceItems
        )
    ) {

        return delivery.serviceItems;

    }

    if (
        Array.isArray(
            delivery?.data?.items
        )
    ) {

        return delivery.data.items;

    }

    return [];

};


// =====================================================
// LOOKUP
// =====================================================

const getLookupValue = (
    value
) => {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {

        return "-";

    }

    if (
        typeof value === "object"
    ) {

        return String(
            value?.value ??
            value?.label ??
            value?.name ??
            value?.text ??
            value?.code ??
            value?._id ??
            "-"
        );

    }

    return String(
        value
    );

};



// =====================================================
// BENEFICIARY NAME
// =====================================================

const getBeneficiaryName = (
    beneficiary
) => {

    if (
        !beneficiary
    ) {

        return "-";

    }

    if (
        typeof beneficiary === "string"
    ) {

        return beneficiary;

    }

    if (
        beneficiary?.name
    ) {

        return String(
            beneficiary.name
        );

    }

    if (
        beneficiary?.fullName
    ) {

        return String(
            beneficiary.fullName
        );

    }

    const fullName =
        [
            beneficiary?.firstName,
            beneficiary?.middleName,
            beneficiary?.lastName
        ]
            .filter(Boolean)
            .join(" ");

    return (
        fullName ||
        beneficiary?.beneficiaryNumber ||
        beneficiary?._id ||
        "-"
    );

};


// =====================================================
// DATE
// =====================================================

const formatDate = (
    value
) => {

    if (
        !value
    ) {

        return "-";

    }

    const date =
        new Date(
            value
        );

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {

        return "-";

    }

    return date.toLocaleDateString();

};


// =====================================================
// DATE TIME
// =====================================================

const formatDateTime = (
    value
) => {

    if (
        !value
    ) {

        return "-";

    }

    const date =
        new Date(
            value
        );

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {

        return "-";

    }

    return date.toLocaleString();

};


// =====================================================
// MONEY
// =====================================================

const formatMoney = (
    value
) => {

    return Number(
        value || 0
    ).toLocaleString(
        undefined,
        {
            minimumFractionDigits: 2,
            maximumFractionDigits: 2
        }
    );

};


// =====================================================
// NUMERIC
// =====================================================

const getNumber = (
    value,
    fallback = 0
) => {

    const number =
        Number(
            value
        );

    return Number.isFinite(
        number
    )
        ? number
        : fallback;

};


// =====================================================
// FORMAT QUANTITY
// =====================================================

const formatQuantity = (
    quantity
) => {

    const number =
        getNumber(
            quantity,
            0
        );

    if (
        Number.isInteger(
            number
        )
    ) {

        return String(
            number
        );

    }

    return number.toLocaleString(
        undefined,
        {
            maximumFractionDigits: 2
        }
    );

};


// =====================================================
// UNIT PLURALIZATION
// =====================================================

const pluralizeUnit = (
    unit,
    quantity
) => {

    if (
        !unit
    ) {

        return "";

    }

    const number =
        getNumber(
            quantity,
            0
        );

    if (
        number === 1
    ) {

        return unit;

    }

    switch (
        String(unit)
            .trim()
            .toLowerCase()
    ) {

        case "box":
            return "Boxes";

        case "pair":
            return "Pairs";

        case "day":
            return "Days";

        case "pack":
            return "Packs";

        case "piece":
            return "Pieces";

        default:
            return `${unit}s`;

    }

};


// =====================================================
// SUMMARY CARD
// =====================================================

const SummaryCard = ({
    icon,
    label,
    value,
    subtitle
}) => {

    return (

        <Paper
            elevation={0}
            sx={{
                p: 2.5,
                height: "100%",
                border: "1px solid",
                borderColor: "divider",
                borderRadius: 2
            }}
        >

            <Stack
                direction="row"
                spacing={2}
                alignItems="center"
            >

                <Box
                    sx={{
                        width: 46,
                        height: 46,
                        borderRadius: 2,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        bgcolor: "action.hover"
                    }}
                >

                    {icon}

                </Box>


                <Box
                    sx={{
                        minWidth: 0
                    }}
                >

                    <Typography
                        variant="body2"
                        color="text.secondary"
                    >
                        {label}
                    </Typography>


                    <Typography
                        variant="h6"
                        fontWeight={700}
                        sx={{
                            mt: 0.25
                        }}
                    >
                        {value}
                    </Typography>


                    {
                        subtitle && (

                            <Typography
                                variant="caption"
                                color="text.secondary"
                            >
                                {subtitle}
                            </Typography>

                        )
                    }

                </Box>

            </Stack>

        </Paper>

    );

};


// =====================================================
// SECTION
// =====================================================

const DetailSection = ({
    title,
    subtitle,
    children
}) => {

    return (

        <Paper
            elevation={0}
            sx={{
                border: "1px solid",
                borderColor: "divider",
                borderRadius: 2,
                overflow: "hidden"
            }}
        >

            <Box
                sx={{
                    px: 2.5,
                    py: 2,
                    bgcolor: "background.default"
                }}
            >

                <Typography
                    variant="h6"
                    fontWeight={700}
                >
                    {title}
                </Typography>


                {
                    subtitle && (

                        <Typography
                            variant="body2"
                            color="text.secondary"
                            sx={{
                                mt: 0.25
                            }}
                        >
                            {subtitle}
                        </Typography>

                    )
                }

            </Box>


            <Divider />


            <Box
                sx={{
                    p: 2.5
                }}
            >

                {children}

            </Box>

        </Paper>

    );

};


// =====================================================
// INFO FIELD
// =====================================================

const DetailField = ({
    label,
    value
}) => {

    return (

        <Box>

            <Typography
                variant="caption"
                color="text.secondary"
                sx={{
                    display: "block",
                    mb: 0.5
                }}
            >
                {label}
            </Typography>


            <Typography
                variant="body1"
                fontWeight={600}
            >
                {value || "-"}
            </Typography>

        </Box>

    );

};


// =====================================================
// RECIPIENT NAME LABEL
// =====================================================

const getRecipientNameLabel = (
    recipientType
) => {

    switch (
        recipientType
    ) {

        case "Household":
            return "Household Name / Identifier";

        case "Group / Community":
            return "Group / Community Name";

        case "Institution":
            return "Institution Name";

        default:
            return "Recipient Name";

    }

};


// =====================================================
// RECIPIENT NAME REQUIRED
// =====================================================

const requiresRecipientName = (
    recipientType
) => {

    return (
        recipientType === "Household" ||
        recipientType === "Group / Community" ||
        recipientType === "Institution"
    );

};


// =====================================================
// GET SERVICE ITEM FROM ALLOCATION
// =====================================================

const getServiceItemFromAllocation = (
    allocation,
    items
) => {

    const allocationItem =
        allocation?.serviceItem;

    if (
        allocationItem &&
        typeof allocationItem === "object"
    ) {

        return allocationItem;

    }

    if (
        allocationItem === null ||
        allocationItem === undefined ||
        allocationItem === ""
    ) {

        return null;

    }

    return items.find(
        (
            item
        ) =>
            String(
                item?._id
            ) ===
            String(
                allocationItem
            )
    ) || null;

};


// =====================================================
// GET DETAIL ITEM FROM ALLOCATION
// =====================================================

const getDetailItemFromAllocation = (
    allocation,
    serviceItem
) => {

    const detailItem =
        allocation?.detailItem;

    if (
        detailItem &&
        typeof detailItem === "object"
    ) {

        return detailItem;

    }

    if (
        detailItem === null ||
        detailItem === undefined ||
        detailItem === ""
    ) {

        return null;

    }

    const detailItems =
        Array.isArray(
            serviceItem?.detailItems
        )
            ? serviceItem.detailItems
            : [];

    return detailItems.find(
        (
            item
        ) =>
            String(
                item?._id
            ) ===
            String(
                detailItem
            )
    ) || null;

};


// =====================================================
// GET ITEM TOTAL
// =====================================================

const getServiceItemTotal = (
    item
) => {

    const quantity =
        getNumber(
            item?.quantity,
            0
        );

    const unitCost =
        getNumber(
            item?.unitCost,
            0
        );

    if (
        item?.totalCost !== undefined &&
        item?.totalCost !== null
    ) {

        return getNumber(
            item.totalCost,
            quantity * unitCost
        );

    }

    return quantity * unitCost;

};


// =====================================================
// GET DETAIL ITEMS
// =====================================================

const getDetailItems = (
    item
) => {

    if (
        Array.isArray(
            item?.detailItems
        )
    ) {

        return item.detailItems;

    }

    return [];

};


// =====================================================
// DETAIL ITEM TOTAL
// =====================================================

const getDetailItemTotal = (
    detailItem
) => {

    const quantity =
        getNumber(
            detailItem?.quantity,
            0
        );

    const unitCost =
        getNumber(
            detailItem?.unitCost,
            0
        );

    if (
        detailItem?.totalCost !== undefined &&
        detailItem?.totalCost !== null
    ) {

        return getNumber(
            detailItem.totalCost,
            quantity * unitCost
        );

    }

    return quantity * unitCost;

};


// =====================================================
// ALLOCATION DISPLAY
// =====================================================

const getAllocationDisplay = (
    allocation,
    serviceItem
) => {

    const detailItem =
        getDetailItemFromAllocation(
            allocation,
            serviceItem
        );

    const quantity =
        getNumber(
            allocation?.quantity,
            0
        );

    const allocatedValue =
        getNumber(
            allocation?.allocatedValue,
            0
        );

    /*
     * IMPORTANT:
     *
     * Detail allocations use the detail item's
     * own unit. Parent allocations use the parent
     * service item's unit.
     */
    const allocationUnit =
        detailItem?.unit ||
        serviceItem?.unit;

    const unit =
        getLookupValue(
            allocationUnit
        );

    const isMonetary =
        isMonetaryUnit(
            allocationUnit
        );

    const allocationBehavior =
        getAllocationBehavior(
            serviceItem
        );

    if (
        isMonetary
    ) {

        return {

            primary:
                `Allocated Amount: ETB ${formatMoney(
                    allocatedValue
                )}`,

            secondary:
                allocatedValue > 0
                    ? "Beneficiary-attributable financial value"
                    : "No beneficiary-level financial allocation declared"

        };

    }

    const quantityText =
        `Allocated Quantity: ${formatQuantity(
            quantity
        )} ${pluralizeUnit(
            unit,
            quantity
        )}`;

    const valueText =
        allocatedValue > 0
            ? `ETB ${formatMoney(
                allocatedValue
            )}`
            : "";

    if (
        allocationBehavior ===
        "PARTICIPATION"
    ) {

        return {

            primary:
                quantityText,

            secondary:
                valueText
                    ? `Participation • Allocated Value: ${valueText}`
                    : "Participation • Each beneficiary is recorded independently against the delivered quantity"

        };

    }

    return {

        primary:
            quantityText,

        secondary:
            valueText
                ? `Allocated Value: ${valueText}`
                : `Unit: ${unit}`

    };

};


// =====================================================
// PHYSICAL QUANTITY SUMMARY
// =====================================================

const getPhysicalQuantitySummary = (
    items
) => {

    const physicalItems =
        items.filter(
            (
                item
            ) =>
                !isMonetaryUnit(
                    item?.unit
                ) &&
                getNumber(
                    item?.quantity,
                    0
                ) > 0
        );

    if (
        physicalItems.length === 0
    ) {

        return "Not applicable";

    }

    const grouped =
        new Map();

    physicalItems.forEach(
        (
            item
        ) => {

            const unit =
                getLookupValue(
                    item?.unit
                );

            const quantity =
                getNumber(
                    item?.quantity,
                    0
                );

            const existing =
                grouped.get(
                    unit
                ) || 0;

            grouped.set(
                unit,
                existing + quantity
            );

        }
    );

   const summaryEntries =
    Array.from(
        grouped.entries()
    )
        .filter(
            (
                [
                    ,
                    quantity
                ]
            ) =>
                getNumber(
                    quantity,
                    0
                ) > 0
        );

if (
    summaryEntries.length === 0
) {

    return "0";

}

return summaryEntries
    .map(
        (
            [
                unit,
                quantity
            ]
        ) =>
            `${formatQuantity(
                quantity
            )} ${pluralizeUnit(
                unit,
                quantity
            )}`
    )
    .join(
        " + "
    );

};


// =====================================================
// ALLOCATED CONSUMPTION QUANTITY SUMMARY
// =====================================================

const getAllocatedConsumptionQuantitySummary = (
    items,
    beneficiaryRecords
) => {

    const grouped =
        new Map();

    beneficiaryRecords.forEach(
        (
            record
        ) => {

            const allocations =
                Array.isArray(
                    record?.allocations
                )
                    ? record.allocations
                    : [];

            allocations.forEach(
                (
                    allocation
                ) => {

                    const serviceItem =
                        getServiceItemFromAllocation(
                            allocation,
                            items
                        );

                    if (
                        !serviceItem
                    ) {

                        return;

                    }

                    if (
                        getAllocationBehavior(
                            serviceItem
                        ) !==
                        "CONSUMPTION"
                    ) {

                        return;

                    }

                    const detailItem =
                        getDetailItemFromAllocation(
                            allocation,
                            serviceItem
                        );

                    /*
                     * IMPORTANT:
                     *
                     * If this is a detail allocation,
                     * use the detail unit.
                     *
                     * If this is a parent allocation,
                     * use the parent unit.
                     */
                    const allocationUnit =
                        detailItem?.unit ||
                        serviceItem?.unit;

                    if (
                        isMonetaryUnit(
                            allocationUnit
                        )
                    ) {

                        return;

                    }

                    const quantity =
                        getNumber(
                            allocation?.quantity,
                            0
                        );

                    if (
                        quantity <= 0
                    ) {

                        return;

                    }

                    const unit =
                        getLookupValue(
                            allocationUnit
                        );

                    const existing =
                        grouped.get(
                            unit
                        ) || 0;

                    grouped.set(
                        unit,
                        existing + quantity
                    );

                }
            );

        }
    );

    if (
        grouped.size === 0
    ) {

        return "0";

    }

    return Array.from(
        grouped.entries()
    )
        .map(
            (
                [
                    unit,
                    quantity
                ]
            ) =>
                `${formatQuantity(
                    quantity
                )} ${pluralizeUnit(
                    unit,
                    quantity
                )}`
        )
        .join(
            " + "
        );

};


// =====================================================
// TOTAL BENEFICIARY PARTICIPATION SUMMARY
// =====================================================

const getBeneficiaryParticipationSummary = (
    items,
    beneficiaryRecords
) => {

    const grouped =
        new Map();

    beneficiaryRecords.forEach(
        (
            record
        ) => {

            const allocations =
                Array.isArray(
                    record?.allocations
                )
                    ? record.allocations
                    : [];

            allocations.forEach(
                (
                    allocation
                ) => {

                    const serviceItem =
                        getServiceItemFromAllocation(
                            allocation,
                            items
                        );

                    if (
                        !serviceItem
                    ) {

                        return;

                    }

                    if (
                        getAllocationBehavior(
                            serviceItem
                        ) !==
                        "PARTICIPATION"
                    ) {

                        return;

                    }

                    const detailItem =
                        getDetailItemFromAllocation(
                            allocation,
                            serviceItem
                        );

                    /*
                     * Participation detail allocations
                     * must also retain their own unit.
                     */
                    const allocationUnit =
                        detailItem?.unit ||
                        serviceItem?.unit;

                    if (
                        isMonetaryUnit(
                            allocationUnit
                        )
                    ) {

                        return;

                    }

                    const quantity =
                        getNumber(
                            allocation?.quantity,
                            0
                        );

                    if (
                        quantity <= 0
                    ) {

                        return;

                    }

                    const unit =
                        getLookupValue(
                            allocationUnit
                        );

                    const existing =
                        grouped.get(
                            unit
                        ) || 0;

                    grouped.set(
                        unit,
                        existing + quantity
                    );

                }
            );

        }
    );

    if (
        grouped.size === 0
    ) {

        return "0";

    }

    return Array.from(
        grouped.entries()
    )
        .map(
            (
                [
                    unit,
                    quantity
                ]
            ) =>
                `${formatQuantity(
                    quantity
                )} ${pluralizeUnit(
                    unit,
                    quantity
                )}`
        )
        .join(
            " + "
        );

};



const getUnallocatedPhysicalQuantitySummary = (
    items,
    beneficiaryRecords
) => {
    const directAllocatedByItem = new Map();
    const detailAllocatedByItem = new Map();

    // Collect allocations by parent service item and detail item.
    beneficiaryRecords.forEach((record) => {
        const allocations = Array.isArray(record?.allocations)
            ? record.allocations
            : [];

        allocations.forEach((allocation) => {
            const serviceItem = getServiceItemFromAllocation(
                allocation,
                items
            );

            if (!serviceItem) {
                return;
            }

            const quantity = getNumber(allocation?.quantity, 0);

            if (quantity <= 0) {
                return;
            }

            const detailItem = getDetailItemFromAllocation(
                allocation,
                serviceItem
            );

            if (detailItem) {
                const detailId = String(detailItem?._id);

                detailAllocatedByItem.set(
                    detailId,
                    (detailAllocatedByItem.get(detailId) || 0) + quantity
                );

                return;
            }

            if (isMonetaryUnit(serviceItem?.unit)) {
                return;
            }

            const itemId = String(serviceItem?._id);

            directAllocatedByItem.set(
                itemId,
                (directAllocatedByItem.get(itemId) || 0) + quantity
            );
        });
    });

    // Aggregate unallocated physical quantities by unit.
    const grouped = new Map();

    const addQuantity = (unit, quantity) => {
        if (
            !unit ||
            unit === "-" ||
            getNumber(quantity, 0) <= 0
        ) {
            return;
        }

        grouped.set(
            unit,
            (grouped.get(unit) || 0) + quantity
        );
    };

    items.forEach((item) => {
        if (isMonetaryUnit(item?.unit)) {
            return;
        }

        const itemId = String(item?._id);
        const allocationBehavior = getAllocationBehavior(item);
        const detailItems = getDetailItems(item);
        const hasDetails = detailItems.length > 0;

        // Participation allocations do not consume physical quantity.
        if (allocationBehavior === "PARTICIPATION") {
            return;
        }

        /*
         * When details exist, calculate physical quantities from
         * details only. Do not count the parent as a second pool.
         */
        if (hasDetails) {
            detailItems.forEach((detailItem) => {
                if (isMonetaryUnit(detailItem?.unit)) {
                    return;
                }

                const detailUnit = getLookupValue(detailItem?.unit);

                if (!detailUnit || detailUnit === "-") {
                    return;
                }

                const detailId = String(detailItem?._id);
                const delivered = getNumber(detailItem?.quantity, 0);
                const allocated = detailAllocatedByItem.get(detailId) || 0;

                const unallocated = Math.max(
                    0,
                    delivered - allocated
                );

                addQuantity(detailUnit, unallocated);
            });

            return;
        }

        // Without details, use the parent quantity pool.
        const parentUnit = getLookupValue(item?.unit);

        if (!parentUnit || parentUnit === "-") {
            return;
        }

        const delivered = getNumber(item?.quantity, 0);
        const allocated = directAllocatedByItem.get(itemId) || 0;

        const unallocated = Math.max(
            0,
            delivered - allocated
        );

        addQuantity(parentUnit, unallocated);
    });

    const summaryEntries = Array.from(grouped.entries())
        .filter(([, quantity]) => getNumber(quantity, 0) > 0);

    if (summaryEntries.length === 0) {
        return "0";
    }

    return summaryEntries
        .map(([unit, quantity]) =>
            `${formatQuantity(quantity)} ${pluralizeUnit(unit, quantity)}`
        )
        .join(" + ");
};
// =====================================================
// DIRECT PARENT ALLOCATED QUANTITY SUMMARY
// =====================================================

const getDirectParentAllocatedQuantitySummary = (
    items,
    beneficiaryRecords
) => {

    const grouped =
        new Map();


    beneficiaryRecords.forEach(
        (
            record
        ) => {

            const allocations =
                Array.isArray(
                    record?.allocations
                )
                    ? record.allocations
                    : [];


            allocations.forEach(
                (
                    allocation
                ) => {

                    const serviceItem =
                        getServiceItemFromAllocation(
                            allocation,
                            items
                        );


                    if (
                        !serviceItem
                    ) {

                        return;

                    }


                    const detailItem =
                        getDetailItemFromAllocation(
                            allocation,
                            serviceItem
                        );


                    /*
                     * Detail allocation does not consume
                     * parent quantity.
                     */
                    if (
                        detailItem
                    ) {

                        return;

                    }


                    if (
                        isMonetaryUnit(
                            serviceItem?.unit
                        )
                    ) {

                        return;

                    }


                    if (
                        getAllocationBehavior(
                            serviceItem
                        ) !==
                        "CONSUMPTION"
                    ) {

                        return;

                    }


                    const quantity =
                        getNumber(
                            allocation?.quantity,
                            0
                        );


                    if (
                        quantity <= 0
                    ) {

                        return;

                    }


                    const unit =
                        getLookupValue(
                            serviceItem?.unit
                        );


                    if (
                        !unit ||
                        unit === "-"
                    ) {

                        return;

                    }


                    const existing =
                        grouped.get(
                            unit
                        ) || 0;


                    grouped.set(
                        unit,
                        existing + quantity
                    );

                }
            );

        }
    );


    /*
     * -------------------------------------------------
     * NO DIRECT PARENT ALLOCATIONS
     * -------------------------------------------------
     *
     * Still display the parent unit.
     *
     * Example:
     * Delivered = 1 Box
     * Direct Parent Allocated = 0 Boxes
     *
     * Do not return plain "0".
     */
    if (
        grouped.size === 0
    ) {

        const parentUnits =
            new Map();


        items.forEach(
            (
                item
            ) => {

                if (
                    isMonetaryUnit(
                        item?.unit
                    )
                ) {

                    return;

                }


                if (
                    getAllocationBehavior(
                        item
                    ) !==
                    "CONSUMPTION"
                ) {

                    return;

                }


                const unit =
                    getLookupValue(
                        item?.unit
                    );


                if (
                    !unit ||
                    unit === "-"
                ) {

                    return;

                }


                parentUnits.set(
                    unit,
                    true
                );

            }
        );


        if (
            parentUnits.size === 0
        ) {

            return "0";

        }


        return Array.from(
            parentUnits.keys()
        )
            .map(
                (
                    unit
                ) =>
                    `0 ${pluralizeUnit(
                        unit,
                        0
                    )}`
            )
            .join(
                " + "
            );

    }


    return Array.from(
        grouped.entries()
    )
        .map(
            (
                [
                    unit,
                    quantity
                ]
            ) =>
                `${formatQuantity(
                    quantity
                )} ${pluralizeUnit(
                    unit,
                    quantity
                )}`
        )
        .join(
            " + "
        );

};

// =====================================================
// PAGE
// =====================================================

const ServiceDeliveryDetailsPage = () => {

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
        delivery,
        setDelivery
    ] = useState(
        null
    );


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

            const load =
                async () => {

                    try {

                        setLoading(
                            true
                        );

                        const response =
                            await getServiceDeliveryByIdService(
                                id
                            );

                        console.log(
                            "Service Delivery Details Response:",
                            response
                        );

                        const normalizedDelivery =
                            getResponseData(
                                response
                            );

                        console.log(
                            "Service Delivery Details Data:",
                            normalizedDelivery
                        );

                        console.log(
                            "Service Delivery Items:",
                            normalizedDelivery?.items
                        );

                        setDelivery(
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
                            error?.response?.data
                        );

                        setDelivery(
                            null
                        );

                    }

                    finally {

                        setLoading(
                            false
                        );

                    }

                };

            load();

        },
        [
            id
        ]
    );


    // =================================================
    // LOADING
    // =================================================

    if (
        loading
    ) {

        return (

            <PageContainer>

                <PageHeader
                    title="Service Delivery"
                    subtitle="Loading record..."
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
        !delivery
    ) {

        return (

            <PageContainer>

                <PageHeader
                    title="Service Delivery"
                    subtitle="Record not found"
                />

                <AppButton
                    variant="outlined"
                    onClick={() =>
                        navigate(
                            "/service-deliveries"
                        )
                    }
                    sx={{
                        mt: 3
                    }}
                >
                    Back to Service Deliveries
                </AppButton>

            </PageContainer>

        );

    }


    // =================================================
    // DATA
    // =================================================

    const items =
        normalizeServiceItems(
            delivery
        );

    const associations =
        Array.isArray(
            delivery.beneficiaries
        )
            ? delivery.beneficiaries
            : [];

    const beneficiaryRecords =
        associations.length > 0
            ? associations
            : (
                delivery.beneficiary
                    ? [
                        {
                            beneficiary:
                                delivery.beneficiary,
                            status:
                                "Received",
                            allocations:
                                []
                        }
                    ]
                    : []
            );

    const beneficiaryCount =
        beneficiaryRecords.length;


    // =================================================
    // PHYSICAL DELIVERY QUANTITY
    // =================================================

    const physicalQuantitySummary =
        getPhysicalQuantitySummary(
            items
        );


    // =================================================
    // TOTAL ACTUAL DELIVERY COST
    // =================================================

    const calculatedTotal =
        items.reduce(
            (
                total,
                item
            ) =>
                total +
                getServiceItemTotal(
                    item
                ),
            0
        );

    const totalAmount =
        delivery.totalAmount !== undefined &&
        delivery.totalAmount !== null
            ? getNumber(
                delivery.totalAmount,
                calculatedTotal
            )
            : calculatedTotal;


    const allocationMethod =
        delivery.allocationMethod ||
        "Individual";

    const recipientType =
        delivery.recipientType ||
        "Individual";

    const recipientName =
        typeof delivery.recipientName === "string"
            ? delivery.recipientName.trim()
            : "";

    const showRecipientName =
        requiresRecipientName(
            recipientType
        );


   
    // =================================================
    // PER-ITEM ALLOCATION ACCOUNTING
    // =================================================

    const itemAllocationSummary =
        items.map((item) => {
            const itemId = String(item?._id);

            const itemTotal =
                getServiceItemTotal(item);

            const allocationBehavior =
                getAllocationBehavior(item);

            const detailItems =
                getDetailItems(item);

            const hasDetails =
                detailItems.length > 0;

            let allocatedValue = 0;
            let allocatedQuantity = 0;

            /*
             * Direct parent allocations are kept separate
             * from detail allocations.
             *
             * Detail quantities never get added to the
             * parent's allocated quantity.
             */
            beneficiaryRecords.forEach((record) => {
                const allocations =
                    Array.isArray(record?.allocations)
                        ? record.allocations
                        : [];

                allocations.forEach((allocation) => {
                    const serviceItem =
                        getServiceItemFromAllocation(
                            allocation,
                            items
                        );

                    if (
                        !serviceItem ||
                        String(serviceItem?._id) !== itemId
                    ) {
                        return;
                    }

                    // Financial allocations from both parent
                    // and detail levels belong to this item.
                    allocatedValue += getNumber(
                        allocation?.allocatedValue,
                        0
                    );

                    const detailItem =
                        getDetailItemFromAllocation(
                            allocation,
                            serviceItem
                        );

                    // Do not count detail quantities as parent
                    // quantities, even when units happen to match.
                    if (detailItem) {
                        return;
                    }

                    if (
                        !isMonetaryUnit(serviceItem?.unit)
                    ) {
                        allocatedQuantity += getNumber(
                            allocation?.quantity,
                            0
                        );
                    }
                });
            });

            const unallocatedValue =
                Math.max(
                    0,
                    itemTotal - allocatedValue
                );

            const monetary =
                isMonetaryUnit(item?.unit);

            const deliveredQuantity =
                monetary
                    ? 0
                    : getNumber(item?.quantity, 0);

            let unallocatedQuantity = 0;

            /*
             * If detail items exist, the parent quantity
             * is delivery information only. Detail quantities
             * are accounted for in the detail summary below.
             */
            if (
                !monetary &&
                !hasDetails &&
                allocationBehavior !== "PARTICIPATION"
            ) {
                unallocatedQuantity =
                    Math.max(
                        0,
                        deliveredQuantity - allocatedQuantity
                    );
            }

            return {
                item,
                itemTotal,
                allocatedValue,
                unallocatedValue,
                deliveredQuantity,
                allocatedQuantity,
                unallocatedQuantity,
                allocationBehavior
            };
        });


    // =================================================
    // TOTAL ALLOCATED VALUE
    // =================================================

    const totalAllocatedValue =
        itemAllocationSummary.reduce(
            (total, summary) =>
                total + summary.allocatedValue,
            0
        );


    // =================================================
    // TOTAL UNALLOCATED VALUE
    // =================================================

    const unallocatedValue =
        itemAllocationSummary.reduce(
            (total, summary) =>
                total + summary.unallocatedValue,
            0
        );


    // =================================================
    // UNIT-AWARE PHYSICAL SUMMARIES
    // =================================================

    const totalAllocatedQuantitySummary =
        getDirectParentAllocatedQuantitySummary(
            items,
            beneficiaryRecords
        );

    const unallocatedPhysicalQuantitySummary =
        getUnallocatedPhysicalQuantitySummary(
            items,
            beneficiaryRecords
        );

    const allocatedConsumptionQuantitySummary =
        getAllocatedConsumptionQuantitySummary(
            items,
            beneficiaryRecords
        );

    const beneficiaryParticipationSummary =
        getBeneficiaryParticipationSummary(
            items,
            beneficiaryRecords
        );


    // =================================================
    // PARTICIPATION ITEMS
    // =================================================

    const participationItems =
        itemAllocationSummary.filter(
            (summary) =>
                !isMonetaryUnit(summary.item?.unit) &&
                summary.allocationBehavior === "PARTICIPATION"
        );

    const hasParticipationItems =
        participationItems.length > 0;


    // =================================================
    // DETAIL ITEM ALLOCATION SUMMARY
    // =================================================

    const getDetailAllocationSummary = (
        serviceItem,
        detailItem
    ) => {
        let allocatedQuantity = 0;
        let allocatedValue = 0;

        beneficiaryRecords.forEach((record) => {
            const allocations =
                Array.isArray(record?.allocations)
                    ? record.allocations
                    : [];

            allocations.forEach((allocation) => {
                const allocationServiceItem =
                    getServiceItemFromAllocation(
                        allocation,
                        items
                    );

                if (
                    !allocationServiceItem ||
                    String(allocationServiceItem?._id) !==
                        String(serviceItem?._id)
                ) {
                    return;
                }

                const allocationDetailItem =
                    getDetailItemFromAllocation(
                        allocation,
                        allocationServiceItem
                    );

                if (
                    !allocationDetailItem ||
                    String(allocationDetailItem?._id) !==
                        String(detailItem?._id)
                ) {
                    return;
                }

                allocatedQuantity += getNumber(
                    allocation?.quantity,
                    0
                );

                allocatedValue += getNumber(
                    allocation?.allocatedValue,
                    0
                );
            });
        });

        const deliveredQuantity =
            getNumber(detailItem?.quantity, 0);

        const monetary =
            isMonetaryUnit(detailItem?.unit);

        const behavior =
            getAllocationBehavior(serviceItem);

        const unallocatedQuantity =
            monetary ||
            behavior === "PARTICIPATION"
                ? 0
                : Math.max(
                    0,
                    deliveredQuantity - allocatedQuantity
                );

        return {
            deliveredQuantity,
            allocatedQuantity,
            unallocatedQuantity,
            allocatedValue
        };
    };

    // =================================================
    // PAGE
    // =================================================

    return (

        <PageContainer>


            {/* =================================================
                HEADER
            ================================================= */}

            <PageHeader
                title={
                    delivery.deliveryNumber ||
                    "Service Delivery"
                }
                subtitle="Service delivery record and beneficiary details"
                action={() =>
                    navigate(
                        `/service-deliveries/${id}/edit`
                    )
                }
                actionLabel="Edit"
                actionIcon={
                    <Edit />
                }
            />


            {/* =================================================
                STATUS
            ================================================= */}

            <Stack
                direction="row"
                spacing={1}
                alignItems="center"
                sx={{
                    mb: 3,
                    flexWrap: "wrap"
                }}
            >

                <Typography
                    variant="body2"
                    color="text.secondary"
                >
                    Status:
                </Typography>

                <StatusChip
                    status={
                        delivery.status ||
                        "Delivered"
                    }
                />

                <Chip
                    size="small"
                    label={
                        `Recipient: ${recipientType}`
                    }
                    variant="outlined"
                />

                <Chip
                    size="small"
                    label={
                        `Allocation: ${allocationMethod}`
                    }
                    variant="outlined"
                />

            </Stack>


            {/* =================================================
                KPI SUMMARY
            ================================================= */}

            <Grid
                container
                spacing={2}
                sx={{
                    mb: 3
                }}
            >

                <Grid
                    item
                    xs={12}
                    sm={6}
                    md={3}
                >

                    <SummaryCard
                        icon={
                            <People />
                        }
                        label="Beneficiaries"
                        value={
                            beneficiaryCount
                        }
                        subtitle="People associated with delivery"
                    />

                </Grid>


                <Grid
                    item
                    xs={12}
                    sm={6}
                    md={3}
                >

                    <SummaryCard
                        icon={
                            <Inventory2 />
                        }
                        label="Service Items"
                        value={
                            items.length
                        }
                        subtitle="Services recorded"
                    />

                </Grid>


                <Grid
                    item
                    xs={12}
                    sm={6}
                    md={3}
                >

                    <SummaryCard
                        icon={
                            <Numbers />
                        }
                        label="Physical Quantity Delivered"
                        value={
                            physicalQuantitySummary
                        }
                        subtitle="Physical units only; monetary items excluded"
                    />

                </Grid>


                <Grid
                    item
                    xs={12}
                    sm={6}
                    md={3}
                >

                    <SummaryCard
                        icon={
                            <Payments />
                        }
                        label="Total Cost"
                        value={
                            `ETB ${formatMoney(
                                totalAmount
                            )}`
                        }
                        subtitle="Actual delivery cost"
                    />

                </Grid>

            </Grid>


            {/* =================================================
                DELIVERY OVERVIEW
            ================================================= */}

            <DetailSection
                title="Delivery Overview"
                subtitle="Program, activity and delivery information"
            >

                <Grid
                    container
                    spacing={3}
                >

                    <Grid
                        item
                        xs={12}
                        sm={6}
                        md={3}
                    >

                        <DetailField
                            label="Program"
                            value={
                                delivery.program?.name ||
                                getLookupValue(
                                    delivery.program
                                )
                            }
                        />

                    </Grid>


                    <Grid
                        item
                        xs={12}
                        sm={6}
                        md={3}
                    >

                        <DetailField
                            label="Project"
                            value={
                                delivery.project?.name ||
                                getLookupValue(
                                    delivery.project
                                )
                            }
                        />

                    </Grid>


                    <Grid
                        item
                        xs={12}
                        sm={6}
                        md={3}
                    >

                        <DetailField
                            label="Activity"
                            value={
                                delivery.activity?.name ||
                                getLookupValue(
                                    delivery.activity
                                )
                            }
                        />

                    </Grid>


                    <Grid
                        item
                        xs={12}
                        sm={6}
                        md={3}
                    >

                        <DetailField
                            label="Activity Run"
                            value={
                                delivery.activityRun?.name ||
                                delivery.activityRun?.runName ||
                                delivery.activityRun?.title ||
                                getLookupValue(
                                    delivery.activityRun
                                )
                            }
                        />

                    </Grid>


                    <Grid
                        item
                        xs={12}
                        sm={6}
                        md={3}
                    >

                        <Stack
                            direction="row"
                            spacing={1}
                            alignItems="center"
                        >

                            <CalendarMonth
                                fontSize="small"
                                color="action"
                            />

                            <DetailField
                                label="Delivery Date"
                                value={
                                    formatDate(
                                        delivery.deliveryDate ||
                                        delivery.date
                                    )
                                }
                            />

                        </Stack>

                    </Grid>


                    <Grid
                        item
                        xs={12}
                        sm={6}
                        md={3}
                    >

                        <Stack
                            direction="row"
                            spacing={1}
                            alignItems="center"
                        >

                            <LocationOn
                                fontSize="small"
                                color="action"
                            />

                            <DetailField
                                label="Location"
                                value={
                                    delivery.deliveryLocation
                                }
                            />

                        </Stack>

                    </Grid>


                    <Grid
                        item
                        xs={12}
                        sm={6}
                        md={3}
                    >

                        <DetailField
                            label="Recipient Type"
                            value={
                                recipientType
                            }
                        />

                    </Grid>

                   {
                        showRecipientName && (

                            <Grid
                                item
                                xs={12}
                                sm={6}
                                md={3}
                            >

                                <DetailField
                                    label={
                                        getRecipientNameLabel(
                                            recipientType
                                        )
                                    }
                                    value={
                                        recipientName ||
                                        "-"
                                    }
                                />

                            </Grid>

                        )
                    }


                    <Grid
                        item
                        xs={12}
                        sm={6}
                        md={3}
                    >

                        <DetailField
                            label="Allocation Method"
                            value={
                                allocationMethod
                            }
                        />

                    </Grid>


                    <Grid
                        item
                        xs={12}
                        sm={6}
                        md={3}
                    >

                        <DetailField
                            label="Delivery Number"
                            value={
                                delivery.deliveryNumber
                            }
                        />

                    </Grid>

                </Grid>

            </DetailSection>



            {/* =================================================
                FUNDING INFORMATION
            ================================================= */}

            <DetailSection
                title="Funding Information"
                subtitle="Donors and donations associated with this delivery"
            >

                <Grid
                    container
                    spacing={3}
                >

                    


                    {/* -----------------------------------------
                        ITEM-LEVEL FUNDING
                    ----------------------------------------- */}

                    {Array.isArray(delivery.items) &&
                        delivery.items.map((item, index) => {

                            const funding =
                                getItemFunding(item);

                            const serviceName =
                                getFundingText(
                                    item.serviceType
                                ) ||
                                `Service Item ${index + 1}`;

                            if (
                                !funding.donor &&
                                !funding.donation &&
                                !funding.fundingSource
                            ) {
                                return null;
                            }

                            return (
                                <Grid
                                    item
                                    xs={12}
                                    key={item._id || index}
                                >

                                    <DetailSection
                                        title={serviceName}
                                        subtitle="Service item funding details"
                                    >

                                        <Grid
                                            container
                                            spacing={3}
                                        >

                                            <Grid
                                                item
                                                xs={12}
                                                sm={6}
                                                md={3}
                                            >

                                                <DetailField
                                                    label="Donor"
                                                    value={
                                                        funding.donor ||
                                                        "Not specified"
                                                    }
                                                />

                                            </Grid>

                                            <Grid
                                                item
                                                xs={12}
                                                sm={6}
                                                md={3}
                                            >

                                                <DetailField
                                                    label="Donation"
                                                    value={
                                                        funding.donation ||
                                                        "Not specified"
                                                    }
                                                />

                                            </Grid>

                                            <Grid
                                                item
                                                xs={12}
                                                sm={6}
                                                md={3}
                                            >

                                                <DetailField
                                                    label="Currency"
                                                    value={
                                                        funding.currency ||
                                                        "Not specified"
                                                    }
                                                />

                                            </Grid>

                                            <Grid
                                                item
                                                xs={12}
                                                sm={6}
                                                md={3}
                                            >

                                                <DetailField
                                                    label="Donation Funding Source"
                                                    value={
                                                        funding.fundingSource ||
                                                        "Not specified"
                                                    }
                                                />

                                            </Grid>

                                        </Grid>

                                    </DetailSection>

                                </Grid>
                            );
                        })
                    }

                    {/* -----------------------------------------
                        NO ITEM-LEVEL FUNDING
                    ----------------------------------------- */}

                    {(
                        !Array.isArray(delivery.items) ||
                        !delivery.items.some(
                            (item) =>
                                item?.donor ||
                                item?.donation
                        )
                    ) && (

                        <Grid
                            item
                            xs={12}
                        >

                            <DetailField
                                label="Item-Level Funding"
                                value="Not specified"
                            />

                        </Grid>

                    )}

                </Grid>

            </DetailSection>
            {/* =================================================
                BENEFICIARIES
            ================================================= */}

            <Box
                sx={{
                    mt: 3
                }}
            >

                <DetailSection
                    title={
                        `Beneficiaries Served (${beneficiaryCount})`
                    }
                    subtitle="Beneficiary participation and allocation information"
                >

                    {
                        beneficiaryRecords.length === 0

                            ? (

                                <Stack
                                    spacing={1}
                                >

                                    <Typography
                                        color="text.secondary"
                                    >
                                        No beneficiaries recorded.
                                    </Typography>


                                    {
                                        recipientName && (

                                            <Typography
                                                variant="body2"
                                                fontWeight={600}
                                            >
                                                Recipient: {
                                                    recipientName
                                                }
                                            </Typography>

                                        )
                                    }

                                </Stack>

                            )

                            : (

                                <Stack
                                    spacing={0}
                                >

                                    {
                                        beneficiaryRecords.map(
                                            (
                                                record,
                                                index
                                            ) => {

                                                const beneficiary =
                                                    record?.beneficiary ||
                                                    record;

                                                const allocations =
                                                    Array.isArray(
                                                        record?.allocations
                                                    )
                                                        ? record.allocations
                                                        : [];


                                                return (

                                                    <Box
                                                        key={
                                                            record?._id ||
                                                            beneficiary?._id ||
                                                            beneficiary?.id ||
                                                            beneficiary?.beneficiaryNumber ||
                                                            index
                                                        }
                                                        sx={{
                                                            py: 2,
                                                            borderBottom:
                                                                index <
                                                                beneficiaryRecords.length - 1
                                                                    ? "1px solid"
                                                                    : "none",
                                                            borderColor:
                                                                "divider"
                                                        }}
                                                    >

                                                        <Stack
                                                            direction="row"
                                                            spacing={1.5}
                                                            justifyContent="space-between"
                                                            alignItems="center"
                                                        >

                                                            <Stack
                                                                direction="row"
                                                                spacing={1.5}
                                                                alignItems="center"
                                                            >

                                                                <People
                                                                    fontSize="small"
                                                                    color="action"
                                                                />

                                                                <Box>

                                                                    <Typography
                                                                        variant="body2"
                                                                        fontWeight={600}
                                                                    >
                                                                        {
                                                                            getBeneficiaryName(
                                                                                beneficiary
                                                                            )
                                                                        }
                                                                    </Typography>


                                                                    {
                                                                        beneficiary?.beneficiaryNumber && (

                                                                            <Typography
                                                                                variant="caption"
                                                                                color="text.secondary"
                                                                            >
                                                                                {
                                                                                    beneficiary.beneficiaryNumber
                                                                                }
                                                                            </Typography>

                                                                        )
                                                                    }

                                                                </Box>

                                                            </Stack>


                                                            <Chip
                                                                size="small"
                                                                label={
                                                                    record?.status ||
                                                                    "Received"
                                                                }
                                                            />

                                                        </Stack>


                                                        {
                                                            allocations.length > 0 && (

                                                                <Box
                                                                    sx={{
                                                                        mt: 1.5,
                                                                        ml: {
                                                                            xs: 0,
                                                                            sm: 5
                                                                        }
                                                                    }}
                                                                >

                                                                    <Typography
                                                                        variant="caption"
                                                                        color="text.secondary"
                                                                        sx={{
                                                                            display: "block",
                                                                            mb: 1
                                                                        }}
                                                                    >
                                                                        Item Allocations
                                                                    </Typography>


                                                                    <Stack
                                                                        spacing={0.75}
                                                                    >

                                                                        {
                                                                            allocations.map(
                                                                                (
                                                                                    allocation,
                                                                                    allocationIndex
                                                                                ) => {

                                                                                    const serviceItem =
                                                                                        getServiceItemFromAllocation(
                                                                                            allocation,
                                                                                            items
                                                                                        );

                                                                                    if (
                                                                                        !serviceItem
                                                                                    ) {

                                                                                        return null;

                                                                                    }


                                                                                    const detailItem =
                                                                                        getDetailItemFromAllocation(
                                                                                            allocation,
                                                                                            serviceItem
                                                                                        );


                                                                                    const serviceType =
                                                                                        getLookupValue(
                                                                                            serviceItem?.serviceType
                                                                                        );


                                                                                    const allocationDisplay =
                                                                                        getAllocationDisplay(
                                                                                            allocation,
                                                                                            serviceItem
                                                                                        );


                                                                                    const allocationUnit =
                                                                                        detailItem?.unit ||
                                                                                        serviceItem?.unit;


                                                                                    const allocationQuantity =
                                                                                        getNumber(
                                                                                            allocation?.quantity,
                                                                                            0
                                                                                        );


                                                                                    return (

                                                                                        <Box
                                                                                            key={
                                                                                                allocation?._id ||
                                                                                                allocationIndex
                                                                                            }
                                                                                            sx={{
                                                                                                p: 1,
                                                                                                borderRadius: 1,
                                                                                                bgcolor:
                                                                                                    "action.hover"
                                                                                            }}
                                                                                        >

                                                                                            <Stack
                                                                                                direction={{
                                                                                                    xs: "column",
                                                                                                    sm: "row"
                                                                                                }}
                                                                                                spacing={1}
                                                                                                justifyContent="space-between"
                                                                                            >

                                                                                                <Box>

                                                                                                    <Typography
                                                                                                        variant="body2"
                                                                                                        fontWeight={600}
                                                                                                    >
                                                                                                        {
                                                                                                            serviceType
                                                                                                        }
                                                                                                    </Typography>


                                                                                                    {
                                                                                                        detailItem && (

                                                                                                            <Typography
                                                                                                                variant="body2"
                                                                                                                fontWeight={600}
                                                                                                                sx={{
                                                                                                                    mt: 0.25
                                                                                                                }}
                                                                                                            >
                                                                                                                Detail: {
                                                                                                                    detailItem?.name ||
                                                                                                                    detailItem?.label ||
                                                                                                                    getLookupValue(
                                                                                                                        detailItem
                                                                                                                    )
                                                                                                                }
                                                                                                            </Typography>

                                                                                                        )
                                                                                                    }


                                                                                                    {
                                                                                                        allocationUnit && (

                                                                                                            <Typography
                                                                                                                variant="caption"
                                                                                                                color="text.secondary"
                                                                                                            >
                                                                                                                Unit: {
                                                                                                                    getLookupValue(
                                                                                                                        allocationUnit
                                                                                                                    )
                                                                                                                }
                                                                                                            </Typography>

                                                                                                        )
                                                                                                    }

                                                                                                </Box>


                                                                                                <Box
                                                                                                    sx={{
                                                                                                        textAlign: {
                                                                                                            xs: "left",
                                                                                                            sm: "right"
                                                                                                        }
                                                                                                    }}
                                                                                                >

                                                                                                    <Typography
                                                                                                        variant="body2"
                                                                                                        fontWeight={600}
                                                                                                    >

                                                                                                        {
                                                                                                            getAllocationBehavior(
                                                                                                                serviceItem
                                                                                                            ) === "PARTICIPATION"

                                                                                                                ? `Participation: ${formatQuantity(
                                                                                                                    allocationQuantity
                                                                                                                )} ${pluralizeUnit(
                                                                                                                    getLookupValue(
                                                                                                                        allocationUnit
                                                                                                                    ),
                                                                                                                    allocationQuantity
                                                                                                                )}`

                                                                                                                : detailItem

                                                                                                                    ? `Allocated: ${formatQuantity(
                                                                                                                        allocationQuantity
                                                                                                                    )} ${pluralizeUnit(
                                                                                                                        getLookupValue(
                                                                                                                            allocationUnit
                                                                                                                        ),
                                                                                                                        allocationQuantity
                                                                                                                    )}`

                                                                                                                    : allocationDisplay.primary

                                                                                                        }

                                                                                                    </Typography>


                                                                                                    <Typography
                                                                                                        variant="caption"
                                                                                                        color="text.secondary"
                                                                                                    >
                                                                                                        {
                                                                                                            allocationDisplay.secondary
                                                                                                        }
                                                                                                    </Typography>

                                                                                                </Box>

                                                                                            </Stack>

                                                                                        </Box>

                                                                                    );

                                                                                }
                                                                            )

                                                                        }

                                                                    </Stack>

                                                                </Box>

                                                            )
                                                        }

                                                    </Box>

                                                );

                                            }
                                        )
                                    }

                                </Stack>

                            )

                    }

                </DetailSection>

            </Box>


            {/* =================================================
                DELIVERED SERVICES
            ================================================= */}

            <Box
                sx={{
                    mt: 3
                }}
            >

                <DetailSection
                    title="Delivered Services"
                    subtitle="Service items included in this delivery"
                >

                    <Stack
                        spacing={2}
                    >

                        {
                            items.length === 0

                                ? (

                                    <Typography
                                        color="text.secondary"
                                    >
                                        No service items recorded.
                                    </Typography>

                                )

                                : (

                                    items.map(
                                        (
                                            item,
                                            index
                                        ) => {

                                            const summary =
                                                itemAllocationSummary[index];

                                            const detailItems =
                                                getDetailItems(
                                                    item
                                                );


                                            return (

                                                <Paper
                                                    key={
                                                        item?._id ||
                                                        index
                                                    }
                                                    elevation={0}
                                                    sx={{
                                                        p: 2,
                                                        border: "1px solid",
                                                        borderColor: "divider",
                                                        borderRadius: 2
                                                    }}
                                                >

                                                    <Grid
                                                        container
                                                        spacing={2}
                                                    >

                                                        <Grid
                                                            item
                                                            xs={12}
                                                            md={4}
                                                        >

                                                            <Typography
                                                                variant="body1"
                                                                fontWeight={700}
                                                            >
                                                                {
                                                                    getLookupValue(
                                                                        item?.serviceType
                                                                    )
                                                                }
                                                            </Typography>


                                                            {
                                                                item?.remarks && (

                                                                    <Typography
                                                                        variant="body2"
                                                                        color="text.secondary"
                                                                        sx={{
                                                                            mt: 0.5
                                                                        }}
                                                                    >
                                                                        {
                                                                            item.remarks
                                                                        }
                                                                    </Typography>

                                                                )
                                                            }

                                                        </Grid>


                                                        <Grid
                                                            item
                                                            xs={12}
                                                            sm={4}
                                                            md={2}
                                                        >

                                                            <DetailField
                                                                label="Quantity"
                                                                value={
                                                                    isMonetaryUnit(
                                                                        item?.unit
                                                                    )
                                                                        ? "-"
                                                                        : `${formatQuantity(
                                                                            item?.quantity
                                                                        )} ${pluralizeUnit(
                                                                            getLookupValue(
                                                                                item?.unit
                                                                            ),
                                                                            item?.quantity
                                                                        )}`
                                                                }
                                                            />

                                                        </Grid>


                                                        <Grid
                                                            item
                                                            xs={12}
                                                            sm={4}
                                                            md={2}
                                                        >

                                                            <DetailField
                                                                label="Unit Cost"
                                                                value={
                                                                    `ETB ${formatMoney(
                                                                        item?.unitCost
                                                                    )}`
                                                                }
                                                            />

                                                        </Grid>


                                                        <Grid
                                                            item
                                                            xs={12}
                                                            sm={4}
                                                            md={2}
                                                        >

                                                            <DetailField
                                                                label="Actual Cost"
                                                                value={
                                                                    `ETB ${formatMoney(
                                                                        summary?.itemTotal
                                                                    )}`
                                                                }
                                                            />

                                                        </Grid>


                                                        <Grid
                                                            item
                                                            xs={12}
                                                            sm={4}
                                                            md={2}
                                                        >

                                                            <DetailField
                                                                label="Allocation"
                                                                value={
                                                                    summary?.allocationBehavior
                                                                }
                                                            />

                                                        </Grid>

                                                    </Grid>


                                                    {
                                                        detailItems.length > 0 && (

                                                            <Box
                                                                sx={{
                                                                    mt: 2
                                                                }}
                                                            >

                                                                <Divider
                                                                    sx={{
                                                                        mb: 2
                                                                    }}
                                                                />


                                                                <Typography
                                                                    variant="subtitle2"
                                                                    fontWeight={700}
                                                                    sx={{
                                                                        mb: 1.5
                                                                    }}
                                                                >
                                                                    Detail Items
                                                                </Typography>


                                                                <Stack
                                                                    spacing={1}
                                                                >

                                                                    {
                                                                        detailItems.map(
                                                                            (
                                                                                detailItem,
                                                                                detailIndex
                                                                            ) => {

                                                                                const detailSummary =
                                                                                    getDetailAllocationSummary(
                                                                                        item,
                                                                                        detailItem
                                                                                    );


                                                                                const detailUnit =
                                                                                    getLookupValue(
                                                                                        detailItem?.unit
                                                                                    );


                                                                                const detailQuantity =
                                                                                    getNumber(
                                                                                        detailItem?.quantity,
                                                                                        0
                                                                                    );


                                                                                return (

                                                                                    <Paper
                                                                                        key={
                                                                                            detailItem?._id ||
                                                                                            detailIndex
                                                                                        }
                                                                                        elevation={0}
                                                                                        sx={{
                                                                                            p: 1.5,
                                                                                            bgcolor: "action.hover",
                                                                                            borderRadius: 1
                                                                                        }}
                                                                                    >

                                                                                        <Grid
                                                                                            container
                                                                                            spacing={2}
                                                                                            alignItems="center"
                                                                                        >

                                                                                            <Grid
                                                                                                item
                                                                                                xs={12}
                                                                                                sm={3}
                                                                                            >

                                                                                                <Typography
                                                                                                    variant="body2"
                                                                                                    fontWeight={600}
                                                                                                >
                                                                                                    {
                                                                                                        detailItem?.name ||
                                                                                                        detailItem?.label ||
                                                                                                        "Detail Item"
                                                                                                    }
                                                                                                </Typography>

                                                                                            </Grid>


                                                                                            <Grid
                                                                                                item
                                                                                                xs={6}
                                                                                                sm={2}
                                                                                            >

                                                                                                <DetailField
                                                                                                    label="Delivered"
                                                                                                    value={
                                                                                                        `${formatQuantity(
                                                                                                            detailQuantity
                                                                                                        )} ${pluralizeUnit(
                                                                                                            detailUnit,
                                                                                                            detailQuantity
                                                                                                        )}`
                                                                                                    }
                                                                                                />

                                                                                            </Grid>


                                                                                            <Grid
                                                                                                item
                                                                                                xs={6}
                                                                                                sm={2}
                                                                                            >

                                                                                                <DetailField
                                                                                                    label="Allocated"
                                                                                                    value={
                                                                                                        `${formatQuantity(
                                                                                                            detailSummary.allocatedQuantity
                                                                                                        )} ${pluralizeUnit(
                                                                                                            detailUnit,
                                                                                                            detailSummary.allocatedQuantity
                                                                                                        )}`
                                                                                                    }
                                                                                                />

                                                                                            </Grid>


                                                                                            <Grid
                                                                                                item
                                                                                                xs={6}
                                                                                                sm={2}
                                                                                            >

                                                                                                <DetailField
                                                                                                    label="Unallocated"
                                                                                                    value={
                                                                                                        isMonetaryUnit(
                                                                                                            detailItem?.unit
                                                                                                        )
                                                                                                            ? "-"
                                                                                                            : `${formatQuantity(
                                                                                                                detailSummary.unallocatedQuantity
                                                                                                            )} ${pluralizeUnit(
                                                                                                                detailUnit,
                                                                                                                detailSummary.unallocatedQuantity
                                                                                                            )}`
                                                                                                    }
                                                                                                />

                                                                                            </Grid>


                                                                                            <Grid
                                                                                                item
                                                                                                xs={6}
                                                                                                sm={2}
                                                                                            >

                                                                                                <DetailField
                                                                                                    label="Unit Cost"
                                                                                                    value={
                                                                                                        `ETB ${formatMoney(
                                                                                                            detailItem?.unitCost
                                                                                                        )}`
                                                                                                    }
                                                                                                />

                                                                                            </Grid>


                                                                                            <Grid
                                                                                                item
                                                                                                xs={12}
                                                                                                sm={1}
                                                                                            >

                                                                                                <DetailField
                                                                                                    label="Value"
                                                                                                    value={
                                                                                                        `ETB ${formatMoney(
                                                                                                            detailSummary.allocatedValue
                                                                                                        )}`
                                                                                                    }
                                                                                                />

                                                                                            </Grid>

                                                                                        </Grid>

                                                                                    </Paper>

                                                                                );

                                                                            }
                                                                        )
                                                                    }

                                                                </Stack>

                                                            </Box>

                                                        )
                                                    }

                                                </Paper>

                                            );

                                        }
                                    )

                                )
                        }

                    </Stack>

                </DetailSection>

            </Box>


            {/* =================================================
                ITEM ALLOCATION BREAKDOWN
            ================================================= */}

            <Box
                sx={{
                    mt: 3
                }}
            >

                <DetailSection
                    title="Item Allocation Breakdown"
                    subtitle="Parent service-item quantity and beneficiary allocation accounting"
                >

                    <Stack
                        spacing={1.5}
                    >

                        {
                            itemAllocationSummary.map(
                                (
                                    summary,
                                    index
                                ) => {

                                    const item =
                                        summary.item;

                                    const unit =
                                        getLookupValue(
                                            item?.unit
                                        );


                                    return (

                                        <Paper
                                            key={
                                                item?._id ||
                                                index
                                            }
                                            elevation={0}
                                            sx={{
                                                p: 2,
                                                border: "1px solid",
                                                borderColor: "divider",
                                                borderRadius: 2
                                            }}
                                        >

                                            <Stack
                                                direction={{
                                                    xs: "column",
                                                    md: "row"
                                                }}
                                                spacing={2}
                                                justifyContent="space-between"
                                            >

                                                <Box>

                                                    <Typography
                                                        variant="body1"
                                                        fontWeight={700}
                                                    >
                                                        {
                                                            getLookupValue(
                                                                item?.serviceType
                                                            )
                                                        }
                                                    </Typography>

                                                    <Typography
                                                        variant="caption"
                                                        color="text.secondary"
                                                    >
                                                        {
                                                            summary.allocationBehavior
                                                        }
                                                    </Typography>

                                                </Box>


                                                <Stack
                                                    direction={{
                                                        xs: "column",
                                                        sm: "row"
                                                    }}
                                                    spacing={2}
                                                >

                                                    {
                                                        !isMonetaryUnit(
                                                            item?.unit
                                                        ) && (

                                                            <DetailField
                                                                label="Delivered"
                                                                value={
                                                                    `${formatQuantity(
                                                                        summary.deliveredQuantity
                                                                    )} ${pluralizeUnit(
                                                                        unit,
                                                                        summary.deliveredQuantity
                                                                    )}`
                                                                }
                                                            />

                                                        )
                                                    }


                                                    {
                                                        !isMonetaryUnit(
                                                            item?.unit
                                                        ) && (

                     
<DetailField
    label="Direct Parent Allocated"
    value={
        getAllocationBehavior(item) === "PARTICIPATION"
            ? `0 ${pluralizeUnit(unit, 0)}`
            : `${formatQuantity(
                summary.allocatedQuantity
            )} ${pluralizeUnit(
                unit,
                summary.allocatedQuantity
            )}`
    }
/>

)}

{
    !isMonetaryUnit(item?.unit) && (
        <DetailField
            label="Parent Unallocated"
            value={
                getAllocationBehavior(item) === "PARTICIPATION"
                    ? "N/A — participation allocation"
                    : getDetailItems(summary.item).length > 0
                        ? "N/A — see detail items"
                        : `${formatQuantity(
                            summary.unallocatedQuantity
                        )} ${pluralizeUnit(
                            unit,
                            summary.unallocatedQuantity
                        )}`
            }
        />
    )
}

<DetailField
    label="Actual Cost"
    value={`ETB ${formatMoney(summary.itemTotal)}`}
/>


                                                    <DetailField
                                                        label="Allocated Value"
                                                        value={
                                                            `ETB ${formatMoney(
                                                                summary.allocatedValue
                                                            )}`
                                                        }
                                                    />

                                                </Stack>

                                            </Stack>

                                        </Paper>

                                    );

                                }
                            )

                        }

                    </Stack>

                </DetailSection>

            </Box>

{/* =================================================
    ALLOCATION SUMMARY
================================================= */}

<Box
    sx={{
        mt: 3
    }}
>

    <DetailSection
        title="Allocation Summary"
        subtitle="Overall beneficiary allocation accounting"
    >

        <Grid
            container
            spacing={3}
        >

            <Grid
                item
                xs={12}
                sm={6}
                md={3}
            >

                <DetailField
                    label="Total Allocated Value"
                    value={
                        `ETB ${formatMoney(
                            totalAllocatedValue
                        )}`
                    }
                />

            </Grid>


            <Grid
                item
                xs={12}
                sm={6}
                md={3}
            >

                <DetailField
                    label="Unallocated Value"
                    value={
                        `ETB ${formatMoney(
                            unallocatedValue
                        )}`
                    }
                />

            </Grid>


            <Grid
                item
                xs={12}
                sm={6}
                md={3}
            >

                <DetailField
                    label="Direct Parent Allocated Quantity"
                    value={
                        totalAllocatedQuantitySummary
                    }
                />

            </Grid>


            <Grid
                item
                xs={12}
                sm={6}
                md={3}
            >

                <DetailField
                    label="Consumption Allocated Quantity"
                    value={
                        allocatedConsumptionQuantitySummary
                    }
                />

            </Grid>


            <Grid
                item
                xs={12}
                sm={6}
                md={3}
            >

                <DetailField
    label="Participation Quantity"
    value={
        beneficiaryParticipationSummary === "0"
            ? "—"
            : beneficiaryParticipationSummary
    }
/>

            </Grid>


            <Grid
                item
                xs={12}
                sm={6}
                md={3}
            >

                <DetailField
                    label="Unallocated Physical Quantities"
                    value={
                        unallocatedPhysicalQuantitySummary
                    }
                />

            </Grid>

        </Grid>


        {
            hasParticipationItems && (

                <Box
                    sx={{
                        mt: 2
                    }}
                >

                    <Typography
                        variant="caption"
                        color="text.secondary"
                    >
                        Participation allocations are beneficiary-level records and do not consume the shared delivered quantity pool.
                    </Typography>

                </Box>

            )
        }

    </DetailSection>

</Box>


            {/* =================================================
                FINANCIAL SUMMARY
            ================================================= */}

            <Box
                sx={{
                    mt: 3
                }}
            >

                <DetailSection
                    title="Financial Summary"
                    subtitle="Actual delivery cost and beneficiary-attributable financial allocation"
                >

                    <Grid
                        container
                        spacing={3}
                    >

                        <Grid
                            item
                            xs={12}
                            sm={6}
                            md={4}
                        >

                            <DetailField
                                label="Actual Delivery Cost"
                                value={
                                    `ETB ${formatMoney(
                                        totalAmount
                                    )}`
                                }
                            />

                        </Grid>


                        <Grid
                            item
                            xs={12}
                            sm={6}
                            md={4}
                        >

                            <DetailField
                                label="Allocated Value"
                                value={
                                    `ETB ${formatMoney(
                                        totalAllocatedValue
                                    )}`
                                }
                            />

                        </Grid>


                        <Grid
                            item
                            xs={12}
                            sm={6}
                            md={4}
                        >

                            <DetailField
                                label="Unallocated Value"
                                value={
                                    `ETB ${formatMoney(
                                        unallocatedValue
                                    )}`
                                }
                            />

                        </Grid>

                    </Grid>

                </DetailSection>

            </Box>


            {/* =================================================
                RECORD INFORMATION
            ================================================= */}

            <Box
                sx={{
                    mt: 3
                }}
            >

                <DetailSection
                    title="Record Information"
                    subtitle="Audit and record timestamps"
                >

                    <Grid
                        container
                        spacing={3}
                    >

                        <Grid
                            item
                            xs={12}
                            sm={6}
                            md={4}
                        >

                            <DetailField
                                label="Created At"
                                value={
                                    formatDateTime(
                                        delivery.createdAt
                                    )
                                }
                            />

                        </Grid>


                        <Grid
                            item
                            xs={12}
                            sm={6}
                            md={4}
                        >

                            <DetailField
                                label="Updated At"
                                value={
                                    formatDateTime(
                                        delivery.updatedAt
                                    )
                                }
                            />

                        </Grid>


                        <Grid
                            item
                            xs={12}
                            sm={6}
                            md={4}
                        >

                            <DetailField
                                label="Record ID"
                                value={
                                    delivery._id
                                }
                            />

                        </Grid>

                    </Grid>

                </DetailSection>

            </Box>


            {/* =================================================
                BACK
            ================================================= */}

            <Stack
                direction="row"
                justifyContent="flex-start"
                sx={{
                    mt: 3
                }}
            >

                <AppButton
                    variant="outlined"
                    onClick={() =>
                        navigate(
                            "/service-deliveries"
                        )
                    }
                >
                    Back to Service Deliveries
                </AppButton>

            </Stack>

        </PageContainer>

    );

};


export default ServiceDeliveryDetailsPage;