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
    Chip,
    Alert
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

import AllocationOverview
    from "../components/AllocationOverview";


import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    InfoRow,
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

// =====================================================
// HOW AN ITEM IS GIVEN OUT (readable)
// =====================================================

const behaviorLabel = (behavior) =>
    behavior === "PARTICIPATION"
        ? "Everyone takes part"
        : "Shared out";


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
                borderRadius: 3
            }}
        >

            <Stack sx={{ alignItems: "center" }}
                direction="row"
                spacing={2}
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
                        sx={{
                            color: "text.secondary"
                        }}
                    >
                        {label}
                    </Typography>


                    <Typography
                        variant="h6"
                        sx={{
                            fontWeight: 700,
                            mt: 0.25
                        }}>
                        {value}
                    </Typography>


                    {
                        subtitle && (

                            <Typography
                                variant="caption"
                                sx={{
                                    color: "text.secondary"
                                }}
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
}) => (

    <PageCard>

        <FormSection
            title={title}
            subtitle={subtitle}
            sx={{
                mb: 0
            }}
        >
            {children}
        </FormSection>

    </PageCard>

);


// =====================================================
// INFO FIELD
// =====================================================
//
// Same label / value style as InfoRow on the other
// details pages, stacked so it fits grid columns.
//
// =====================================================

const DetailField = ({
    label,
    value
}) => (

    <InfoRow
        label={label}
        value={value}
        direction="column"
    />

);


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


                        const normalizedDelivery =
                            getResponseData(
                                response
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
                    title="Service Delivery Details"
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
                    title="Service Delivery Details"
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
    // EQUAL SHARE
    // =================================================
    // People with no allocation of their own share equally
    // what the others' allocations leave (the same rule the
    // reports and the donor trace use). Households, groups
    // and institutions are not split among people.

    const valueGivenToPeople =
        beneficiaryRecords.reduce(
            (sum, record) =>
                sum +
                (Array.isArray(record?.allocations) ? record.allocations : [])
                    .reduce((total, allocation) => total + getNumber(allocation?.allocatedValue, 0), 0),
            0
        );

    const peopleWithoutShare =
        recipientType === "Individual"
            ? beneficiaryRecords.filter(
                record =>
                    !(Array.isArray(record?.allocations) && record.allocations.length)
            ).length
            : 0;

    const valueSharedEqually =
        peopleWithoutShare > 0
            ? Math.max(totalAmount - valueGivenToPeople, 0)
            : 0;

    const equalShare =
        peopleWithoutShare > 0
            ? valueSharedEqually / peopleWithoutShare
            : 0;


   
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


    // The totals (allocated, left, shared equally) come from the
    // server: delivery.allocationSummary (see AllocationOverview)


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
                title="Service Delivery Details"
                subtitle={
                    delivery.deliveryNumber ||
                    "Service delivery record"
                }
            />

            {/* =================================================
                ACTIONS + STATUS
            ================================================= */}

            <PageCard
                sx={{
                    mb: 3
                }}
            >

                <FormSection
                    sx={{
                        mb: 0
                    }}
                >

                    <Stack sx={{ alignItems: {
                            xs: "flex-start",
                            sm: "center"
                        }, justifyContent: "space-between" }}
                        direction={{
                            xs: "column",
                            sm: "row"
                        }}
                        spacing={2}
                    >

                        <AppButton
                            variant="contained"
                            startIcon={<Edit />}
                            onClick={() =>
                                navigate(
                                    `/service-deliveries/${id}/edit`
                                )
                            }
                        >
                            Edit Service Delivery
                        </AppButton>

                        <Stack
                            direction="row"
                            spacing={1}
                            sx={{ alignItems: "center",
                                flexWrap: "wrap",
                                rowGap: 1
                            }}
                        >

                            <Typography
                                variant="body2"
                                sx={{
                                    color: "text.secondary"
                                }}
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

                    </Stack>

                </FormSection>

            </PageCard>

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
                    size={{ xs: 12, sm: 6, md: 3 }}
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
                    size={{ xs: 12, sm: 6, md: 3 }}
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
                    size={{ xs: 12, sm: 6, md: 3 }}
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
                    size={{ xs: 12, sm: 6, md: 3 }}
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
                        size={{ xs: 12, sm: 6, md: 3 }}
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
                        size={{ xs: 12, sm: 6, md: 3 }}
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
                        size={{ xs: 12, sm: 6, md: 3 }}
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
                        size={{ xs: 12, sm: 6, md: 3 }}
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
                        size={{ xs: 12, sm: 6, md: 3 }}
                    >

                        <Stack sx={{ alignItems: "center" }}
                            direction="row"
                            spacing={1}
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
                        size={{ xs: 12, sm: 6, md: 3 }}
                    >

                        <Stack sx={{ alignItems: "center" }}
                            direction="row"
                            spacing={1}
                        >

                            <LocationOn
                                fontSize="small"
                                color="action"
                            />

                            <DetailField
                                label="Location"
                                value={
                                    [
                                        delivery.deliveryLocation,
                                        delivery.woreda,
                                        delivery.zone,
                                        delivery.region
                                    ]
                                        .filter(Boolean)
                                        .join(", ")
                                }
                            />

                        </Stack>

                    </Grid>


                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}
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
                                size={{ xs: 12, sm: 6, md: 3 }}
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
                        size={{ xs: 12, sm: 6, md: 3 }}
                    >

                        <DetailField
                            label="Allocation Method"
                            value={
                                allocationMethod
                            }
                        />

                    </Grid>


                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}
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
                                    size={{ xs: 12 }}
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
                                                size={{ xs: 12, sm: 6, md: 3 }}
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
                                                size={{ xs: 12, sm: 6, md: 3 }}
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
                                                size={{ xs: 12, sm: 6, md: 3 }}
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
                                                size={{ xs: 12, sm: 6, md: 3 }}
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

                                        {/* The donation behind it: pledged only, cancelled, or too small */}

                                        {(() => {

                                            const donation =
                                                item?.donation && typeof item.donation === "object"
                                                    ? item.donation
                                                    : null;

                                            if (!donation) return null;

                                            const itemCost =
                                                getServiceItemTotal(item);

                                            const donationAmount =
                                                getNumber(donation.amount, 0);

                                            const currency =
                                                donation.currency || "ETB";

                                            if (donation.status === "Cancelled") {
                                                return (
                                                    <Alert severity="error" variant="outlined" sx={{ mt: 2 }}>
                                                        This donation is cancelled; it cannot pay for this item. Charge it to another donation.
                                                    </Alert>
                                                );
                                            }

                                            if (itemCost > donationAmount + 0.01) {
                                                return (
                                                    <Alert severity="warning" variant="outlined" sx={{ mt: 2 }}>
                                                        This item costs {currency} {formatMoney(itemCost)}, more than the whole donation ({currency} {formatMoney(donationAmount)}{donation.status === "Pledged" ? ", still pledged" : ""}). Charge part of it to another donation or lower the cost.
                                                    </Alert>
                                                );
                                            }

                                            if (donation.status === "Pledged") {
                                                return (
                                                    <Alert severity="info" variant="outlined" sx={{ mt: 2 }}>
                                                        This donation is still pledged, not received ({currency} {formatMoney(donationAmount)}).
                                                    </Alert>
                                                );
                                            }

                                            return null;

                                        })()}

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
                            size={{ xs: 12 }}
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
                                        sx={{
                                            color: "text.secondary"
                                        }}
                                    >
                                        No beneficiaries recorded.
                                    </Typography>


                                    {
                                        recipientName && (

                                            <Typography
                                                variant="body2"
                                                sx={{
                                                    fontWeight: 600
                                                }}
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

                                                        <Stack sx={{ justifyContent: "space-between", alignItems: "center" }}
                                                            direction="row"
                                                            spacing={1.5}
                                                        >

                                                            <Stack sx={{ alignItems: "center" }}
                                                                direction="row"
                                                                spacing={1.5}
                                                            >

                                                                <People
                                                                    fontSize="small"
                                                                    color="action"
                                                                />

                                                                <Box>

                                                                    <Typography
                                                                        variant="body2"
                                                                        sx={{
                                                                            fontWeight: 600
                                                                        }}
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
                                                                                sx={{
                                                                                    color: "text.secondary"
                                                                                }}
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
                                                            allocations.length === 0 &&
                                                            equalShare > 0 && (

                                                                <Typography
                                                                    variant="body2"
                                                                    sx={{
                                                                        mt: 1,
                                                                        ml: {
                                                                            xs: 0,
                                                                            sm: 5
                                                                        },
                                                                        color: "text.secondary"
                                                                    }}
                                                                >
                                                                    Equal share: <strong>ETB {formatMoney(equalShare)}</strong> (no allocation of their own; ETB {formatMoney(valueSharedEqually)} shared by {peopleWithoutShare} {peopleWithoutShare === 1 ? "person" : "people"})
                                                                </Typography>

                                                            )
                                                        }

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
                                                                        sx={{
                                                                            color: "text.secondary",
                                                                            display: "block",
                                                                            mb: 1
                                                                        }}>
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

                                                                                            <Stack sx={{ justifyContent: "space-between" }}
                                                                                                direction={{
                                                                                                    xs: "column",
                                                                                                    sm: "row"
                                                                                                }}
                                                                                                spacing={1}
                                                                                            >

                                                                                                <Box>

                                                                                                    <Typography
                                                                                                        variant="body2"
                                                                                                        sx={{
                                                                                                            fontWeight: 600
                                                                                                        }}
                                                                                                    >
                                                                                                        {
                                                                                                            serviceType
                                                                                                        }
                                                                                                    </Typography>


                                                                                                    {
                                                                                                        detailItem && (

                                                                                                            <Typography
                                                                                                                variant="body2"
                                                                                                                sx={{
                                                                                                                    fontWeight: 600,
                                                                                                                    mt: 0.25
                                                                                                                }}>
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
                                                                                                                sx={{
                                                                                                                    color: "text.secondary"
                                                                                                                }}
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
                                                                                                        sx={{
                                                                                                            fontWeight: 600
                                                                                                        }}
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
                                                                                                        sx={{
                                                                                                            color: "text.secondary"
                                                                                                        }}
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
                                        sx={{
                                            color: "text.secondary"
                                        }}
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
                                                            size={{ xs: 12, md: 4 }}
                                                        >

                                                            <Typography
                                                                variant="body1"
                                                                sx={{
                                                                    fontWeight: 700
                                                                }}
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
                                                                        sx={{
                                                                            color: "text.secondary",
                                                                            mt: 0.5
                                                                        }}>
                                                                        {
                                                                            item.remarks
                                                                        }
                                                                    </Typography>

                                                                )
                                                            }

                                                        </Grid>


                                                        <Grid
                                                            size={{ xs: 12, sm: 4, md: 2 }}
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
                                                            size={{ xs: 12, sm: 4, md: 2 }}
                                                        >

                                                            <DetailField
                                                                label="Unit Cost"
                                                                value={
                                                                    item?.currency && item.currency !== "ETB" && item?.originalUnitCost != null
                                                                        ? `${item.currency} ${formatMoney(item.originalUnitCost)} (ETB ${formatMoney(item?.unitCost)} at ${item.exchangeRate})`
                                                                        : `ETB ${formatMoney(
                                                                            item?.unitCost
                                                                        )}`
                                                                }
                                                            />

                                                        </Grid>


                                                        <Grid
                                                            size={{ xs: 12, sm: 4, md: 2 }}
                                                        >

                                                            <DetailField
                                                                label={item?.paidByExpense ? "Actual Cost (bought with an expense)" : "Actual Cost"}
                                                                value={
                                                                    `ETB ${formatMoney(
                                                                        summary?.itemTotal
                                                                    )}`
                                                                }
                                                            />

                                                        </Grid>


                                                        <Grid
                                                            size={{ xs: 12, sm: 4, md: 2 }}
                                                        >

                                                            <DetailField
                                                                label="Allocation"
                                                                value={
                                                                    behaviorLabel(summary?.allocationBehavior)
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
                                                                    sx={{
                                                                        fontWeight: 700,
                                                                        mb: 1.5
                                                                    }}>
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

                                                                                // the server’s figures, in the unit the detail is given out in
                                                                                const serverDetail =
                                                                                    delivery.allocationSummary?.items
                                                                                        ?.find(entry => String(entry.itemId) === String(item?._id))
                                                                                        ?.details?.find(entry => String(entry.detailId) === String(detailItem?._id));


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
                                                                                            sx={{
                                                                                                alignItems: "center"
                                                                                            }}
                                                                                        >

                                                                                            <Grid
                                                                                                size={{ xs: 12, sm: 2 }}
                                                                                            >

                                                                                                <Typography
                                                                                                    variant="body2"
                                                                                                    sx={{
                                                                                                        fontWeight: 600
                                                                                                    }}
                                                                                                >
                                                                                                    {
                                                                                                        detailItem?.name ||
                                                                                                        detailItem?.label ||
                                                                                                        "Detail Item"
                                                                                                    }
                                                                                                </Typography>

                                                                                            </Grid>


                                                                                            <Grid
                                                                                                size={{ xs: 6, sm: 2 }}
                                                                                            >

                                                                                                <DetailField
                                                                                                    label="Delivered"
                                                                                                    value={
                                                                                                        serverDetail?.deliveredText ||
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
                                                                                                size={{ xs: 6, sm: 2 }}
                                                                                            >

                                                                                                <DetailField
                                                                                                    label="Allocated"
                                                                                                    value={
                                                                                                        serverDetail?.allocatedText ||
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
                                                                                                size={{ xs: 6, sm: 2 }}
                                                                                            >

                                                                                                <DetailField
                                                                                                    label="Not given out"
                                                                                                    value={
                                                                                                        serverDetail?.remainingText || isMonetaryUnit(
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
                                                                                                size={{ xs: 6, sm: 2 }}
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
                                                                                                size={{ xs: 12, sm: 2 }}
                                                                                            >

                                                                                                <DetailField
                                                                                                    label="Value"
                                                                                                    value={
                                                                                                        `ETB ${formatMoney(
                                                                                                            serverDetail?.allocatedValue ?? detailSummary.allocatedValue
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
                ALLOCATION (one calculation, from the server)
            ================================================= */}

            {delivery.allocationSummary && (
                <Box sx={{ mt: 3 }}>
                    <AllocationOverview summary={delivery.allocationSummary} />
                </Box>
            )}

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
                            size={{ xs: 12, sm: 6, md: 4 }}
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
                            size={{ xs: 12, sm: 6, md: 4 }}
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
                            size={{ xs: 12, sm: 6, md: 4 }}
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
                sx={{ justifyContent: "flex-start",
                    mt: 3,
                    mb: 5
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