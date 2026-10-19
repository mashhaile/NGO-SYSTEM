const {
    isNil,
    toNumber,
    normalizeText,
    getName,
    getCode,
    getId,
    sameId,
    getUnitObject,
    getUnitName,
    unitsMatch,
    normalizeAllocationBehavior,
    isMonetaryUnit,
    asArray,
    firstDefined,
    formatDeliveryLocation
} = require("../helpers");

const {
    drawTitle,
    drawSectionTitle,
    drawSummaryGrid,
    drawTable,
    drawReportMetadata,
    addPageFooters,
    pdfMoney
} = require("../pdf");

const {
    addTitle,
    addMetadata,
    addSummary,
    addDataTable,
    applyMoneyColumns,
    applyNumberColumns
} = require("../excel");

const {
    createCsv
} = require("../csv");


/* =========================================================
   GENERAL HELPERS
========================================================= */

const displayName = (
    value,
    fallback = "—"
) => {

    if (isNil(value)) {
        return fallback;
    }

    if (typeof value === "string") {
        return normalizeText(
            value,
            fallback
        );
    }

    return normalizeText(
        getName(
            value,
            fallback
        ),
        fallback
    );
};


const displayText = (
    value,
    fallback = "—"
) => {

    if (isNil(value)) {
        return fallback;
    }

    return normalizeText(
        value,
        fallback
    );
};


const getRawReportRows = (
    report
) => {

    if (
        Array.isArray(report)
    ) {
        return report;
    }

    if (
        Array.isArray(
            report?.data
        )
    ) {
        return report.data;
    }

    if (
        Array.isArray(
            report?.data?.rows
        )
    ) {
        return report.data.rows;
    }

    if (
        Array.isArray(
            report?.rows
        )
    ) {
        return report.rows;
    }

    if (
        report &&
        (
            report?.deliveryNumber ||
            report?.serviceDeliveryNumber ||
            report?.referenceNumber ||
            report?.items ||
            report?.serviceItems
        )
    ) {
        return [report];
    }

    return [];
};


/* =========================================================
   SERVICE DELIVERY DATA ACCESS
========================================================= */

const getServiceItems = (
    delivery
) => {

    return asArray(
        firstDefined(
            delivery?.items,
            delivery?.serviceItems
        )
    );
};


const getDetailItems = (
    serviceItem
) => {

    return asArray(
        firstDefined(
            serviceItem?.detailItems,
            serviceItem?.details
        )
    );
};


const getBeneficiaryDeliveryRecordsSource = (
    delivery
) => {

    return asArray(
        firstDefined(
            delivery?.serviceDeliveryBeneficiaries,
            delivery?.beneficiaryRecords,
            delivery?.beneficiaries
        )
    );
};


/* =========================================================
   BENEFICIARY / ALLOCATION ACCESS
========================================================= */

const getAllocations = (
    delivery
) => {

    const records =
        getBeneficiaryDeliveryRecordsSource(
            delivery
        );

    const allocations = [];

    for (
        const record
        of records
    ) {

        const recordAllocations =
            asArray(
                record?.allocations
            );

        for (
            const allocation
            of recordAllocations
        ) {

            allocations.push({

                ...allocation,

                beneficiary:
                    firstDefined(
                        allocation?.beneficiary,
                        record?.beneficiary,
                        allocation?.recipient,
                        record?.recipient
                    ),

                beneficiaryNumber:
                    displayText(
                        firstDefined(
                            allocation?.beneficiaryNumber,
                            record?.beneficiaryNumber,

                            allocation?.beneficiary?.beneficiaryNumber,
                            record?.beneficiary?.beneficiaryNumber,

                            allocation?.beneficiary?.number,
                            record?.beneficiary?.number,

                            allocation?.beneficiary?.code,
                            record?.beneficiary?.code,

                            allocation?.beneficiary?.beneficiaryCode,
                            record?.beneficiary?.beneficiaryCode
                        )
                    ),

                beneficiaryName:
                    displayName(
                        firstDefined(
                            allocation?.beneficiaryName,
                            record?.beneficiaryName,

                            allocation?.recipientName,
                            record?.recipientName,

                            allocation?.beneficiary?.name,
                            record?.beneficiary?.name
                        )
                    ),

                beneficiaryStatus:
                    firstDefined(
                        allocation?.beneficiaryStatus,
                        record?.status
                    ),

                beneficiaryRemarks:
                    firstDefined(
                        allocation?.beneficiaryRemarks,
                        record?.remarks
                    )
            });
        }
    }

    return allocations;
};


const getBeneficiaryRecords = (
    delivery
) => {

    const records =
        getBeneficiaryDeliveryRecordsSource(
            delivery
        );

    if (
        records.length > 0
    ) {
        return records;
    }

    /*
     * Legacy fallback.
     */
    if (
        delivery?.beneficiary
    ) {

        return [
            {
                beneficiary:
                    delivery.beneficiary,

                status:
                    delivery.status,

                remarks:
                    firstDefined(
                        delivery?.remarks,
                        "—"
                    ),

                allocations: []
            }
        ];
    }

    return [];
};


/* =========================================================
   DETAIL ITEM RESOLUTION
========================================================= */

const resolveDetailItem = (
    serviceItem,
    allocation
) => {

    const reference =
        firstDefined(
            allocation?.detailItem,
            allocation?.detailItemId
        );

    if (!reference) {
        return null;
    }

    if (
        typeof reference === "object"
    ) {
        return reference;
    }

    return getDetailItems(
        serviceItem
    ).find(
        detail =>
            sameId(
                detail,
                reference
            )
    ) || null;
};


/* =========================================================
   SERVICE TYPE / ALLOCATION BEHAVIOR
========================================================= */

const getServiceType = (
    serviceItem
) => {

    return firstDefined(
        serviceItem?.serviceType,
        serviceItem?.type
    );
};


const getAllocationBehavior = (
    serviceItem
) => {

    const serviceType =
        getServiceType(
            serviceItem
        );

    if (
        serviceType &&
        typeof serviceType === "object"
    ) {

        const behavior =
            firstDefined(
                serviceType?.allocationBehavior,
                serviceType?.allocation?.behavior
            );

        if (behavior) {

            return normalizeAllocationBehavior(
                behavior
            );
        }
    }

    return normalizeAllocationBehavior(
        firstDefined(
            serviceItem?.allocationBehavior,
            serviceItem?.allocation?.allocationBehavior,
            serviceItem?.allocation?.behavior
        )
    );
};


/* =========================================================
   SERVICE ITEM IDENTITY
========================================================= */

const getServiceTypeName = (
    serviceItem
) => {

    return getName(
        getServiceType(
            serviceItem
        ),
        "—"
    );
};


const getServiceItemName = (
    serviceItem
) => {

    return getName(
        firstDefined(
            serviceItem?.serviceItem,
            serviceItem?.item,
            serviceItem?.name,
            serviceItem?.serviceType
        ),
        "—"
    );
};


const getServiceItemCode = (
    serviceItem
) => {

    return getCode(
        firstDefined(
            serviceItem?.serviceItem,
            serviceItem?.item,
            serviceItem?.code,
            serviceItem?.serviceType
        ),
        "—"
    );
};


const getDetailItemName = (
    detailItem
) => {

    if (
        typeof detailItem === "string"
    ) {

        return normalizeText(
            detailItem,
            "—"
        );
    }

    return normalizeText(
        firstDefined(
            detailItem?.name,
            getName(
                detailItem,
                null
            )
        ),
        "—"
    );
};


/* =========================================================
   SERVICE ITEM QUANTITY / VALUE
========================================================= */

const getDeliveredQuantity = (
    serviceItem
) => {

    return toNumber(
        firstDefined(
            serviceItem?.quantity,
            serviceItem?.deliveredQuantity
        ),
        0
    );
};


const getUnit = (
    serviceItem
) => {

    return getUnitObject(
        firstDefined(
            serviceItem?.unit,
            serviceItem?.quantityUnit
        )
    );
};


const getUnitCost = (
    serviceItem
) => {

    return toNumber(
        firstDefined(
            serviceItem?.unitCost,
            serviceItem?.costPerUnit,
            serviceItem?.price
        ),
        0
    );
};


const getActualValue = (
    serviceItem
) => {

    const explicit =
        firstDefined(
            serviceItem?.actualValue,
            serviceItem?.totalValue,
            serviceItem?.totalCost,
            serviceItem?.value
        );

    if (
        !isNil(explicit)
    ) {

        return toNumber(
            explicit,
            0
        );
    }

    return (
        getDeliveredQuantity(
            serviceItem
        ) *
        getUnitCost(
            serviceItem
        )
    );
};


/* =========================================================
   ALLOCATION FILTER
========================================================= */

const getAllocationsForServiceItem = (
    serviceItem,
    allocations = []
) => {

    const serviceItemId =
        getId(
            serviceItem
        );

    return allocations.filter(
        allocation => {

            const allocationServiceItem =
                firstDefined(
                    allocation?.serviceItem,
                    allocation?.item,
                    allocation?.service
                );

            if (
                allocationServiceItem &&
                sameId(
                    allocationServiceItem,
                    serviceItem
                )
            ) {
                return true;
            }

            const allocationServiceItemId =
                firstDefined(
                    allocation?.serviceItemId,
                    allocation?.itemId,
                    allocation?.serviceId
                );

            if (
                serviceItemId &&
                allocationServiceItemId &&
                sameId(
                    allocationServiceItemId,
                    serviceItemId
                )
            ) {
                return true;
            }

            return false;
        }
    );
};


/* =========================================================
   ALLOCATION VALUES
========================================================= */

const getAllocatedValue = (
    serviceItem,
    deliveryAllocations = []
) => {

    const itemAllocations =
        getAllocationsForServiceItem(
            serviceItem,
            deliveryAllocations
        );

    return itemAllocations.reduce(
        (
            sum,
            allocation
        ) => {

            return (
                sum +
                toNumber(
                    firstDefined(
                        allocation?.allocatedValue,
                        allocation?.value
                    ),
                    0
                )
            );
        },
        0
    );
};


const getUnallocatedValue = (
    serviceItem,
    deliveryAllocations = []
) => {

    return Math.max(
        0,
        getActualValue(
            serviceItem
        ) -
        getAllocatedValue(
            serviceItem,
            deliveryAllocations
        )
    );
};


const getOverAllocatedValue = (
    serviceItem,
    deliveryAllocations = []
) => {

    return Math.max(
        0,
        getAllocatedValue(
            serviceItem,
            deliveryAllocations
        ) -
        getActualValue(
            serviceItem
        )
    );
};


/* =========================================================
   ALLOCATION QUANTITY
========================================================= */

const calculateQuantityAllocation = (
    serviceItem,
    deliveryAllocations = []
) => {

    const behavior =
        getAllocationBehavior(
            serviceItem
        );

    const parentUnit =
        getUnit(
            serviceItem
        );

    let directParentAllocatedQuantity = 0;
    let sameUnitDetailAllocatedQuantity = 0;
    let differentUnitDetailAllocatedQuantity = 0;

    for (
        const allocation
        of deliveryAllocations
    ) {

        const allocationServiceItem =
            firstDefined(
                allocation?.serviceItem,
                allocation?.item,
                allocation?.service
            );

        if (
            allocationServiceItem &&
            !sameId(
                allocationServiceItem,
                serviceItem
            )
        ) {
            continue;
        }

        const allocationServiceItemId =
            firstDefined(
                allocation?.serviceItemId,
                allocation?.itemId,
                allocation?.serviceId
            );

        if (
            !allocationServiceItem &&
            allocationServiceItemId &&
            getId(serviceItem) &&
            !sameId(
                allocationServiceItemId,
                getId(serviceItem)
            )
        ) {
            continue;
        }

        const allocationBehavior =
            normalizeAllocationBehavior(
                firstDefined(
                    allocation?.allocationBehavior,
                    allocation?.behavior,
                    behavior
                )
            );

        if (
            allocationBehavior &&
            allocationBehavior !== "Consumption"
        ) {
            continue;
        }

        const quantity =
            toNumber(
                allocation?.quantity,
                0
            );

        if (
            quantity <= 0
        ) {
            continue;
        }

        const detailItem =
            resolveDetailItem(
                serviceItem,
                allocation
            );

        if (
            !detailItem
        ) {

            directParentAllocatedQuantity +=
                quantity;

            continue;
        }

        const detailUnit =
            getUnitObject(
                firstDefined(
                    detailItem?.unit,
                    detailItem?.quantityUnit
                )
            );

        if (
            unitsMatch(
                parentUnit,
                detailUnit
            )
        ) {

            sameUnitDetailAllocatedQuantity +=
                quantity;

        } else {

            differentUnitDetailAllocatedQuantity +=
                quantity;
        }
    }

    const consumedQuantity =
        directParentAllocatedQuantity +
        sameUnitDetailAllocatedQuantity;

    return {

        directParentAllocatedQuantity,

        sameUnitDetailAllocatedQuantity,

        differentUnitDetailAllocatedQuantity,

        consumedQuantity,

        allocatedQuantity:
            consumedQuantity
    };
};


/* =========================================================
   SERVICE ITEM STATUS
========================================================= */

const calculateServiceItemStatus = (
    serviceItem,
    deliveryAllocations = []
) => {

    const behavior =
        getAllocationBehavior(
            serviceItem
        );

    const actualValue =
        getActualValue(
            serviceItem
        );

    const allocatedValue =
        getAllocatedValue(
            serviceItem,
            deliveryAllocations
        );

    const unallocatedValue =
        getUnallocatedValue(
            serviceItem,
            deliveryAllocations
        );

    const overAllocatedValue =
        getOverAllocatedValue(
            serviceItem,
            deliveryAllocations
        );

    const quantity =
        getDeliveredQuantity(
            serviceItem
        );

    const quantityAllocation =
        calculateQuantityAllocation(
            serviceItem,
            deliveryAllocations
        );

    const consumedQuantity =
        quantityAllocation.consumedQuantity;

    let allocationStatus = "";
    let quantityStatus = "";

    if (
        behavior === "Monetary" ||
        behavior === "Participation" ||
        isMonetaryUnit(
            getUnit(serviceItem)
        )
    ) {

        quantityStatus =
            "Not Applicable";

    } else if (
        consumedQuantity > quantity
    ) {

        quantityStatus =
            "Over Allocated";

    } else if (
        consumedQuantity <= 0
    ) {

        quantityStatus =
            "Not Allocated";

    } else if (
        consumedQuantity >= quantity
    ) {

        quantityStatus =
            "Fully Allocated";

    } else {

        quantityStatus =
            "Partially Allocated";
    }


    const hasValueAllocation =
        allocatedValue > 0;

    const hasQuantityAllocation =
        consumedQuantity > 0 ||
        (
            behavior === "Participation" &&
            deliveryAllocations.length > 0
        );


    if (
        !hasValueAllocation &&
        !hasQuantityAllocation
    ) {

        allocationStatus =
            "Not Allocated";

    } else if (
        overAllocatedValue > 0 ||
        consumedQuantity > quantity
    ) {

        allocationStatus =
            "Over Allocated";

    } else if (
        behavior === "Participation"
    ) {

        allocationStatus =
            "Allocated";

    } else if (
        unallocatedValue <= 0
    ) {

        allocationStatus =
            "Fully Allocated";

    } else {

        allocationStatus =
            "Partially Allocated";
    }


    return {

        behavior,

        actualValue,

        allocatedValue,

        unallocatedValue,

        overAllocatedValue,

        deliveredQuantity:
            quantity,

        allocatedQuantity:
            quantityAllocation.allocatedQuantity,

        consumedQuantity,

        directParentAllocatedQuantity:
            quantityAllocation
                .directParentAllocatedQuantity,

        sameUnitDetailAllocatedQuantity:
            quantityAllocation
                .sameUnitDetailAllocatedQuantity,

        differentUnitDetailAllocatedQuantity:
            quantityAllocation
                .differentUnitDetailAllocatedQuantity,

        allocationStatus,

        quantityStatus
    };
};


/* =========================================================
   DETAIL ITEM MODEL
========================================================= */

const buildDetailItemModel = (
    serviceItem,
    detailItem,
    deliveryAllocations = []
) => {

    const quantity =
        toNumber(
            firstDefined(
                detailItem?.quantity,
                detailItem?.deliveredQuantity
            ),
            0
        );

    const unit =
        getUnitObject(
            firstDefined(
                detailItem?.unit,
                detailItem?.quantityUnit
            )
        );

    const unitCost =
        toNumber(
            firstDefined(
                detailItem?.unitCost,
                detailItem?.costPerUnit,
                detailItem?.price
            ),
            0
        );

    const value =
        toNumber(
            firstDefined(
                detailItem?.value,
                detailItem?.totalValue,
                detailItem?.totalCost
            ),
            quantity * unitCost
        );


    const detailAllocations =
        deliveryAllocations.filter(
            allocation => {

                const resolved =
                    resolveDetailItem(
                        serviceItem,
                        allocation
                    );

                return (
                    resolved &&
                    sameId(
                        resolved,
                        detailItem
                    )
                );
            }
        );


    const allocatedQuantity =
        detailAllocations.reduce(
            (
                sum,
                allocation
            ) => {

                return (
                    sum +
                    toNumber(
                        allocation?.quantity,
                        0
                    )
                );
            },
            0
        );


    const allocatedValue =
        detailAllocations.reduce(
            (
                sum,
                allocation
            ) => {

                return (
                    sum +
                    toNumber(
                        firstDefined(
                            allocation?.allocatedValue,
                            allocation?.value
                        ),
                        0
                    )
                );
            },
            0
        );


    return {

        id:
            getId(
                detailItem
            ),

        parentServiceItem:
            getServiceItemName(
                serviceItem
            ),

        serviceType:
            getServiceTypeName(
                serviceItem
            ),

        detailItem:
            getDetailItemName(
                detailItem
            ),

        quantity,

        unit,

        unitName:
            getUnitName(
                unit
            ),

        unitCost,

        value,

        allocatedQuantity,

        allocatedValue,

        unallocatedValue:
            Math.max(
                0,
                value -
                allocatedValue
            )
    };
};


/* =========================================================
   BENEFICIARY
========================================================= */

const getBeneficiaryName = (
    allocation
) => {

    const beneficiary =
        firstDefined(
            allocation?.beneficiary,
            allocation?.recipient
        );

    return getName(
        beneficiary,
        normalizeText(
            firstDefined(
                allocation?.beneficiaryName,
                allocation?.recipientName
            ),
            "—"
        )
    );
};


const getBeneficiaryNumber = (
    allocation
) => {

    const beneficiary =
        firstDefined(
            allocation?.beneficiary,
            allocation?.recipient
        );

    return normalizeText(
        firstDefined(
            beneficiary?.beneficiaryNumber,
            beneficiary?.number,
            beneficiary?.code,
            beneficiary?.beneficiaryCode,
            allocation?.beneficiaryNumber
        ),
        "—"
    );
};


/* =========================================================
   ALLOCATION ROW MODEL
========================================================= */

const buildAllocationRow = (
    serviceItem,
    allocation
) => {

    const detailItem =
        resolveDetailItem(
            serviceItem,
            allocation
        );

    const quantity =
        toNumber(
            allocation?.quantity,
            0
        );

    const allocatedValue =
        toNumber(
            firstDefined(
                allocation?.allocatedValue,
                allocation?.value
            ),
            0
        );


    const unit =
        getUnitObject(
            detailItem
                ? firstDefined(
                    detailItem?.unit,
                    detailItem?.quantityUnit
                )
                : firstDefined(
                    allocation?.unit,
                    serviceItem?.unit,
                    serviceItem?.quantityUnit
                )
        );


    return {

        allocationType:
            detailItem
                ? "Detail Allocation"
                : "Service Item Allocation",

        serviceType:
            getServiceTypeName(
                serviceItem
            ),

        serviceItem:
            getServiceItemName(
                serviceItem
            ),

        detailItem:
            detailItem
                ? getDetailItemName(
                    detailItem
                )
                : "—",

        beneficiaryNumber:
            getBeneficiaryNumber(
                allocation
            ),

        beneficiary:
            getBeneficiaryName(
                allocation
            ),

        quantity,

        unit,

        unitName:
            getUnitName(
                unit
            ),

        allocatedValue,

        allocationBehavior:
            getAllocationBehavior(
                serviceItem
            ),

        remarks:
            normalizeText(
                firstDefined(
                    allocation?.remarks,
                    allocation?.beneficiaryRemarks
                ),
                "—"
            )
    };
};


/* =========================================================
   BENEFICIARY DELIVERY RECORD
========================================================= */

const buildBeneficiaryDeliveryRecord = (
    record
) => {

    const beneficiary =
        firstDefined(
            record?.beneficiary,
            record?.recipient
        );

    return {

        beneficiaryNumber:
            normalizeText(
                firstDefined(
                    beneficiary?.beneficiaryNumber,
                    beneficiary?.number,
                    beneficiary?.code,
                    beneficiary?.beneficiaryCode,
                    record?.beneficiaryNumber
                ),
                "—"
            ),

        beneficiary:
            getName(
                beneficiary,
                normalizeText(
                    firstDefined(
                        record?.beneficiaryName,
                        record?.recipientName
                    ),
                    "—"
                )
            ),

        status:
            normalizeText(
                record?.status,
                "—"
            ),

        remarks:
            normalizeText(
                record?.remarks,
                "—"
            )
    };
};


/* =========================================================
   ORGANIZATION / REPORTING PERIOD
========================================================= */

const resolveOrganization = (
    report,
    options = {},
    deliveries = [],
    rows = []
) => {

    const candidates = [

        options?.organization,
        options?.organizationName,
        options?.org,
        options?.orgName,

        report?.organization,
        report?.organizationName,
        report?.org,
        report?.orgName,

        report?.metadata?.organization,
        report?.metadata?.organizationName,
        report?.metadata?.org,
        report?.metadata?.orgName,

        report?.meta?.organization,
        report?.meta?.organizationName,
        report?.meta?.org,
        report?.meta?.orgName,

        report?.filters?.organization,
        report?.filters?.organizationName,
        report?.filters?.org,
        report?.filters?.orgName,

        report?.filter?.organization,
        report?.filter?.organizationName,

        report?.data?.organization,
        report?.data?.organizationName,
        report?.data?.org,
        report?.data?.orgName,

        report?.data?.metadata?.organization,
        report?.data?.metadata?.organizationName,

        rows?.[0]?.organization,
        rows?.[0]?.organizationName,
        rows?.[0]?.org,
        rows?.[0]?.orgName,

        rows?.[0]?.metadata?.organization,
        rows?.[0]?.metadata?.organizationName,

        deliveries?.[0]?.organization,
        deliveries?.[0]?.organizationName
    ];


    for (
        const candidate
        of candidates
    ) {

        if (
            isNil(candidate)
        ) {
            continue;
        }


        if (
            typeof candidate === "string"
        ) {

            const value =
                normalizeText(
                    candidate,
                    ""
                );

            if (
                value
            ) {
                return value;
            }

            continue;
        }


        const name =
            getName(
                candidate,
                ""
            );

        if (
            normalizeText(
                name,
                ""
            )
        ) {

            return normalizeText(
                name,
                "—"
            );
        }
    }


    return "—";
};


const formatReportingDate = (
    value
) => {

    if (!value) {
        return "";
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

        return normalizeText(
            value,
            ""
        );
    }

    return date.toLocaleDateString(
        "en-GB",
        {
            day: "2-digit",
            month: "short",
            year: "numeric"
        }
    );
};


const resolveReportingPeriod = (
    report,
    options = {}
) => {

    const filters = firstDefined(
        options?.filters,
        report?.filters,
        report?.filter,
        {}
    );


    const direct =
        firstDefined(

            options?.reportingPeriod,

            report?.reportingPeriod,

            report?.metadata?.reportingPeriod,
            report?.metadata?.period,

            report?.meta?.reportingPeriod,
            report?.meta?.period,

            filters?.reportingPeriod,
            filters?.period,

            report?.data?.reportingPeriod,
            report?.data?.period
        );


    if (
        direct
    ) {

        if (
            typeof direct === "string"
        ) {

            return normalizeText(
                direct,
                "All Dates"
            );
        }


        if (
            direct?.label
        ) {

            return normalizeText(
                direct.label,
                "All Dates"
            );
        }


        const directFrom =
            firstDefined(
                direct?.from,
                direct?.dateFrom,
                direct?.startDate,
                direct?.start,
                direct?.begin
            );


        const directTo =
            firstDefined(
                direct?.to,
                direct?.dateTo,
                direct?.endDate,
                direct?.end,
                direct?.finish
            );


        if (
            directFrom &&
            directTo
        ) {

            return (
                `${formatReportingDate(
                    directFrom
                )} – ${formatReportingDate(
                    directTo
                )}`
            );
        }


        if (
            directFrom
        ) {

            return (
                `From ${formatReportingDate(
                    directFrom
                )}`
            );
        }


        if (
            directTo
        ) {

            return (
                `Until ${formatReportingDate(
                    directTo
                )}`
            );
        }
    }


    const dateFrom =
        firstDefined(

            options?.dateFrom,
            options?.startDate,
            options?.from,

            filters?.dateFrom,
            filters?.startDate,
            filters?.from,
            filters?.start,

            report?.dateFrom,
            report?.startDate,
            report?.from,

            report?.metadata?.dateFrom,
            report?.metadata?.startDate,

            report?.meta?.dateFrom,
            report?.meta?.startDate,

            report?.data?.dateFrom,
            report?.data?.startDate
        );


    const dateTo =
        firstDefined(

            options?.dateTo,
            options?.endDate,
            options?.to,

            filters?.dateTo,
            filters?.endDate,
            filters?.to,
            filters?.end,

            report?.dateTo,
            report?.endDate,
            report?.to,

            report?.metadata?.dateTo,
            report?.metadata?.endDate,

            report?.meta?.dateTo,
            report?.meta?.endDate,

            report?.data?.dateTo,
            report?.data?.endDate
        );


    if (
        dateFrom &&
        dateTo
    ) {

        return (
            `${formatReportingDate(
                dateFrom
            )} – ${formatReportingDate(
                dateTo
            )}`
        );
    }


    if (
        dateFrom
    ) {

        return (
            `From ${formatReportingDate(
                dateFrom
            )}`
        );
    }


    if (
        dateTo
    ) {

        return (
            `Until ${formatReportingDate(
                dateTo
            )}`
        );
    }


    return "All Dates";
};


/* =========================================================
   SERVICE DELIVERY MODEL
========================================================= */

const buildServiceDeliveryModel = (
    delivery
) => {

    const serviceItems =
        getServiceItems(
            delivery
        );


    const beneficiaryRecords =
        getBeneficiaryRecords(
            delivery
        );


    const allocations =
        getAllocations(
            delivery
        );


    const organization =
        displayName(
            firstDefined(
                delivery?.organization,
                delivery?.organizationName,
                delivery?.org,
                delivery?.orgName
            )
        );


    const organizationName =
        organization;


    const items =
        serviceItems.map(
            serviceItem => {

                const itemAllocations =
                    getAllocationsForServiceItem(
                        serviceItem,
                        allocations
                    );


                const status =
                    calculateServiceItemStatus(
                        serviceItem,
                        itemAllocations
                    );


                const unit =
                    getUnit(
                        serviceItem
                    );


                return {

                    id:
                        getId(
                            serviceItem
                        ),

                    serviceType:
                        getServiceTypeName(
                            serviceItem
                        ),

                    serviceTypeCode:
                        getCode(
                            getServiceType(
                                serviceItem
                            ),
                            "—"
                        ),

                    serviceItem:
                        getServiceItemName(
                            serviceItem
                        ),

                    serviceItemCode:
                        getServiceItemCode(
                            serviceItem
                        ),

                    allocationBehavior:
                        status.behavior,

                    quantity:
                        status.deliveredQuantity,

                    unit,

                    unitName:
                        getUnitName(
                            unit
                        ),

                    unitCost:
                        getUnitCost(
                            serviceItem
                        ),

                    actualValue:
                        status.actualValue,

                    allocatedValue:
                        status.allocatedValue,

                    unallocatedValue:
                        status.unallocatedValue,

                    overAllocatedValue:
                        status.overAllocatedValue,

                    allocatedQuantity:
                        status.allocatedQuantity,

                    consumedQuantity:
                        status.consumedQuantity,

                    allocationStatus:
                        status.allocationStatus,

                    quantityStatus:
                        status.quantityStatus,

                    details:
                        getDetailItems(
                            serviceItem
                        ).map(
                            detail =>
                                buildDetailItemModel(
                                    serviceItem,
                                    detail,
                                    itemAllocations
                                )
                        ),

                    allocations:
                        itemAllocations.map(
                            allocation =>
                                buildAllocationRow(
                                    serviceItem,
                                    allocation
                                )
                        )
                };
            }
        );


    return {

        id:
            getId(
                delivery
            ),

        organization,

        organizationName,

        deliveryNumber:
            normalizeText(
                firstDefined(
                    delivery?.deliveryNumber,
                    delivery?.serviceDeliveryNumber,
                    delivery?.referenceNumber,
                    delivery?.code
                ),
                "—"
            ),

        deliveryDate:
            firstDefined(
                delivery?.deliveryDate,
                delivery?.date,
                delivery?.createdAt
            ) || null,

        program:
            getName(
                delivery?.program,
                "—"
            ),

        programCode:
            getCode(
                delivery?.program,
                "—"
            ),

        project:
            getName(
                delivery?.project,
                "—"
            ),

        projectCode:
            getCode(
                delivery?.project,
                "—"
            ),

        activity:
            getName(
                delivery?.activity,
                "—"
            ),

        activityCode:
            getCode(
                delivery?.activity,
                "—"
            ),

        activityRun:
            getName(
                firstDefined(
                    delivery?.activityRun,
                    delivery?.run
                ),
                "—"
            ),

        activityRunCode:
            getCode(
                firstDefined(
                    delivery?.activityRun,
                    delivery?.run
                ),
                "—"
            ),

        location:
            normalizeText(
                formatDeliveryLocation(delivery),
                "—"
            ),

        recipientType:
            normalizeText(
                delivery?.recipientType,
                "—"
            ),

        recipientName:
            normalizeText(
                firstDefined(
                    delivery?.recipientName,
                    getName(
                        delivery?.recipient,
                        ""
                    )
                ),
                "—"
            ),

        allocationMethod:
            normalizeText(
                delivery?.allocationMethod,
                "—"
            ),

        status:
            normalizeText(
                delivery?.status,
                "—"
            ),

        fundingSource:
            getName(
                delivery?.fundingSource,
                "—"
            ),

        beneficiaries:
            beneficiaryRecords.map(
                buildBeneficiaryDeliveryRecord
            ),

        items,

        allocations:
            items.flatMap(
                item =>
                    item.allocations
            )
    };
};


/* =========================================================
   REPORT-LEVEL MODEL
========================================================= */

const buildServiceDeliveryReport = (
    report,
    options = {}
) => {

    const rows =
        getRawReportRows(
            report
        );


    const deliveries =
        rows.map(
            buildServiceDeliveryModel
        );


    const organization =
        resolveOrganization(
            report,
            options,
            deliveries,
            rows
        );


    const generatedAt =
        firstDefined(
            options?.generatedAt,
            report?.generatedAt,
            report?.metadata?.generatedAt,
            report?.meta?.generatedAt,
            new Date()
        );


    const reportingPeriod =
        resolveReportingPeriod(
            report,
            options
        );


    /* =====================================================
       ALLOCATIONS
    ===================================================== */

    const allocationRows =
        deliveries.flatMap(
            delivery =>
                delivery.allocations
        );


    const allBeneficiaryRecords =
        deliveries.flatMap(
            delivery =>
                delivery.beneficiaries
        );


    /* =====================================================
       UNIQUE BENEFICIARIES
    ===================================================== */

    const allBeneficiaryMap =
        new Map();


    for (
        const record
        of allBeneficiaryRecords
    ) {

        const key =
            record.beneficiaryNumber !== "—"
                ? record.beneficiaryNumber
                : record.beneficiary;


        if (
            !allBeneficiaryMap.has(
                key
            )
        ) {

            allBeneficiaryMap.set(
                key,
                record
            );
        }
    }


    /* =====================================================
       BENEFICIARIES WITH ALLOCATIONS
    ===================================================== */

    const allocationBeneficiaryMap =
        new Map();


    for (
        const row
        of allocationRows
    ) {

        const key =
            row.beneficiaryNumber !== "—"
                ? row.beneficiaryNumber
                : row.beneficiary;


        if (
            !allocationBeneficiaryMap.has(
                key
            )
        ) {

            allocationBeneficiaryMap.set(
                key,
                {
                    beneficiaryNumber:
                        row.beneficiaryNumber,

                    beneficiary:
                        row.beneficiary,

                    allocations:
                        []
                }
            );
        }


        allocationBeneficiaryMap
            .get(key)
            .allocations
            .push(
                row
            );
    }


    const beneficiaries =
        Array.from(
            allocationBeneficiaryMap.values()
        );


    /* =====================================================
       FINANCIAL SUMMARY
    ===================================================== */

    let totalActualValue = 0;
    let totalAllocatedValue = 0;
    let totalUnallocatedValue = 0;
    let totalOverAllocatedValue = 0;


    for (
        const delivery
        of deliveries
    ) {

        for (
            const item
            of delivery.items
        ) {

            totalActualValue +=
                item.actualValue;

            totalAllocatedValue +=
                item.allocatedValue;

            totalUnallocatedValue +=
                item.unallocatedValue;

            totalOverAllocatedValue +=
                item.overAllocatedValue;
        }
    }


    /* =====================================================
       QUANTITY BY UNIT
    ===================================================== */

    const quantityByUnitMap =
        new Map();


    for (
        const delivery
        of deliveries
    ) {

        for (
            const item
            of delivery.items
        ) {

            if (
                item.quantity <= 0 ||
                !item.unitName ||
                item.unitName === "—"
            ) {
                continue;
            }


            const key =
                item.unitName;


            quantityByUnitMap.set(
                key,
                (
                    quantityByUnitMap.get(
                        key
                    ) || 0
                ) +
                item.quantity
            );
        }
    }


    const quantityByUnit =
        Array.from(
            quantityByUnitMap.entries()
        ).map(
            (
                [
                    unit,
                    quantity
                ]
            ) => ({
                unit,
                quantity
            })
        );


    /* =====================================================
       SERVICE ITEMS
    ===================================================== */

    const totalServiceItems =
        deliveries.reduce(
            (
                sum,
                delivery
            ) =>
                sum +
                delivery.items.length,
            0
        );


    const allocationRate =
        totalActualValue > 0
            ? (
                totalAllocatedValue /
                totalActualValue
            ) * 100
            : 0;


    const averageDeliveryValue =
        deliveries.length > 0
            ? (
                totalActualValue /
                deliveries.length
            )
            : 0;


    /* =====================================================
       BENEFICIARY SUMMARIES
    ===================================================== */

    const beneficiarySummaries =
        beneficiaries.map(
            beneficiary => {

                const quantityMap =
                    new Map();

                let allocatedValue = 0;

                const services =
                    new Set();


                for (
                    const allocation
                    of beneficiary.allocations
                ) {

                    allocatedValue +=
                        toNumber(
                            allocation.allocatedValue,
                            0
                        );


                    if (
                        allocation.quantity > 0 &&
                        allocation.unitName !== "—"
                    ) {

                        quantityMap.set(
                            allocation.unitName,
                            (
                                quantityMap.get(
                                    allocation.unitName
                                ) || 0
                            ) +
                            allocation.quantity
                        );
                    }


                    const serviceLabel =
                        allocation.detailItem !== "—"
                            ? (
                                `${allocation.serviceItem} — ${allocation.detailItem}`
                            )
                            : allocation.serviceItem;


                    services.add(
                        serviceLabel
                    );
                }


                return {

                    beneficiaryNumber:
                        beneficiary.beneficiaryNumber,

                    beneficiary:
                        beneficiary.beneficiary,

                    allocatedQuantityByUnit:
                        Array.from(
                            quantityMap.entries()
                        ).map(
                            (
                                [
                                    unit,
                                    quantity
                                ]
                            ) => ({
                                unit,
                                quantity
                            })
                        ),

                    allocatedValue,

                    servicesReceived:
                        Array.from(
                            services
                        )
                };
            }
        );


    return {

        reportType:
            "serviceDelivery",

        organization,

        generatedAt,

        reportingPeriod,

        deliveries,

        allocations:
            allocationRows,

        beneficiaries:
            beneficiarySummaries,

        beneficiaryRecords:
            allBeneficiaryRecords,

        summary: {

            totalDeliveries:
                deliveries.length,

            totalBeneficiaries:
                allBeneficiaryMap.size,

            beneficiaryDeliveryRecords:
                allBeneficiaryRecords.length,

            totalBeneficiariesWithAllocations:
                beneficiaries.length,

            totalServiceItems,

            totalActualValue,

            totalAllocatedValue,

            totalUnallocatedValue,

            totalOverAllocatedValue,

            allocationRate,

            averageDeliveryValue,

            quantityByUnit
        }
    };
};


/* =========================================================
   PDF EXPORT
========================================================= */

const toPdf = async (
    doc,
    report,
    options = {}
) => {

    const model =
        buildServiceDeliveryReport(
            report,
            options
        );

    const summary =
        model.summary;


    const text =
        value =>
            normalizeText(
                value,
                "—"
            );


    const money =
        value =>
            pdfMoney(
                toNumber(
                    value,
                    0
                )
            );


    const number =
        value => {

            const numeric =
                toNumber(
                    value,
                    0
                );


            if (
                Number.isInteger(
                    numeric
                )
            ) {

                return numeric.toLocaleString(
                    "en-US"
                );
            }


            return numeric.toLocaleString(
                "en-US",
                {
                    minimumFractionDigits: 0,
                    maximumFractionDigits: 2
                }
            );
        };


    const percentage =
        value => {

            const numeric =
                toNumber(
                    value,
                    0
                );

            return (
                `${numeric.toLocaleString(
                    "en-US",
                    {
                        minimumFractionDigits: 2,
                        maximumFractionDigits: 2
                    }
                )}%`
            );
        };


    const formatDate =
        value => {

            if (!value) {
                return "—";
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

                return text(
                    value
                );
            }


            return date.toLocaleDateString(
                "en-GB",
                {
                    day: "2-digit",
                    month: "short",
                    year: "numeric"
                }
            );
        };


    /* =====================================================
       HEADER
    ===================================================== */

    drawTitle(
        doc,
        "SERVICE DELIVERY REPORT"
    );


    drawReportMetadata(
        doc,
        {
            organization:
                model.organization,

            generatedAt:
                model.generatedAt,

            reportingPeriod:
                model.reportingPeriod
        }
    );


    /* =====================================================
       EXECUTIVE SUMMARY
    ===================================================== */

    drawSectionTitle(
        doc,
        "EXECUTIVE SUMMARY"
    );


    drawSummaryGrid(
        doc,
        [

            {
                label:
                    "TOTAL DELIVERIES",

                value:
                    number(
                        summary.totalDeliveries
                    )
            },

            {
                label:
                    "TOTAL BENEFICIARIES",

                value:
                    number(
                        summary.totalBeneficiaries
                    )
            },

            {
                label:
                    "SERVICE ITEMS",

                value:
                    number(
                        summary.totalServiceItems
                    )
            },

            {
                label:
                    "DELIVERY RECORDS",

                value:
                    number(
                        summary.beneficiaryDeliveryRecords
                    )
            },

            {
                label:
                    "ACTUAL SUPPORT VALUE",

                value:
                    money(
                        summary.totalActualValue
                    )
            },

            {
                label:
                    "ALLOCATED VALUE",

                value:
                    money(
                        summary.totalAllocatedValue
                    )
            },

            {
                label:
                    "UNALLOCATED VALUE",

                value:
                    money(
                        summary.totalUnallocatedValue
                    )
            },

            {
                label:
                    "OVER ALLOCATED",

                value:
                    money(
                        summary.totalOverAllocatedValue
                    )
            },

            {
                label:
                    "ALLOCATION RATE",

                value:
                    percentage(
                        summary.allocationRate
                    )
            },

            {
                label:
                    "AVERAGE DELIVERY VALUE",

                value:
                    money(
                        summary.averageDeliveryValue
                    )
            }
        ]
    );


    /* =====================================================
       DELIVERY INFORMATION
    ===================================================== */

    if (
        model.deliveries.length === 1
    ) {

        const delivery =
            model.deliveries[0];


        drawSectionTitle(
            doc,
            "DELIVERY INFORMATION"
        );


        drawTable(
            doc,

            [
                {
                    label: "Delivery No.",
                    key: "deliveryNumber"
                },
                {
                    label: "Delivery Date",
                    key: "deliveryDate"
                },
                {
                    label: "Program",
                    key: "program"
                },
                {
                    label: "Project",
                    key: "project"
                },
                {
                    label: "Activity",
                    key: "activity"
                },
                {
                    label: "Activity Run",
                    key: "activityRun"
                },
                {
                    label: "Location",
                    key: "location"
                },
                {
                    label: "Status",
                    key: "status"
                },
                {
                    label: "Recipient Type",
                    key: "recipientType"
                },
                {
                    label: "Recipient",
                    key: "recipientName"
                },
                {
                    label: "Allocation Method",
                    key: "allocationMethod"
                },
                {
                    label: "Funding Source",
                    key: "fundingSource"
                }
            ],

            [
                {

                    deliveryNumber:
                        text(
                            delivery.deliveryNumber
                        ),

                    deliveryDate:
                        formatDate(
                            delivery.deliveryDate
                        ),

                    program:
                        text(
                            delivery.program
                        ),

                    project:
                        text(
                            delivery.project
                        ),

                    activity:
                        text(
                            delivery.activity
                        ),

                    activityRun:
                        text(
                            delivery.activityRun
                        ),

                    location:
                        text(
                            delivery.location
                        ),

                    status:
                        text(
                            delivery.status
                        ),

                    recipientType:
                        text(
                            delivery.recipientType
                        ),

                    recipientName:
                        text(
                            delivery.recipientName
                        ),

                    allocationMethod:
                        text(
                            delivery.allocationMethod
                        ),

                    fundingSource:
                        text(
                            delivery.fundingSource
                        )
                }
            ]
        );
    }


    /* =====================================================
       DELIVERED QUANTITY
    ===================================================== */

    drawSectionTitle(
        doc,
        "DELIVERED QUANTITY"
    );


    const quantityRows =
        summary.quantityByUnit.map(
            row => ({
                unit:
                    text(
                        row.unit
                    ),

                quantity:
                    number(
                        row.quantity
                    )
            })
        );


    drawTable(
        doc,

        [
            {
                label:
                    "Unit",

                key:
                    "unit"
            },

            {
                label:
                    "Quantity",

                key:
                    "quantity"
            }
        ],

        quantityRows.length > 0
            ? quantityRows
            : [
                {
                    unit:
                        "—",

                    quantity:
                        "0"
                }
            ]
    );


    /* =====================================================
       SERVICES DELIVERED
    ===================================================== */

    const serviceRows =
        model.deliveries.flatMap(
            delivery =>
                delivery.items.map(
                    item => ({

                        delivery:
                            text(
                                delivery.deliveryNumber
                            ),

                        service:
                            text(
                                item.serviceItem
                            ),

                        quantity:
                            number(
                                item.quantity
                            ),

                        unit:
                            text(
                                item.unitName
                            ),

                        actualValue:
                            money(
                                item.actualValue
                            ),

                        allocatedValue:
                            money(
                                item.allocatedValue
                            ),

                        unallocatedValue:
                            money(
                                item.unallocatedValue
                            ),

                        status:
                            text(
                                item.allocationStatus
                            )
                    })
                )
        );


    if (
        serviceRows.length > 0
    ) {

        drawSectionTitle(
            doc,
            "SERVICES DELIVERED"
        );


        drawTable(
            doc,

            [
                {
                    label:
                        "Delivery",

                    key:
                        "delivery"
                },

                {
                    label:
                        "Service",

                    key:
                        "service"
                },

                {
                    label:
                        "Qty",

                    key:
                        "quantity"
                },

                {
                    label:
                        "Unit",

                    key:
                        "unit"
                },

                {
                    label:
                        "Actual Value",

                    key:
                        "actualValue"
                },

                {
                    label:
                        "Allocated",

                    key:
                        "allocatedValue"
                },

                {
                    label:
                        "Unallocated",

                    key:
                        "unallocatedValue"
                },

                {
                    label:
                        "Status",

                    key:
                        "status"
                }
            ],

            serviceRows
        );
    }


    /* =====================================================
       SUPPORTING DETAILS
    ===================================================== */

    const detailRows =
        model.deliveries.flatMap(
            delivery =>
                delivery.items.flatMap(
                    item =>
                        item.details.map(
                            detail => ({

                                delivery:
                                    text(
                                        delivery.deliveryNumber
                                    ),

                                service:
                                    text(
                                        detail.serviceType
                                    ),

                                detailItem:
                                    text(
                                        detail.detailItem
                                    ),

                                quantity:
                                    number(
                                        detail.quantity
                                    ),

                                unit:
                                    text(
                                        detail.unitName
                                    ),

                                unitCost:
                                    money(
                                        detail.unitCost
                                    ),

                                value:
                                    money(
                                        detail.value
                                    ),

                                allocated:
                                    money(
                                        detail.allocatedValue
                                    ),

                                unallocated:
                                    money(
                                        detail.unallocatedValue
                                    )
                            })
                        )
                )
        );


    if (
        detailRows.length > 0
    ) {

        drawSectionTitle(
            doc,
            "SUPPORTING DETAIL ITEMS"
        );


        drawTable(
            doc,

            [
                {
                    label:
                        "Delivery",

                    key:
                        "delivery"
                },

                {
                    label:
                        "Service",

                    key:
                        "service"
                },

                {
                    label:
                        "Detail Item",

                    key:
                        "detailItem"
                },

                {
                    label:
                        "Qty",

                    key:
                        "quantity"
                },

                {
                    label:
                        "Unit",

                    key:
                        "unit"
                },

                {
                    label:
                        "Unit Cost",

                    key:
                        "unitCost"
                },

                {
                    label:
                        "Value",

                    key:
                        "value"
                },

                {
                    label:
                        "Allocated",

                    key:
                        "allocated"
                },

                {
                    label:
                        "Unallocated",

                    key:
                        "unallocated"
                }
            ],

            detailRows
        );
    }


   /* =====================================================
   BENEFICIARY ALLOCATIONS
===================================================== */

const beneficiaryAllocationMap = new Map();

for (const allocation of model.allocations || []) {

    const beneficiaryNumber =
        allocation.beneficiaryNumber &&
        allocation.beneficiaryNumber !== "—"
            ? String(allocation.beneficiaryNumber).trim()
            : "";

    const beneficiaryName =
        allocation.beneficiary &&
        allocation.beneficiary !== "—"
            ? String(allocation.beneficiary).trim()
            : "";

    /*
     * Prefer beneficiary number.
     * Fall back to beneficiary name.
     * If neither exists, create a unique key so unrelated
     * anonymous allocations are never merged together.
     */
    const key =
        beneficiaryNumber
            ? `number:${beneficiaryNumber}`
            : beneficiaryName
                ? `name:${beneficiaryName}`
                : `unknown:${beneficiaryAllocationMap.size}`;

    if (!beneficiaryAllocationMap.has(key)) {

        beneficiaryAllocationMap.set(key, {
            beneficiaryNumber:
                beneficiaryNumber || "—",

            beneficiary:
                beneficiaryName || "—",

            allocations: [],

            totalAllocatedValue: 0
        });
    }

    const group =
        beneficiaryAllocationMap.get(key);

    const allocatedValue =
        toNumber(
            firstDefined(
                allocation.allocatedValue,
                allocation.value,
                0
            )
        );

    group.allocations.push({
        ...allocation,
        allocatedValue
    });

    group.totalAllocatedValue +=
        allocatedValue;
}


if (beneficiaryAllocationMap.size > 0) {

    drawSectionTitle(
        doc,
        "BENEFICIARY ALLOCATIONS"
    );


    const beneficiaryAllocationRows = [];


    for (
        const group
        of beneficiaryAllocationMap.values()
    ) {

        /*
         * Render every allocation belonging to the
         * beneficiary.
         *
         * Beneficiary information is shown ONLY on
         * the first allocation row. This prevents the
         * report from visually repeating the beneficiary
         * identity and total on every allocation.
         */
        group.allocations.forEach(
            (allocation, index) => {

                const quantity =
                    toNumber(
                        allocation.quantity
                    );

                beneficiaryAllocationRows.push({

                    beneficiaryNumber:
                        index === 0
                            ? group.beneficiaryNumber
                            : "",

                    beneficiary:
                        index === 0
                            ? group.beneficiary
                            : "",

                    service:
                        firstDefined(
                            allocation.service,
                            allocation.serviceName,
                            "—"
                        ),

                    detailItem:
                        firstDefined(
                            allocation.detailItem,
                            allocation.detailItemName,
                            "—"
                        ),

                    quantity:
                        quantity > 0
                            ? quantity
                            : "—",

                    unit:
                        firstDefined(
                            allocation.unit,
                            allocation.unitName,
                            "—"
                        ),

                    allocated:
                        pdfMoney(
                            allocation.allocatedValue
                        ),

                    isSubtotal: false
                });
            }
        );


        /*
         * One and ONLY one beneficiary subtotal.
         */
        beneficiaryAllocationRows.push({

            beneficiaryNumber: "",

            beneficiary: "",

            service: "",

            detailItem: "",

            quantity: "",

            unit: "Beneficiary Total",

            allocated:
                pdfMoney(
                    group.totalAllocatedValue
                ),

            isSubtotal: true
        });
    }


    drawTable(
        doc,
        [
            {
                label: "Beneficiary No.",
                key: "beneficiaryNumber"
            },

            {
                label: "Beneficiary",
                key: "beneficiary"
            },

            {
                label: "Service",
                key: "service"
            },

            {
                label: "Detail Item",
                key: "detailItem"
            },

            {
                label: "Qty",
                key: "quantity"
            },

            {
                label: "Unit",
                key: "unit"
            },

            {
                label: "Allocated",
                key: "allocated"
            }
        ],
        beneficiaryAllocationRows
    );
}


/* =====================================================
   FINAL REPORT TOTALS
===================================================== */

drawSectionTitle(
    doc,
    "REPORT TOTALS"
);


drawSummaryGrid(
    doc,
    [

        {
            label:
                "ACTUAL SUPPORT VALUE",

            value:
                money(
                    summary.totalActualValue
                )
        },

        {
            label:
                "ALLOCATED VALUE",

            value:
                money(
                    summary.totalAllocatedValue
                )
        },

        {
            label:
                "UNALLOCATED VALUE",

            value:
                money(
                    summary.totalUnallocatedValue
                )
        },

        {
            label:
                "OVER ALLOCATED",

            value:
                money(
                    summary.totalOverAllocatedValue
                )
        },

        {
            label:
                "ALLOCATION RATE",

            value:
                percentage(
                    summary.allocationRate
                )
        }

    ]
);


/* =====================================================
   FOOTER
===================================================== */

addPageFooters(
    doc,
    options.footer || {}
);


return doc;
};
/* =========================================================
   EXCEL EXPORT
========================================================= */

const toExcel = async (
    workbook,
    report,
    options = {}
) => {

    const model =
        buildServiceDeliveryReport(
            report,
            options
        );


    const summarySheet =
        workbook.addWorksheet(
            "Summary"
        );


    addTitle(
        summarySheet,
        "Service Delivery Report"
    );


    addMetadata(
        summarySheet,
        [

            [
                "Organization",
                model.organization
            ],

            [
                "Generated",
                model.generatedAt
            ],

            [
                "Reporting Period",
                model.reportingPeriod
            ]
        ]
    );


    addSummary(
        summarySheet,
        [

            [
                "Total Deliveries",
                model.summary.totalDeliveries
            ],

            [
                "Total Beneficiaries",
                model.summary.totalBeneficiaries
            ],

            [
                "Beneficiary Delivery Records",
                model.summary.beneficiaryDeliveryRecords
            ],

            [
                "Unique Beneficiaries With Allocations",
                model.summary.totalBeneficiariesWithAllocations
            ],

            [
                "Total Service Items",
                model.summary.totalServiceItems
            ],

            [
                "Actual Support Value",
                model.summary.totalActualValue
            ],

            [
                "Allocated Value",
                model.summary.totalAllocatedValue
            ],

            [
                "Unallocated",
                model.summary.totalUnallocatedValue
            ],

            [
                "Over Allocated",
                model.summary.totalOverAllocatedValue
            ],

            [
                "Allocation Rate",
                model.summary.allocationRate
            ],

            [
                "Average Delivery Value",
                model.summary.averageDeliveryValue
            ]
        ]
    );


    /* =====================================================
       QUANTITY BY UNIT
    ===================================================== */

    const quantitySheet =
        workbook.addWorksheet(
            "Quantity By Unit"
        );


    addDataTable(
        quantitySheet,

        [
            {
                label:
                    "Unit",

                key:
                    "unit"
            },

            {
                label:
                    "Quantity",

                key:
                    "quantity"
            }
        ],

        model.summary.quantityByUnit
    );


    applyNumberColumns(
        quantitySheet,
        ["B"]
    );


    /* =====================================================
       SERVICE ITEMS
    ===================================================== */

    const serviceItemSheet =
        workbook.addWorksheet(
            "Service Items"
        );


    addDataTable(
        serviceItemSheet,

        [
            {
                label:
                    "Delivery",

                key:
                    "deliveryNumber"
            },

            {
                label:
                    "Service Type",

                key:
                    "serviceType"
            },

            {
                label:
                    "Service Item",

                key:
                    "serviceItem"
            },

            {
                label:
                    "Quantity",

                key:
                    "quantity"
            },

            {
                label:
                    "Unit",

                key:
                    "unitName"
            },

            {
                label:
                    "Unit Cost",

                key:
                    "unitCost"
            },

            {
                label:
                    "Actual Value",

                key:
                    "actualValue"
            },

            {
                label:
                    "Allocated Value",

                key:
                    "allocatedValue"
            },

            {
                label:
                    "Unallocated",

                key:
                    "unallocatedValue"
            },

            {
                label:
                    "Over Allocated",

                key:
                    "overAllocatedValue"
            },

            {
                label:
                    "Allocation Status",

                key:
                    "allocationStatus"
            },

            {
                label:
                    "Quantity Status",

                key:
                    "quantityStatus"
            }
        ],

        model.deliveries.flatMap(
            delivery =>
                delivery.items.map(
                    item => ({

                        deliveryNumber:
                            delivery.deliveryNumber,

                        serviceType:
                            item.serviceType,

                        serviceItem:
                            item.serviceItem,

                        quantity:
                            item.quantity,

                        unitName:
                            item.unitName,

                        unitCost:
                            item.unitCost,

                        actualValue:
                            item.actualValue,

                        allocatedValue:
                            item.allocatedValue,

                        unallocatedValue:
                            item.unallocatedValue,

                        overAllocatedValue:
                            item.overAllocatedValue,

                        allocationStatus:
                            item.allocationStatus,

                        quantityStatus:
                            item.quantityStatus
                    })
                )
        )
    );


    applyNumberColumns(
        serviceItemSheet,
        ["D"]
    );


    applyMoneyColumns(
        serviceItemSheet,
        [
            "F",
            "G",
            "H",
            "I",
            "J"
        ]
    );


    /* =====================================================
       DETAIL ITEMS
    ===================================================== */

    const detailSheet =
        workbook.addWorksheet(
            "Detail Items"
        );


    const detailRows =
        model.deliveries.flatMap(
            delivery =>
                delivery.items.flatMap(
                    item =>
                        item.details.map(
                            detail => ({

                                deliveryNumber:
                                    delivery.deliveryNumber,

                                serviceType:
                                    detail.serviceType,

                                serviceItem:
                                    detail.parentServiceItem,

                                detailItem:
                                    detail.detailItem,

                                quantity:
                                    detail.quantity,

                                unitName:
                                    detail.unitName,

                                unitCost:
                                    detail.unitCost,

                                value:
                                    detail.value,

                                allocatedValue:
                                    detail.allocatedValue,

                                unallocatedValue:
                                    detail.unallocatedValue
                            })
                        )
                )
        );


    addDataTable(
        detailSheet,

        [
            {
                label:
                    "Delivery",

                key:
                    "deliveryNumber"
            },

            {
                label:
                    "Service Type",

                key:
                    "serviceType"
            },

            {
                label:
                    "Service Item",

                key:
                    "serviceItem"
            },

            {
                label:
                    "Detail Item",

                key:
                    "detailItem"
            },

            {
                label:
                    "Quantity",

                key:
                    "quantity"
            },

            {
                label:
                    "Unit",

                key:
                    "unitName"
            },

            {
                label:
                    "Unit Cost",

                key:
                    "unitCost"
            },

            {
                label:
                    "Value",

                key:
                    "value"
            },

            {
                label:
                    "Allocated Value",

                key:
                    "allocatedValue"
            },

            {
                label:
                    "Unallocated",

                key:
                    "unallocatedValue"
            }
        ],

        detailRows
    );


    applyNumberColumns(
        detailSheet,
        ["E"]
    );


    applyMoneyColumns(
        detailSheet,
        [
            "G",
            "H",
            "I",
            "J"
        ]
    );


    /* =====================================================
       BENEFICIARY ALLOCATIONS
    ===================================================== */

    const allocationSheet =
        workbook.addWorksheet(
            "Beneficiary Allocations"
        );


    addDataTable(
        allocationSheet,

        [
            {
                label:
                    "Allocation Type",

                key:
                    "allocationType"
            },

            {
                label:
                    "Service Type",

                key:
                    "serviceType"
            },

            {
                label:
                    "Service Item",

                key:
                    "serviceItem"
            },

            {
                label:
                    "Detail Item",

                key:
                    "detailItem"
            },

            {
                label:
                    "Beneficiary No.",

                key:
                    "beneficiaryNumber"
            },

            {
                label:
                    "Beneficiary",

                key:
                    "beneficiary"
            },

            {
                label:
                    "Quantity",

                key:
                    "quantity"
            },

            {
                label:
                    "Unit",

                key:
                    "unitName"
            },

            {
                label:
                    "Allocated Value",

                key:
                    "allocatedValue"
            },

            {
                label:
                    "Allocation Behavior",

                key:
                    "allocationBehavior"
            },

            {
                label:
                    "Remarks",

                key:
                    "remarks"
            }
        ],

        model.allocations
    );


    applyNumberColumns(
        allocationSheet,
        ["G"]
    );


    applyMoneyColumns(
        allocationSheet,
        ["I"]
    );


    /* =====================================================
       BENEFICIARY RECORDS
    ===================================================== */

    const recordSheet =
        workbook.addWorksheet(
            "Beneficiary Records"
        );


    addDataTable(
        recordSheet,

        [
            {
                label:
                    "Beneficiary No.",

                key:
                    "beneficiaryNumber"
            },

            {
                label:
                    "Beneficiary",

                key:
                    "beneficiary"
            },

            {
                label:
                    "Status",

                key:
                    "status"
            },

            {
                label:
                    "Remarks",

                key:
                    "remarks"
            }
        ],

        model.beneficiaryRecords
    );


    /* =====================================================
       BENEFICIARY SUMMARY
    ===================================================== */

    const beneficiarySheet =
        workbook.addWorksheet(
            "Beneficiary Summary"
        );


    addDataTable(
        beneficiarySheet,

        [
            {
                label:
                    "Beneficiary No.",

                key:
                    "beneficiaryNumber"
            },

            {
                label:
                    "Beneficiary",

                key:
                    "beneficiary"
            },

            {
                label:
                    "Allocated Quantity",

                key:
                    "allocatedQuantityByUnit"
            },

            {
                label:
                    "Allocated Value",

                key:
                    "allocatedValue"
            },

            {
                label:
                    "Services Received",

                key:
                    "servicesReceived"
            }
        ],

        model.beneficiaries.map(
            beneficiary => ({

                beneficiaryNumber:
                    beneficiary.beneficiaryNumber,

                beneficiary:
                    beneficiary.beneficiary,

                allocatedQuantityByUnit:
                    beneficiary
                        .allocatedQuantityByUnit
                        .map(
                            quantity =>
                                `${quantity.quantity} ${quantity.unit}`
                        )
                        .join(", "),

                allocatedValue:
                    beneficiary.allocatedValue,

                servicesReceived:
                    beneficiary
                        .servicesReceived
                        .join(", ")
            })
        )
    );


    applyMoneyColumns(
        beneficiarySheet,
        ["D"]
    );


    return workbook;
};


/* =========================================================
   CSV EXPORT
========================================================= */

const toCsv = (
    report,
    options = {}
) => {

    const model =
        buildServiceDeliveryReport(
            report,
            options
        );


    const rows =
        model.deliveries.flatMap(
            delivery =>
                delivery.items.map(
                    item => ({

                        Organization:
                            model.organization,

                        "Reporting Period":
                            model.reportingPeriod,

                        Delivery:
                            delivery.deliveryNumber,

                        "Delivery Date":
                            delivery.deliveryDate,

                        Program:
                            delivery.program,

                        Project:
                            delivery.project,

                        Activity:
                            delivery.activity,

                        "Activity Run":
                            delivery.activityRun,

                        "Recipient Type":
                            delivery.recipientType,

                        "Allocation Method":
                            delivery.allocationMethod,

                        "Delivery Status":
                            delivery.status,

                        "Service Type":
                            item.serviceType,

                        "Service Type Code":
                            item.serviceTypeCode,

                        "Service Item":
                            item.serviceItem,

                        "Service Item Code":
                            item.serviceItemCode,

                        "Allocation Behavior":
                            item.allocationBehavior,

                        Quantity:
                            item.quantity,

                        Unit:
                            item.unitName,

                        "Unit Cost":
                            item.unitCost,

                        "Actual Value":
                            item.actualValue,

                        "Allocated Value":
                            item.allocatedValue,

                        Unallocated:
                            item.unallocatedValue,

                        "Over Allocated":
                            item.overAllocatedValue,

                        "Allocated Quantity":
                            item.allocatedQuantity,

                        "Consumed Quantity":
                            item.consumedQuantity,

                        "Allocation Status":
                            item.allocationStatus,

                        "Quantity Status":
                            item.quantityStatus
                    })
                )
        );


    return createCsv(
        rows,

        {
            fields: [

                {
                    label:
                        "Organization",

                    value:
                        "Organization"
                },

                {
                    label:
                        "Reporting Period",

                    value:
                        "Reporting Period"
                },

                {
                    label:
                        "Delivery",

                    value:
                        "Delivery"
                },

                {
                    label:
                        "Delivery Date",

                    value:
                        "Delivery Date"
                },

                {
                    label:
                        "Program",

                    value:
                        "Program"
                },

                {
                    label:
                        "Project",

                    value:
                        "Project"
                },

                {
                    label:
                        "Activity",

                    value:
                        "Activity"
                },

                {
                    label:
                        "Activity Run",

                    value:
                        "Activity Run"
                },

                {
                    label:
                        "Recipient Type",

                    value:
                        "Recipient Type"
                },

                {
                    label:
                        "Allocation Method",

                    value:
                        "Allocation Method"
                },

                {
                    label:
                        "Delivery Status",

                    value:
                        "Delivery Status"
                },

                {
                    label:
                        "Service Type",

                    value:
                        "Service Type"
                },

                {
                    label:
                        "Service Type Code",

                    value:
                        "Service Type Code"
                },

                {
                    label:
                        "Service Item",

                    value:
                        "Service Item"
                },

                {
                    label:
                        "Service Item Code",

                    value:
                        "Service Item Code"
                },

                {
                    label:
                        "Allocation Behavior",

                    value:
                        "Allocation Behavior"
                },

                {
                    label:
                        "Quantity",

                    value:
                        "Quantity"
                },

                {
                    label:
                        "Unit",

                    value:
                        "Unit"
                },

                {
                    label:
                        "Unit Cost",

                    value:
                        "Unit Cost"
                },

                {
                    label:
                        "Actual Value",

                    value:
                        "Actual Value"
                },

                {
                    label:
                        "Allocated Value",

                    value:
                        "Allocated Value"
                },

                {
                    label:
                        "Unallocated",

                    value:
                        "Unallocated"
                },

                {
                    label:
                        "Over Allocated",

                    value:
                        "Over Allocated"
                },

                {
                    label:
                        "Allocated Quantity",

                    value:
                        "Allocated Quantity"
                },

                {
                    label:
                        "Consumed Quantity",

                    value:
                        "Consumed Quantity"
                },

                {
                    label:
                        "Allocation Status",

                    value:
                        "Allocation Status"
                },

                {
                    label:
                        "Quantity Status",

                    value:
                        "Quantity Status"
                }
            ]
        }
    );
};


/* =========================================================
   EXPORTS
========================================================= */

module.exports = {

    getServiceItems,

    getDetailItems,

    getAllocations,

    getBeneficiaryRecords,

    resolveDetailItem,

    getServiceType,

    getAllocationBehavior,

    getServiceTypeName,

    getServiceItemName,

    getServiceItemCode,

    getDetailItemName,

    getDeliveredQuantity,

    getUnit,

    getUnitCost,

    getActualValue,

    getAllocatedValue,

    getUnallocatedValue,

    getOverAllocatedValue,

    calculateQuantityAllocation,

    calculateServiceItemStatus,

    getAllocationsForServiceItem,

    buildDetailItemModel,

    buildAllocationRow,

    buildBeneficiaryDeliveryRecord,

    buildServiceDeliveryModel,

    buildServiceDeliveryReport,

    build:
        buildServiceDeliveryReport,

    toPdf,

    toExcel,

    toCsv
};