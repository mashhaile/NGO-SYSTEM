const ServiceDelivery =
    require("../../models/ServiceDelivery");

const ServiceDeliveryBeneficiary =
    require("../../models/ServiceDeliveryBeneficiary");


// =====================================================
// HELPERS
// =====================================================

const toNumber = (value) => {

    const number =
        Number(value);

    return Number.isFinite(number)
        ? number
        : 0;

};


const toId = (value) => {

    if (!value) {
        return null;
    }

    return String(
        value?._id ||
        value
    );

};


const getBeneficiaryName = (beneficiary) => {

    if (!beneficiary) {
        return null;
    }

    return [
        beneficiary.firstName,
        beneficiary.middleName,
        beneficiary.lastName
    ]
        .filter(Boolean)
        .join(" ");

};


const getUnitObject = (unit) => {

    if (!unit) {
        return null;
    }

    if (
        typeof unit === "object" &&
        unit._id
    ) {

        return {

            id:
                unit._id,

            name:
                unit.name ||
                null,

            value:
                unit.value ||
                null,

            code:
                unit.code ||
                null

        };

    }

    return {

        id:
            unit

    };

};


const getUnitKey = (unit) => {

    if (!unit) {
        return null;
    }

    return (
        unit?._id ||
        unit?.id ||
        unit
    )
        ? String(
            unit?._id ||
            unit?.id ||
            unit
        )
        : null;

};


const getUnitLabel = (unit) => {

    if (!unit) {
        return "Unknown";
    }

    return (
        unit.name ||
        unit.value ||
        unit.code ||
        unit.id ||
        unit._id ||
        "Unknown"
    );

};


const isMonetaryUnit = (unit) => {

    const values = [

        unit?.name,
        unit?.value,
        unit?.code

    ]
        .filter(Boolean)
        .map(
            value =>
                String(
                    value
                )
                    .trim()
                    .toLowerCase()
        );

    return values.some(
        value =>
            value === "etb" ||
            value === "birr" ||
            value === "money" ||
            value === "monetary" ||
            value.includes("currency") ||
            value.includes("monetary")
    );

};


const getAllocationBehavior = (item) => {

    const values = [

        item?.serviceType?.allocationBehavior,
        item?.serviceType?.behavior,
        item?.allocationBehavior

    ]
        .filter(Boolean)
        .map(
            value =>
                String(
                    value
                )
                    .trim()
                    .toUpperCase()
        );

    if (
        values.includes("PARTICIPATION")
    ) {

        return "PARTICIPATION";

    }

    return "CONSUMPTION";

};


const getDetailItemFromAllocation = (
    allocation,
    serviceItem
) => {

    if (
        !allocation?.detailItem ||
        !Array.isArray(
            serviceItem?.detailItems
        )
    ) {

        return null;

    }

    const detailId =
        toId(
            allocation.detailItem
        );

    return (
        serviceItem.detailItems.find(
            detail =>
                toId(
                    detail
                ) ===
                detailId
        ) ||
        null
    );

};


const getServiceItemFromAllocation = (
    allocation,
    items
) => {

    if (
        !allocation?.serviceItem ||
        !Array.isArray(items)
    ) {

        return null;

    }

    const serviceItemId =
        toId(
            allocation.serviceItem
        );

    return (
        items.find(
            item =>
                toId(
                    item
                ) ===
                serviceItemId
        ) ||
        null
    );

};


const getServiceItemTotal = (item) => {

    const parentTotal =
        toNumber(
            item?.totalCost
        );

    if (
        parentTotal > 0
    ) {

        return parentTotal;

    }

    if (
        Array.isArray(
            item?.detailItems
        )
    ) {

        return item.detailItems.reduce(
            (
                total,
                detail
            ) =>
                total +
                toNumber(
                    detail?.totalCost
                ),
            0
        );

    }

    return 0;

};


// =====================================================
// DATE FILTER
// =====================================================

const buildDeliveryDateFilter = (
    filters = {}
) => {

    let startDate = null;
    let endDate = null;


    // =================================================
    // EXPLICIT DATE RANGE
    // =================================================

    if (
        filters.startDate
    ) {

        startDate =
            new Date(
                filters.startDate
            );

    }


    if (
        filters.endDate
    ) {

        endDate =
            new Date(
                filters.endDate
            );

        if (
            !Number.isNaN(
                endDate.getTime()
            )
        ) {

            endDate.setDate(
                endDate.getDate() + 1
            );

        }

    }


    // =================================================
    // YEAR
    // =================================================

    if (
        filters.year &&
        !filters.startDate &&
        !filters.endDate
    ) {

        const year =
            Number(
                filters.year
            );

        if (
            Number.isInteger(
                year
            )
        ) {

            startDate =
                new Date(
                    year,
                    0,
                    1
                );

            endDate =
                new Date(
                    year + 1,
                    0,
                    1
                );

        }

    }


    // =================================================
    // REPORTING PERIOD
    // =================================================

    if (
        filters.period &&
        filters.year
    ) {

        const year =
            Number(
                filters.year
            );

        const period =
            String(
                filters.period
            )
                .trim()
                .toLowerCase();


        // =============================================
        // MONTHLY
        // =============================================

        if (
            period === "monthly" &&
            filters.month
        ) {

            const month =
                Number(
                    filters.month
                ) - 1;

            if (
                month >= 0 &&
                month <= 11
            ) {

                startDate =
                    new Date(
                        year,
                        month,
                        1
                    );

                endDate =
                    new Date(
                        year,
                        month + 1,
                        1
                    );

            }

        }


        // =============================================
        // QUARTERLY
        // =============================================

        if (
            period === "quarterly" &&
            filters.quarter
        ) {

            const quarter =
                Number(
                    filters.quarter
                );

            if (
                quarter >= 1 &&
                quarter <= 4
            ) {

                const month =
                    (quarter - 1) * 3;

                startDate =
                    new Date(
                        year,
                        month,
                        1
                    );

                endDate =
                    new Date(
                        year,
                        month + 3,
                        1
                    );

            }

        }


        // =============================================
        // SEMI ANNUAL / SIX MONTHLY
        // =============================================

        if (
            (
                period === "semiannual" ||
                period === "semi-annual" ||
                period === "sixmonthly" ||
                period === "six-monthly"
            ) &&
            filters.half
        ) {

            const half =
                Number(
                    filters.half
                );

            if (
                half === 1
            ) {

                startDate =
                    new Date(
                        year,
                        0,
                        1
                    );

                endDate =
                    new Date(
                        year,
                        6,
                        1
                    );

            }

            if (
                half === 2
            ) {

                startDate =
                    new Date(
                        year,
                        6,
                        1
                    );

                endDate =
                    new Date(
                        year + 1,
                        0,
                        1
                    );

            }

        }


        // =============================================
        // ANNUAL
        // =============================================

        if (
            period === "annual" ||
            period === "yearly"
        ) {

            startDate =
                new Date(
                    year,
                    0,
                    1
                );

            endDate =
                new Date(
                    year + 1,
                    0,
                    1
                );

        }

    }


    const filter = {};


    if (
        startDate ||
        endDate
    ) {

        filter.$gte =
            startDate &&
            !Number.isNaN(
                startDate.getTime()
            )
                ? startDate
                : new Date(0);

        filter.$lt =
            endDate &&
            !Number.isNaN(
                endDate.getTime()
            )
                ? endDate
                : new Date(
                    "9999-12-31"
                );

    }


    return filter;

};


// =====================================================
// MONTH NAME
// =====================================================

const getMonthName = (date) => {

    if (!date) {
        return null;
    }

    return new Date(
        date
    ).toLocaleString(
        "en-US",
        {
            month: "long"
        }
    );

};


// =====================================================
// ADD QUANTITY BY UNIT
// =====================================================

const addQuantityByUnit = (
    map,
    unit,
    quantity
) => {

    const unitId =
        getUnitKey(
            unit
        );

    const key =
        unitId ||
        "unknown";


    if (
        !map.has(
            key
        )
    ) {

        map.set(
            key,
            {

                unit:
                    getUnitObject(
                        unit
                    ),

                quantity:
                    0

            }
        );

    }


    const entry =
        map.get(
            key
        );


    entry.quantity +=
        toNumber(
            quantity
        );

};


// =====================================================
// CONVERT QUANTITY MAP
// =====================================================

const convertQuantityMap = (
    map
) => {

    return Array.from(
        map.values()
    );

};


// =====================================================
// CONVERT QUANTITY MAP TO OBJECT
// =====================================================

const convertQuantityMapToObject = (
    map
) => {

    const result = {};


    map.forEach(
        entry => {

            const unit =
                entry.unit ||
                {};


            const label =
                getUnitLabel(
                    unit
                );


            result[label] =
                toNumber(
                    entry.quantity
                );

        }
    );


    return result;

};


// =====================================================
// GET ALLOCATION ACCOUNTING
// =====================================================

const calculateItemAllocation = (
    item,
    beneficiaryRecords,
    items
) => {

    let directParentAllocatedQuantity =
        0;

    let sameUnitDetailAllocatedQuantity =
        0;

    let allocatedValue =
        0;

    let differentUnitDetailAllocatedQuantity =
        0;


    const itemId =
        toId(
            item
        );


    const parentUnit =
        getUnitLabel(
            item?.unit
        );


    const monetary =
        isMonetaryUnit(
            item?.unit
        );


    const allocationBehavior =
        getAllocationBehavior(
            item
        );


    const beneficiaries = [];


    beneficiaryRecords.forEach(
        record => {

            const allocations =
                Array.isArray(
                    record?.allocations
                )
                    ? record.allocations
                    : [];


            allocations.forEach(
                allocation => {

                    const allocationServiceItem =
                        getServiceItemFromAllocation(
                            allocation,
                            items
                        );


                    if (
                        !allocationServiceItem ||
                        toId(
                            allocationServiceItem
                        ) !==
                        itemId
                    ) {

                        return;

                    }


                    const quantity =
                        toNumber(
                            allocation?.quantity
                        );


                    const value =
                        toNumber(
                            allocation?.allocatedValue
                        );


                    allocatedValue +=
                        value;


                    const detailItem =
                        getDetailItemFromAllocation(
                            allocation,
                            allocationServiceItem
                        );


                    if (
                        detailItem
                    ) {

                        const detailUnit =
                            getUnitLabel(
                                detailItem?.unit
                            );


                        if (
                            parentUnit !==
                                "Unknown" &&
                            detailUnit !==
                                "Unknown" &&
                            parentUnit ===
                                detailUnit
                        ) {

                            if (
                                !monetary &&
                                allocationBehavior ===
                                "CONSUMPTION"
                            ) {

                                sameUnitDetailAllocatedQuantity +=
                                    quantity;

                            }

                        }
                        else {

                            differentUnitDetailAllocatedQuantity +=
                                quantity;

                        }

                    }
                    else {

                        if (
                            !monetary &&
                            allocationBehavior ===
                            "CONSUMPTION"
                        ) {

                            directParentAllocatedQuantity +=
                                quantity;

                        }

                    }


                    beneficiaries.push({

                        id:
                            allocation?._id,

                        beneficiary:
                            record?.beneficiary
                                ? {

                                    id:
                                        record.beneficiary._id,

                                    beneficiaryNumber:
                                        record.beneficiary
                                            .beneficiaryNumber,

                                    name:
                                        getBeneficiaryName(
                                            record.beneficiary
                                        ),

                                    gender:
                                        record.beneficiary.gender

                                }
                                : null,

                        detailItem:
                            detailItem
                                ? {

                                    id:
                                        detailItem._id,

                                    name:
                                        detailItem.name ||
                                        null,

                                    quantity:
                                        toNumber(
                                            detailItem.quantity
                                        ),

                                    unit:
                                        getUnitObject(
                                            detailItem.unit
                                        )

                                }
                                : null,

                        quantity,

                        allocatedValue:
                            value,

                        remarks:
                            allocation?.remarks ||
                            ""

                    });

                }
            );

        }
    );


    const deliveredQuantity =
        monetary
            ? 0
            : toNumber(
                item?.quantity
            );


    const totalParentConsumedQuantity =
        directParentAllocatedQuantity +
        sameUnitDetailAllocatedQuantity;


    let unallocatedQuantity = 0;

    let overAllocatedQuantity = 0;


    if (
        !monetary &&
        allocationBehavior ===
        "CONSUMPTION"
    ) {

        unallocatedQuantity =
            Math.max(
                deliveredQuantity -
                totalParentConsumedQuantity,
                0
            );

        overAllocatedQuantity =
            Math.max(
                totalParentConsumedQuantity -
                deliveredQuantity,
                0
            );

    }


    const actualValue =
        getServiceItemTotal(
            item
        );


    const unallocatedValue =
        Math.max(
            actualValue -
            allocatedValue,
            0
        );


    const overAllocatedValue =
        Math.max(
            allocatedValue -
            actualValue,
            0
        );


    let allocationStatus =
        "Not Allocated";


    if (
        allocatedValue > 0 ||
        directParentAllocatedQuantity > 0 ||
        sameUnitDetailAllocatedQuantity > 0 ||
        differentUnitDetailAllocatedQuantity > 0
    ) {

        if (
            overAllocatedQuantity > 0 ||
            overAllocatedValue > 0
        ) {

            allocationStatus =
                "Over Allocated";

        }
        else if (
            allocationBehavior ===
            "PARTICIPATION"
        ) {

            allocationStatus =
                "Allocated";

        }
        else if (
            unallocatedQuantity === 0 &&
            unallocatedValue === 0
        ) {

            allocationStatus =
                "Fully Allocated";

        }
        else {

            allocationStatus =
                "Partially Allocated";

        }

    }


    return {

        deliveredQuantity,

        directParentAllocatedQuantity,

        sameUnitDetailAllocatedQuantity,

        differentUnitDetailAllocatedQuantity,

        allocatedQuantity:
            totalParentConsumedQuantity,

        unallocatedQuantity,

        overAllocatedQuantity,

        allocatedValue,

        unallocatedValue,

        overAllocatedValue,

        allocationStatus,

        beneficiaries

    };

};


// =====================================================
// GENERATE SERVICE DELIVERY REPORT
// =====================================================

const generate = async (
    filters = {},
    context
) => {

    // =================================================
    // CONTEXT
    // =================================================

    if (
        !context ||
        !context.organizationId
    ) {

        throw new Error(
            "Report organization context is required."
        );

    }


    const organizationId =
        context.organizationId;


    // =================================================
    // DATE FILTER
    // =================================================

    const deliveryDateFilter =
        buildDeliveryDateFilter(
            filters
        );


    // =================================================
    // SERVICE DELIVERY QUERY
    // =================================================

    const serviceQuery = {

        organization:
            organizationId,

        isDeleted:
            false

    };


    // =================================================
    // STATUS
    // =================================================

    if (
        filters.status
    ) {

        serviceQuery.status =
            filters.status;

    }
    else {

        serviceQuery.status =
            "Delivered";

    }


    // =================================================
    // BASIC FILTERS
    // =================================================

    if (
        filters.program
    ) {

        serviceQuery.program =
            filters.program;

    }


    if (
        filters.project
    ) {

        serviceQuery.project =
            filters.project;

    }


    if (
        filters.activity
    ) {

        serviceQuery.activity =
            filters.activity;

    }


    if (
        filters.activityRun
    ) {

        serviceQuery.activityRun =
            filters.activityRun;

    }


    if (
        filters.beneficiary
    ) {

        serviceQuery.beneficiary =
            filters.beneficiary;

    }


    if (
        filters.enrollment
    ) {

        serviceQuery.enrollment =
            filters.enrollment;

    }


    if (
        filters.fundingSource
    ) {

        serviceQuery.fundingSource =
            filters.fundingSource;

    }


    if (
        filters.recipientType
    ) {

        serviceQuery.recipientType =
            filters.recipientType;

    }


    if (
        filters.allocationMethod
    ) {

        serviceQuery.allocationMethod =
            filters.allocationMethod;

    }


    if (
        Object.keys(
            deliveryDateFilter
        ).length > 0
    ) {

        serviceQuery.deliveryDate =
            deliveryDateFilter;

    }


    // =================================================
    // GET DELIVERIES
    // =================================================

    const deliveries =
        await ServiceDelivery.find(
            serviceQuery
        )

        .populate({
            path: "beneficiary",
            select:
                "beneficiaryNumber firstName middleName lastName gender"
        })

        .populate({
            path: "program",
            select:
                "programCode name status"
        })

        .populate({
            path: "project",
            select:
                "projectCode name status"
        })

        .populate({
            path: "activity",
            select:
                "activityCode name activityType status"
        })

        .populate({
            path: "activityRun",
            select:
                "runCode name startDate endDate status"
        })

        .populate({
            path: "fundingSource",
            select:
                "name value code"
        })

        .populate({
            path: "enrollment",
            select:
                "enrollmentDate status"
        })

        .populate({
            path: "items.serviceCategory",
            select:
                "name value code"
        })

        .populate({
            path: "items.serviceType",
            select:
                "name value code allocationBehavior behavior"
        })

        .populate({
            path: "items.unit",
            select:
                "name value code"
        })

        .populate({
            path: "items.detailItems.unit",
            select:
                "name value code"
        })

        .sort({
            deliveryDate:
                -1
        });


    // =================================================
    // BENEFICIARY RELATIONSHIPS
    // =================================================

    const deliveryIds =
        deliveries.map(
            delivery =>
                delivery._id
        );


    let beneficiaryRecords = [];


    if (
        deliveryIds.length > 0
    ) {

        beneficiaryRecords =
            await ServiceDeliveryBeneficiary.find({

                organization:
                    organizationId,

                serviceDelivery:
                    {
                        $in:
                            deliveryIds
                    }

            })

            .populate(
                "beneficiary",
                "beneficiaryNumber firstName middleName lastName gender"
            )

            .populate(
                "enrollment",
                "enrollmentDate status"
            )

            .sort({
                createdAt:
                    1
            });

    }


    // =================================================
    // INDEX BENEFICIARIES BY DELIVERY
    // =================================================

    const beneficiaryMap =
        new Map();


    beneficiaryRecords.forEach(
        record => {

            const deliveryId =
                toId(
                    record.serviceDelivery
                );


            if (
                !beneficiaryMap.has(
                    deliveryId
                )
            ) {

                beneficiaryMap.set(
                    deliveryId,
                    []
                );

            }


            beneficiaryMap
                .get(
                    deliveryId
                )
                .push(
                    record
                );

        }
    );


    // =================================================
    // REPORT MAPS
    // =================================================

    const rows = [];

    const programMap =
        new Map();

    const projectMap =
        new Map();

    const activityMap =
        new Map();

    const categoryMap =
        new Map();

    const serviceTypeMap =
        new Map();

    const fundingMap =
        new Map();

    const monthlyMap =
        new Map();

    const recipientMap =
        new Map();


    // =================================================
    // GLOBAL BENEFICIARIES
    // =================================================

    const beneficiarySet =
        new Set();

    const allocatedBeneficiarySet =
        new Set();


    // =================================================
    // GLOBAL TOTALS
    // =================================================

    let totalAllocatedValue =
        0;

    let totalUnallocatedValue =
        0;

    let totalOverAllocatedValue =
        0;

    let totalAllocatedQuantity =
        0;

    let totalUnallocatedQuantity =
        0;

    let totalOverAllocatedQuantity =
        0;


    // =================================================
    // PROCESS DELIVERIES
    // =================================================

    for (
        const delivery
        of deliveries
    ) {

        const deliveryId =
            toId(
                delivery._id
            );


        const deliveryBeneficiaryRecords =
            beneficiaryMap.get(
                deliveryId
            ) || [];


        const rawItems =
            Array.isArray(
                delivery.items
            )
                ? delivery.items
                : [];


        // =================================================
        // BENEFICIARY ROWS
        // =================================================

        const beneficiaries =
            deliveryBeneficiaryRecords.map(
                record => {

                    const allocations =
                        Array.isArray(
                            record?.allocations
                        )
                            ? record.allocations
                            : [];


                    const allocationRows =
                        allocations.map(
                            allocation => {

                                const serviceItem =
                                    getServiceItemFromAllocation(
                                        allocation,
                                        rawItems
                                    );


                                const detailItem =
                                    getDetailItemFromAllocation(
                                        allocation,
                                        serviceItem
                                    );


                                return {

                                    id:
                                        allocation?._id,

                                    serviceItem:
                                        allocation.serviceItem,

                                    detailItem:
                                        detailItem
                                            ? {

                                                id:
                                                    detailItem._id,

                                                name:
                                                    detailItem.name ||
                                                    null,

                                                quantity:
                                                    toNumber(
                                                        detailItem.quantity
                                                    ),

                                                unit:
                                                    getUnitObject(
                                                        detailItem.unit
                                                    )

                                            }
                                            : null,

                                    quantity:
                                        toNumber(
                                            allocation.quantity
                                        ),

                                    allocatedValue:
                                        toNumber(
                                            allocation.allocatedValue
                                        ),

                                    remarks:
                                        allocation.remarks ||
                                        ""

                                };

                            }
                        );


                    const beneficiaryAllocatedValue =
                        allocationRows.reduce(
                            (
                                total,
                                allocation
                            ) =>
                                total +
                                allocation.allocatedValue,
                            0
                        );


                    const beneficiaryAllocatedQuantity =
                        allocationRows.reduce(
                            (
                                total,
                                allocation
                            ) =>
                                total +
                                allocation.quantity,
                            0
                        );


                    const beneficiaryId =
                        record?.beneficiary
                            ? record.beneficiary._id
                            : null;


                    if (
                        beneficiaryId
                    ) {

                        beneficiarySet.add(
                            String(
                                beneficiaryId
                            )
                        );

                    }


                    if (
                        beneficiaryId &&
                        allocationRows.length > 0
                    ) {

                        allocatedBeneficiarySet.add(
                            String(
                                beneficiaryId
                            )
                        );

                    }


                    return {

                        id:
                            record._id,

                        beneficiary:
                            record.beneficiary
                                ? {

                                    id:
                                        record.beneficiary._id,

                                    beneficiaryNumber:
                                        record.beneficiary
                                            .beneficiaryNumber,

                                    name:
                                        getBeneficiaryName(
                                            record.beneficiary
                                        ),

                                    gender:
                                        record.beneficiary.gender

                                }
                                : null,

                        enrollment:
                            record.enrollment
                                ? {

                                    id:
                                        record.enrollment._id,

                                    enrollmentDate:
                                        record.enrollment
                                            .enrollmentDate,

                                    status:
                                        record.enrollment.status

                                }
                                : null,

                        status:
                            record.status,

                        quantity:
                            record.quantity !== null &&
                            record.quantity !== undefined
                                ? toNumber(
                                    record.quantity
                                )
                                : null,

                        allocations:
                            allocationRows,

                        totalAllocatedQuantity:
                            beneficiaryAllocatedQuantity,

                        totalAllocatedValue:
                            beneficiaryAllocatedValue,

                        remarks:
                            record.remarks ||
                            "",

                        createdAt:
                            record.createdAt,

                        updatedAt:
                            record.updatedAt

                    };

                }
            );


        // =================================================
        // ITEMS
        // =================================================

        const items =
            rawItems.map(
                item => {

                    const itemAllocation =
                        calculateItemAllocation(
                            item,
                            deliveryBeneficiaryRecords,
                            rawItems
                        );


                    const deliveredQuantity =
                        toNumber(
                            item.quantity
                        );


                    const actualValue =
                        getServiceItemTotal(
                            item
                        );


                    const detailItems =
                        Array.isArray(
                            item.detailItems
                        )
                            ? item.detailItems.map(
                                detail => {

                                    const detailId =
                                        toId(
                                            detail
                                        );


                                    let allocatedQuantity =
                                        0;

                                    let allocatedValue =
                                        0;


                                    deliveryBeneficiaryRecords.forEach(
                                        record => {

                                            const allocations =
                                                Array.isArray(
                                                    record?.allocations
                                                )
                                                    ? record.allocations
                                                    : [];


                                            allocations.forEach(
                                                allocation => {

                                                    const allocationServiceItem =
                                                        getServiceItemFromAllocation(
                                                            allocation,
                                                            rawItems
                                                        );


                                                    if (
                                                        !allocationServiceItem ||
                                                        toId(
                                                            allocationServiceItem
                                                        ) !==
                                                        toId(
                                                            item
                                                        )
                                                    ) {

                                                        return;

                                                    }


                                                    const allocationDetailItem =
                                                        getDetailItemFromAllocation(
                                                            allocation,
                                                            item
                                                        );


                                                    if (
                                                        !allocationDetailItem ||
                                                        toId(
                                                            allocationDetailItem
                                                        ) !==
                                                        detailId
                                                    ) {

                                                        return;

                                                    }


                                                    allocatedQuantity +=
                                                        toNumber(
                                                            allocation.quantity
                                                        );

                                                    allocatedValue +=
                                                        toNumber(
                                                            allocation.allocatedValue
                                                        );

                                                }
                                            );

                                        }
                                    );


                                    const detailDeliveredQuantity =
                                        toNumber(
                                            detail.quantity
                                        );


                                    const detailMonetary =
                                        isMonetaryUnit(
                                            detail.unit
                                        );


                                    const behavior =
                                        getAllocationBehavior(
                                            item
                                        );


                                    const detailUnallocatedQuantity =
                                        detailMonetary ||
                                        behavior ===
                                        "PARTICIPATION"
                                            ? 0
                                            : Math.max(
                                                detailDeliveredQuantity -
                                                allocatedQuantity,
                                                0
                                            );


                                    const detailOverAllocatedQuantity =
                                        detailMonetary ||
                                        behavior ===
                                        "PARTICIPATION"
                                            ? 0
                                            : Math.max(
                                                allocatedQuantity -
                                                detailDeliveredQuantity,
                                                0
                                            );


                                    const detailTotalCost =
                                        toNumber(
                                            detail.totalCost
                                        );


                                    const detailUnallocatedValue =
                                        Math.max(
                                            detailTotalCost -
                                            allocatedValue,
                                            0
                                        );


                                    const detailOverAllocatedValue =
                                        Math.max(
                                            allocatedValue -
                                            detailTotalCost,
                                            0
                                        );


                                    return {

                                        id:
                                            detail._id,

                                        name:
                                            detail.name ||
                                            null,

                                        description:
                                            detail.description ||
                                            null,

                                        quantity:
                                            detailDeliveredQuantity,

                                        unit:
                                            getUnitObject(
                                                detail.unit
                                            ),

                                        unitCost:
                                            toNumber(
                                                detail.unitCost
                                            ),

                                        totalCost:
                                            detailTotalCost,

                                        remarks:
                                            detail.remarks ||
                                            "",

                                        allocation: {

                                            allocatedQuantity,

                                            unallocatedQuantity:
                                                detailUnallocatedQuantity,

                                            overAllocatedQuantity:
                                                detailOverAllocatedQuantity,

                                            allocatedValue,

                                            unallocatedValue:
                                                detailUnallocatedValue,

                                            overAllocatedValue:
                                                detailOverAllocatedValue

                                        }

                                    };

                                }
                            )
                            : [];


                    return {

                        id:
                            item._id,

                        serviceCategory:
                            item.serviceCategory
                                ? {

                                    id:
                                        item.serviceCategory._id,

                                    name:
                                        item.serviceCategory.name,

                                    value:
                                        item.serviceCategory.value,

                                    code:
                                        item.serviceCategory.code

                                }
                                : null,

                        serviceType:
                            item.serviceType
                                ? {

                                    id:
                                        item.serviceType._id,

                                    name:
                                        item.serviceType.name,

                                    value:
                                        item.serviceType.value,

                                    code:
                                        item.serviceType.code,

                                    allocationBehavior:
                                        item.serviceType.allocationBehavior ||
                                        item.serviceType.behavior ||
                                        null

                                }
                                : null,

                        allocationBehavior:
                            getAllocationBehavior(
                                item
                            ),

                        quantity:
                            deliveredQuantity,

                        unit:
                            getUnitObject(
                                item.unit
                            ),

                        unitCost:
                            toNumber(
                                item.unitCost
                            ),

                        totalCost:
                            actualValue,

                        remarks:
                            item.remarks ||
                            "",

                        detailItems,

                        allocation: {

                            directParentAllocatedQuantity:
                                itemAllocation
                                    .directParentAllocatedQuantity,

                            sameUnitDetailAllocatedQuantity:
                                itemAllocation
                                    .sameUnitDetailAllocatedQuantity,

                            differentUnitDetailAllocatedQuantity:
                                itemAllocation
                                    .differentUnitDetailAllocatedQuantity,

                            allocatedQuantity:
                                itemAllocation
                                    .allocatedQuantity,

                            unallocatedQuantity:
                                itemAllocation
                                    .unallocatedQuantity,

                            overAllocatedQuantity:
                                itemAllocation
                                    .overAllocatedQuantity,

                            allocatedValue:
                                itemAllocation
                                    .allocatedValue,

                            unallocatedValue:
                                itemAllocation
                                    .unallocatedValue,

                            overAllocatedValue:
                                itemAllocation
                                    .overAllocatedValue,

                            allocationStatus:
                                itemAllocation
                                    .allocationStatus,

                            beneficiaries:
                                itemAllocation
                                    .beneficiaries

                        }

                    };

                }
            );


        // =================================================
        // DELIVERY TOTALS
        // =================================================

        const totalQuantity =
            items.reduce(
                (
                    total,
                    item
                ) =>
                    total +
                    toNumber(
                        item.quantity
                    ),
                0
            );


        const totalItemValue =
            items.reduce(
                (
                    total,
                    item
                ) =>
                    total +
                    toNumber(
                        item.totalCost
                    ),
                0
            );


        const deliveryAllocatedValue =
            items.reduce(
                (
                    total,
                    item
                ) =>
                    total +
                    toNumber(
                        item.allocation.allocatedValue
                    ),
                0
            );


        const deliveryUnallocatedValue =
            items.reduce(
                (
                    total,
                    item
                ) =>
                    total +
                    toNumber(
                        item.allocation.unallocatedValue
                    ),
                0
            );


        const deliveryOverAllocatedValue =
            items.reduce(
                (
                    total,
                    item
                ) =>
                    total +
                    toNumber(
                        item.allocation.overAllocatedValue
                    ),
                0
            );


        const deliveryAllocatedQuantityByUnit =
            new Map();

        const deliveryUnallocatedQuantityByUnit =
            new Map();

        const deliveryOverAllocatedQuantityByUnit =
            new Map();


        items.forEach(
            item => {

                const behavior =
                    item.allocationBehavior;


                if (
                    behavior !==
                    "CONSUMPTION"
                ) {

                    return;

                }


                const parentUnit =
                    item.unit;


                const directParent =
                    toNumber(
                        item.allocation
                            .directParentAllocatedQuantity
                    );


                const sameUnitDetail =
                    toNumber(
                        item.allocation
                            .sameUnitDetailAllocatedQuantity
                    );


                const consumed =
                    directParent +
                    sameUnitDetail;


                addQuantityByUnit(
                    deliveryAllocatedQuantityByUnit,
                    parentUnit,
                    consumed
                );


                addQuantityByUnit(
                    deliveryUnallocatedQuantityByUnit,
                    parentUnit,
                    item.allocation
                        .unallocatedQuantity
                );


                addQuantityByUnit(
                    deliveryOverAllocatedQuantityByUnit,
                    parentUnit,
                    item.allocation
                        .overAllocatedQuantity
                );


                // =========================================
                // DIFFERENT-UNIT DETAIL ALLOCATIONS
                // =========================================

                item.detailItems.forEach(
                    detail => {

                        const detailUnitKey =
                            getUnitKey(
                                detail.unit
                            );

                        const parentUnitKey =
                            getUnitKey(
                                item.unit
                            );


                        if (
                            detailUnitKey &&
                            parentUnitKey &&
                            detailUnitKey ===
                            parentUnitKey
                        ) {

                            return;

                        }


                        addQuantityByUnit(
                            deliveryAllocatedQuantityByUnit,
                            detail.unit,
                            detail.allocation
                                .allocatedQuantity
                        );


                        addQuantityByUnit(
                            deliveryUnallocatedQuantityByUnit,
                            detail.unit,
                            detail.allocation
                                .unallocatedQuantity
                        );


                        addQuantityByUnit(
                            deliveryOverAllocatedQuantityByUnit,
                            detail.unit,
                            detail.allocation
                                .overAllocatedQuantity
                        );

                    }
                );

            }
        );


        const deliveryAllocatedQuantity =
            Array.from(
                deliveryAllocatedQuantityByUnit.values()
            )
                .reduce(
                    (
                        total,
                        entry
                    ) =>
                        total +
                        toNumber(
                            entry.quantity
                        ),
                    0
                );


        const deliveryUnallocatedQuantity =
            Array.from(
                deliveryUnallocatedQuantityByUnit.values()
            )
                .reduce(
                    (
                        total,
                        entry
                    ) =>
                        total +
                        toNumber(
                            entry.quantity
                        ),
                    0
                );


        const deliveryOverAllocatedQuantity =
            Array.from(
                deliveryOverAllocatedQuantityByUnit.values()
            )
                .reduce(
                    (
                        total,
                        entry
                    ) =>
                        total +
                        toNumber(
                            entry.quantity
                        ),
                    0
                );


        // =================================================
        // QUANTITY BY UNIT
        // =================================================

        const quantityByUnitMap =
            new Map();


        items.forEach(
            item => {

                addQuantityByUnit(
                    quantityByUnitMap,
                    item.unit,
                    item.quantity
                );


            }
        );


        // =================================================
        // PROGRAM BREAKDOWN
        // =================================================

        if (
            delivery.program
        ) {

            const id =
                String(
                    delivery.program._id
                );


            if (
                !programMap.has(id)
            ) {

                programMap.set(
                    id,
                    {

                        id:
                            delivery.program._id,

                        programCode:
                            delivery.program.programCode,

                        name:
                            delivery.program.name,

                        deliveries:
                            0,

                        beneficiaries:
                            new Set(),

                        allocatedBeneficiaries:
                            new Set(),

                        totalItems:
                            0,

                        totalSupportValue:
                            0,

                        totalAllocatedValue:
                            0,

                        totalUnallocatedValue:
                            0

                    }
                );

            }


            const program =
                programMap.get(id);


            program.deliveries +=
                1;

            program.totalItems +=
                items.length;

            program.totalSupportValue +=
                toNumber(
                    delivery.totalAmount
                );

            program.totalAllocatedValue +=
                deliveryAllocatedValue;

            program.totalUnallocatedValue +=
                deliveryUnallocatedValue;


            deliveryBeneficiaryRecords.forEach(
                record => {

                    if (
                        record.beneficiary
                    ) {

                        program.beneficiaries.add(
                            String(
                                record.beneficiary._id
                            )
                        );

                    }


                    if (
                        record.beneficiary &&
                        Array.isArray(
                            record.allocations
                        ) &&
                        record.allocations.length > 0
                    ) {

                        program.allocatedBeneficiaries.add(
                            String(
                                record.beneficiary._id
                            )
                        );

                    }

                }
            );

        }


        // =================================================
        // PROJECT BREAKDOWN
        // =================================================

        if (
            delivery.project
        ) {

            const id =
                String(
                    delivery.project._id
                );


            if (
                !projectMap.has(id)
            ) {

                projectMap.set(
                    id,
                    {

                        id:
                            delivery.project._id,

                        projectCode:
                            delivery.project.projectCode,

                        name:
                            delivery.project.name,

                        deliveries:
                            0,

                        beneficiaries:
                            new Set(),

                        allocatedBeneficiaries:
                            new Set(),

                        totalItems:
                            0,

                        totalSupportValue:
                            0,

                        totalAllocatedValue:
                            0,

                        totalUnallocatedValue:
                            0

                    }
                );

            }


            const project =
                projectMap.get(id);


            project.deliveries +=
                1;

            project.totalItems +=
                items.length;

            project.totalSupportValue +=
                toNumber(
                    delivery.totalAmount
                );

            project.totalAllocatedValue +=
                deliveryAllocatedValue;

            project.totalUnallocatedValue +=
                deliveryUnallocatedValue;


            deliveryBeneficiaryRecords.forEach(
                record => {

                    if (
                        record.beneficiary
                    ) {

                        project.beneficiaries.add(
                            String(
                                record.beneficiary._id
                            )
                        );

                    }


                    if (
                        record.beneficiary &&
                        Array.isArray(
                            record.allocations
                        ) &&
                        record.allocations.length > 0
                    ) {

                        project.allocatedBeneficiaries.add(
                            String(
                                record.beneficiary._id
                            )
                        );

                    }

                }
            );

        }


        // =================================================
        // ACTIVITY BREAKDOWN
        // =================================================

        if (
            delivery.activity
        ) {

            const id =
                String(
                    delivery.activity._id
                );


            if (
                !activityMap.has(id)
            ) {

                activityMap.set(
                    id,
                    {

                        id:
                            delivery.activity._id,

                        activityCode:
                            delivery.activity.activityCode,

                        name:
                            delivery.activity.name,

                        activityType:
                            delivery.activity.activityType,

                        deliveries:
                            0,

                        beneficiaries:
                            new Set(),

                        allocatedBeneficiaries:
                            new Set(),

                        totalItems:
                            0,

                        totalSupportValue:
                            0,

                        totalAllocatedValue:
                            0,

                        totalUnallocatedValue:
                            0

                    }
                );

            }


            const activity =
                activityMap.get(id);


            activity.deliveries +=
                1;

            activity.totalItems +=
                items.length;

            activity.totalSupportValue +=
                toNumber(
                    delivery.totalAmount
                );

            activity.totalAllocatedValue +=
                deliveryAllocatedValue;

            activity.totalUnallocatedValue +=
                deliveryUnallocatedValue;


            deliveryBeneficiaryRecords.forEach(
                record => {

                    if (
                        record.beneficiary
                    ) {

                        activity.beneficiaries.add(
                            String(
                                record.beneficiary._id
                            )
                        );

                    }


                    if (
                        record.beneficiary &&
                        Array.isArray(
                            record.allocations
                        ) &&
                        record.allocations.length > 0
                    ) {

                        activity.allocatedBeneficiaries.add(
                            String(
                                record.beneficiary._id
                            )
                        );

                    }

                }
            );

        }


        // =================================================
        // SERVICE CATEGORY
        // =================================================

        items.forEach(
            item => {

                if (
                    !item.serviceCategory
                ) {

                    return;

                }


                const id =
                    String(
                        item.serviceCategory.id
                    );


                if (
                    !categoryMap.has(id)
                ) {

                    categoryMap.set(
                        id,
                        {

                            id:
                                item.serviceCategory.id,

                            name:
                                item.serviceCategory.name,

                            value:
                                item.serviceCategory.value,

                            code:
                                item.serviceCategory.code,

                            quantity:
                                0,

                            valueTotal:
                                0,

                            allocatedValue:
                                0,

                            unallocatedValue:
                                0

                        }
                    );

                }


                const category =
                    categoryMap.get(id);


                category.quantity +=
                    toNumber(
                        item.quantity
                    );

                category.valueTotal +=
                    toNumber(
                        item.totalCost
                    );

                category.allocatedValue +=
                    toNumber(
                        item.allocation
                            .allocatedValue
                    );

                category.unallocatedValue +=
                    toNumber(
                        item.allocation
                            .unallocatedValue
                    );

            }
        );


        // =================================================
        // SERVICE TYPE
        // =================================================

        items.forEach(
            item => {

                if (
                    !item.serviceType
                ) {

                    return;

                }


                const id =
                    String(
                        item.serviceType.id
                    );


                if (
                    !serviceTypeMap.has(id)
                ) {

                    serviceTypeMap.set(
                        id,
                        {

                            id:
                                item.serviceType.id,

                            name:
                                item.serviceType.name,

                            value:
                                item.serviceType.value,

                            code:
                                item.serviceType.code,

                            quantity:
                                0,

                            valueTotal:
                                0,

                            allocatedValue:
                                0,

                            unallocatedValue:
                                0

                        }
                    );

                }


                const serviceType =
                    serviceTypeMap.get(id);


                serviceType.quantity +=
                    toNumber(
                        item.quantity
                    );

                serviceType.valueTotal +=
                    toNumber(
                        item.totalCost
                    );

                serviceType.allocatedValue +=
                    toNumber(
                        item.allocation
                            .allocatedValue
                    );

                serviceType.unallocatedValue +=
                    toNumber(
                        item.allocation
                            .unallocatedValue
                    );

            }
        );


        // =================================================
        // FUNDING SOURCE
        // =================================================

        if (
            delivery.fundingSource
        ) {

            const id =
                String(
                    delivery.fundingSource._id
                );


            if (
                !fundingMap.has(id)
            ) {

                fundingMap.set(
                    id,
                    {

                        id:
                            delivery.fundingSource._id,

                        name:
                            delivery.fundingSource.name,

                        value:
                            delivery.fundingSource.value,

                        code:
                            delivery.fundingSource.code,

                        deliveries:
                            0,

                        totalSupportValue:
                            0,

                        totalAllocatedValue:
                            0,

                        totalUnallocatedValue:
                            0

                    }
                );

            }


            const funding =
                fundingMap.get(id);


            funding.deliveries +=
                1;

            funding.totalSupportValue +=
                toNumber(
                    delivery.totalAmount
                );

            funding.totalAllocatedValue +=
                deliveryAllocatedValue;

            funding.totalUnallocatedValue +=
                deliveryUnallocatedValue;

        }


        // =================================================
        // MONTHLY
        // =================================================

        if (
            delivery.deliveryDate
        ) {

            const date =
                new Date(
                    delivery.deliveryDate
                );


            const key =
                `${date.getFullYear()}-${String(
                    date.getMonth() + 1
                ).padStart(
                    2,
                    "0"
                )}`;


            if (
                !monthlyMap.has(key)
            ) {

                monthlyMap.set(
                    key,
                    {

                        year:
                            date.getFullYear(),

                        month:
                            date.getMonth() + 1,

                        monthName:
                            getMonthName(
                                date
                            ),

                        deliveries:
                            0,

                        beneficiaries:
                            new Set(),

                        allocatedBeneficiaries:
                            new Set(),

                        totalItems:
                            0,

                        totalSupportValue:
                            0,

                        totalAllocatedValue:
                            0,

                        totalUnallocatedValue:
                            0

                    }
                );

            }


            const monthly =
                monthlyMap.get(key);


            monthly.deliveries +=
                1;

            monthly.totalItems +=
                items.length;

            monthly.totalSupportValue +=
                toNumber(
                    delivery.totalAmount
                );

            monthly.totalAllocatedValue +=
                deliveryAllocatedValue;

            monthly.totalUnallocatedValue +=
                deliveryUnallocatedValue;


            deliveryBeneficiaryRecords.forEach(
                record => {

                    if (
                        record.beneficiary
                    ) {

                        monthly.beneficiaries.add(
                            String(
                                record.beneficiary._id
                            )
                        );

                    }


                    if (
                        record.beneficiary &&
                        Array.isArray(
                            record.allocations
                        ) &&
                        record.allocations.length > 0
                    ) {

                        monthly.allocatedBeneficiaries.add(
                            String(
                                record.beneficiary._id
                            )
                        );

                    }

                }
            );

        }


        // =================================================
        // RECIPIENT
        // =================================================

        const recipientType =
            delivery.recipientType ||
            "Unknown";


        if (
            !recipientMap.has(
                recipientType
            )
        ) {

            recipientMap.set(
                recipientType,
                {

                    recipientType,

                    deliveries:
                        0,

                    beneficiaries:
                        new Set(),

                    allocatedBeneficiaries:
                        new Set(),

                    totalSupportValue:
                        0,

                    totalAllocatedValue:
                        0,

                    totalUnallocatedValue:
                        0

                }
            );

        }


        const recipient =
            recipientMap.get(
                recipientType
            );


        recipient.deliveries +=
            1;

        recipient.totalSupportValue +=
            toNumber(
                delivery.totalAmount
            );

        recipient.totalAllocatedValue +=
            deliveryAllocatedValue;

        recipient.totalUnallocatedValue +=
            deliveryUnallocatedValue;


        deliveryBeneficiaryRecords.forEach(
            record => {

                if (
                    record.beneficiary
                ) {

                    recipient.beneficiaries.add(
                        String(
                            record.beneficiary._id
                        )
                    );

                }


                if (
                    record.beneficiary &&
                    Array.isArray(
                        record.allocations
                    ) &&
                    record.allocations.length > 0
                ) {

                    recipient.allocatedBeneficiaries.add(
                        String(
                            record.beneficiary._id
                        )
                    );

                }

            }
        );


        // =================================================
        // GLOBAL TOTALS
        // =================================================

        totalAllocatedValue +=
            deliveryAllocatedValue;

        totalUnallocatedValue +=
            deliveryUnallocatedValue;

        totalOverAllocatedValue +=
            deliveryOverAllocatedValue;


        totalAllocatedQuantity +=
            deliveryAllocatedQuantity;

        totalUnallocatedQuantity +=
            deliveryUnallocatedQuantity;

        totalOverAllocatedQuantity +=
            deliveryOverAllocatedQuantity;


        // =================================================
        // DELIVERY ROW
        // =================================================

        rows.push({

            deliveryId:
                delivery._id,

            deliveryNumber:
                delivery.deliveryNumber,

            deliveryDate:
                delivery.deliveryDate,

            status:
                delivery.status,


            recipientType:
                delivery.recipientType ||
                null,

            recipientName:
                delivery.recipientName ||
                null,


            allocationMethod:
                delivery.allocationMethod ||
                null,


            beneficiary:
                delivery.beneficiary
                    ? {

                        id:
                            delivery.beneficiary._id,

                        beneficiaryNumber:
                            delivery.beneficiary
                                .beneficiaryNumber,

                        name:
                            getBeneficiaryName(
                                delivery.beneficiary
                            ),

                        gender:
                            delivery.beneficiary.gender

                    }
                    : null,


            beneficiaries,


            enrollment:
                delivery.enrollment
                    ? {

                        id:
                            delivery.enrollment._id,

                        enrollmentDate:
                            delivery.enrollment
                                .enrollmentDate,

                        status:
                            delivery.enrollment.status

                    }
                    : null,


            program:
                delivery.program
                    ? {

                        id:
                            delivery.program._id,

                        programCode:
                            delivery.program.programCode,

                        name:
                            delivery.program.name,

                        status:
                            delivery.program.status

                    }
                    : null,


            project:
                delivery.project
                    ? {

                        id:
                            delivery.project._id,

                        projectCode:
                            delivery.project.projectCode,

                        name:
                            delivery.project.name,

                        status:
                            delivery.project.status

                    }
                    : null,


            activity:
                delivery.activity
                    ? {

                        id:
                            delivery.activity._id,

                        activityCode:
                            delivery.activity.activityCode,

                        name:
                            delivery.activity.name,

                        activityType:
                            delivery.activity.activityType,

                        status:
                            delivery.activity.status

                    }
                    : null,


            activityRun:
                delivery.activityRun
                    ? {

                        id:
                            delivery.activityRun._id,

                        runCode:
                            delivery.activityRun.runCode,

                        name:
                            delivery.activityRun.name,

                        startDate:
                            delivery.activityRun.startDate,

                        endDate:
                            delivery.activityRun.endDate,

                        status:
                            delivery.activityRun.status

                    }
                    : null,


            fundingSource:
                delivery.fundingSource
                    ? {

                        id:
                            delivery.fundingSource._id,

                        name:
                            delivery.fundingSource.name,

                        value:
                            delivery.fundingSource.value,

                        code:
                            delivery.fundingSource.code

                    }
                    : null,


            deliveryLocation:
                delivery.deliveryLocation,


            items,


            totalItems:
                items.length,

            totalQuantity,


            quantityByUnit:
                convertQuantityMap(
                    quantityByUnitMap
                ),


            allocatedQuantityByUnit:
                convertQuantityMap(
                    deliveryAllocatedQuantityByUnit
                ),


            unallocatedQuantityByUnit:
                convertQuantityMap(
                    deliveryUnallocatedQuantityByUnit
                ),


            overAllocatedQuantityByUnit:
                convertQuantityMap(
                    deliveryOverAllocatedQuantityByUnit
                ),


            totalItemValue,


            totalAmount:
                toNumber(
                    delivery.totalAmount
                ),


            allocationSummary: {

                allocatedValue:
                    deliveryAllocatedValue,

                unallocatedValue:
                    deliveryUnallocatedValue,

                overAllocatedValue:
                    deliveryOverAllocatedValue,

                allocatedQuantity:
                    deliveryAllocatedQuantity,

                unallocatedQuantity:
                    deliveryUnallocatedQuantity,

                overAllocatedQuantity:
                    deliveryOverAllocatedQuantity,

                beneficiaryCount:
                    deliveryBeneficiaryRecords.length,

                beneficiariesWithAllocations:
                    deliveryBeneficiaryRecords.filter(
                        record =>
                            Array.isArray(
                                record?.allocations
                            ) &&
                            record.allocations.length > 0
                    ).length

            }

        });

    }


    // =================================================
    // CONVERT MAPS
    // =================================================

    const programs =
        Array.from(
            programMap.values()
        )
            .map(
                item => ({

                    ...item,

                    beneficiaries:
                        item.beneficiaries.size,

                    allocatedBeneficiaries:
                        item.allocatedBeneficiaries.size

                })
            );


    const projects =
        Array.from(
            projectMap.values()
        )
            .map(
                item => ({

                    ...item,

                    beneficiaries:
                        item.beneficiaries.size,

                    allocatedBeneficiaries:
                        item.allocatedBeneficiaries.size

                })
            );


    const activities =
        Array.from(
            activityMap.values()
        )
            .map(
                item => ({

                    ...item,

                    beneficiaries:
                        item.beneficiaries.size,

                    allocatedBeneficiaries:
                        item.allocatedBeneficiaries.size

                })
            );


    const monthly =
        Array.from(
            monthlyMap.values()
        )
            .map(
                item => ({

                    ...item,

                    beneficiaries:
                        item.beneficiaries.size,

                    allocatedBeneficiaries:
                        item.allocatedBeneficiaries.size

                })
            )
            .sort(
                (
                    a,
                    b
                ) =>
                    (
                        a.year * 100 +
                        a.month
                    ) -
                    (
                        b.year * 100 +
                        b.month
                    )
            );


    const recipients =
        Array.from(
            recipientMap.values()
        )
            .map(
                item => ({

                    ...item,

                    beneficiaries:
                        item.beneficiaries.size,

                    allocatedBeneficiaries:
                        item.allocatedBeneficiaries.size

                })
            );


    // =================================================
    // GLOBAL ITEM COUNT
    // =================================================

    const totalItems =
        deliveries.reduce(
            (
                total,
                delivery
            ) =>
                total +
                (
                    Array.isArray(
                        delivery.items
                    )
                        ? delivery.items.length
                        : 0
                ),
            0
        );


    // =================================================
    // GLOBAL SUPPORT VALUE
    // =================================================

    const totalSupportValue =
        deliveries.reduce(
            (
                total,
                delivery
            ) =>
                total +
                toNumber(
                    delivery.totalAmount
                ),
            0
        );


    // =================================================
    // AVERAGE DELIVERY VALUE
    // =================================================

    const averageDeliveryValue =
        deliveries.length > 0
            ? totalSupportValue /
              deliveries.length
            : 0;


    // =================================================
    // GLOBAL QUANTITY MAPS
    // =================================================

    const globalQuantityByUnitMap =
        new Map();


    const globalAllocatedQuantityByUnitMap =
        new Map();


    const globalUnallocatedQuantityByUnitMap =
        new Map();


    const globalOverAllocatedQuantityByUnitMap =
        new Map();


    // =================================================
    // BUILD GLOBAL QUANTITIES FROM REPORT ROWS
    // =================================================

    rows.forEach(
        row => {

            row.items.forEach(
                item => {

                    addQuantityByUnit(
                        globalQuantityByUnitMap,
                        item.unit,
                        item.quantity
                    );


                    const behavior =
                        item.allocationBehavior;


                    if (
                        behavior !==
                        "CONSUMPTION"
                    ) {

                        return;

                    }


                    addQuantityByUnit(
                        globalAllocatedQuantityByUnitMap,
                        item.unit,
                        item.allocation
                            .allocatedQuantity
                    );


                    addQuantityByUnit(
                        globalUnallocatedQuantityByUnitMap,
                        item.unit,
                        item.allocation
                            .unallocatedQuantity
                    );


                    addQuantityByUnit(
                        globalOverAllocatedQuantityByUnitMap,
                        item.unit,
                        item.allocation
                            .overAllocatedQuantity
                    );


                    // =====================================
                    // DIFFERENT-UNIT DETAILS
                    // =====================================

                    item.detailItems.forEach(
                        detail => {

                            const parentUnitKey =
                                getUnitKey(
                                    item.unit
                                );

                            const detailUnitKey =
                                getUnitKey(
                                    detail.unit
                                );


                            if (
                                parentUnitKey &&
                                detailUnitKey &&
                                parentUnitKey ===
                                detailUnitKey
                            ) {

                                return;

                            }


                            addQuantityByUnit(
                                globalAllocatedQuantityByUnitMap,
                                detail.unit,
                                detail.allocation
                                    .allocatedQuantity
                            );


                            addQuantityByUnit(
                                globalUnallocatedQuantityByUnitMap,
                                detail.unit,
                                detail.allocation
                                    .unallocatedQuantity
                            );


                            addQuantityByUnit(
                                globalOverAllocatedQuantityByUnitMap,
                                detail.unit,
                                detail.allocation
                                    .overAllocatedQuantity
                            );

                        }
                    );

                }
            );

        }
    );


    // =================================================
    // FINAL REPORT
    // =================================================

    return {

        report:
            "serviceDeliveryReport",

        reportTitle:
            "Service Delivery Report",

        generatedAt:
            new Date(),


        // =================================================
        // PERIOD
        // =================================================

        period: {

            startDate:
                filters.startDate ||
                null,

            endDate:
                filters.endDate ||
                null,

            year:
                filters.year ||
                null,

            period:
                filters.period ||
                null,

            month:
                filters.month ||
                null,

            quarter:
                filters.quarter ||
                null,

            half:
                filters.half ||
                null

        },


        // =================================================
        // FILTERS
        // =================================================

        filters: {

            program:
                filters.program ||
                null,

            project:
                filters.project ||
                null,

            activity:
                filters.activity ||
                null,

            activityRun:
                filters.activityRun ||
                null,

            beneficiary:
                filters.beneficiary ||
                null,

            enrollment:
                filters.enrollment ||
                null,

            fundingSource:
                filters.fundingSource ||
                null,

            recipientType:
                filters.recipientType ||
                null,

            allocationMethod:
                filters.allocationMethod ||
                null,

            status:
                filters.status ||
                "Delivered"

        },


        // =================================================
        // SUMMARY
        // =================================================

        summary: {

            totalDeliveries:
                deliveries.length,

            totalBeneficiaries:
                beneficiarySet.size,

            beneficiariesWithAllocations:
                allocatedBeneficiarySet.size,

            totalPrograms:
                programMap.size,

            totalProjects:
                projectMap.size,

            totalActivities:
                activityMap.size,

            totalItems,


            // =============================================
            // DELIVERED QUANTITY
            // =============================================

            quantityByUnit:
                convertQuantityMapToObject(
                    globalQuantityByUnitMap
                ),


            // =============================================
            // SUPPORT VALUE
            // =============================================

            totalSupportValue,


            // =============================================
            // VALUE ALLOCATION
            // =============================================

            totalAllocatedValue,

            totalUnallocatedValue,

            totalOverAllocatedValue,


            // =============================================
            // QUANTITY ALLOCATION
            // =============================================

            allocatedQuantityByUnit:
                convertQuantityMapToObject(
                    globalAllocatedQuantityByUnitMap
                ),

            unallocatedQuantityByUnit:
                convertQuantityMapToObject(
                    globalUnallocatedQuantityByUnitMap
                ),

            overAllocatedQuantityByUnit:
                convertQuantityMapToObject(
                    globalOverAllocatedQuantityByUnitMap
                ),


            // =============================================
            // RAW QUANTITY TOTALS
            // =============================================

            totalAllocatedQuantity,

            totalUnallocatedQuantity,

            totalOverAllocatedQuantity,


            // =============================================
            // ALLOCATION RATE
            // =============================================

            allocationRate:
                totalSupportValue > 0
                    ? (
                        totalAllocatedValue /
                        totalSupportValue
                    ) * 100
                    : 0,


            // =============================================
            // AVERAGE DELIVERY VALUE
            // =============================================

            averageDeliveryValue

        },


        // =================================================
        // BREAKDOWNS
        // =================================================

        monthly,

        programs,

        projects,

        activities,


        serviceCategories:
            Array.from(
                categoryMap.values()
            ),


        serviceTypes:
            Array.from(
                serviceTypeMap.values()
            ),


        fundingSources:
            Array.from(
                fundingMap.values()
            ),


        recipients,


        // =================================================
        // DELIVERY DATA
        // =================================================

        data:
            rows

    };

};


module.exports = {

    generate

};