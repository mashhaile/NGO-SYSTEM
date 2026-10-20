import React, {
    useMemo
} from "react";

import {
    Box,
    Chip,
    Divider,
    Grid,
    Paper,
    Stack,
    Typography
} from "@mui/material";

import {
    formatDate,
    formatNumber,
    formatCurrency,
    formatValue,
    getLookupDisplayValue,
    ProgramDisplay,
    ProjectDisplay,
    ActivityDisplay,
    ActivityRunDisplay,
    EmptyState,
    StatusValue
} from "../reportDisplayUtils";


// =====================================================
// HELPERS
// =====================================================

const getRows = (report) => {

    if (Array.isArray(report?.data)) {
        return report.data;
    }

    if (Array.isArray(report?.details)) {
        return report.details;
    }

    return [];
};


const getId = (value) => {

    if (!value) {
        return null;
    }

    if (
        typeof value === "string" ||
        typeof value === "number"
    ) {
        return String(value);
    }

    return String(
        value?._id ||
        value?.id ||
        value?.value ||
        ""
    );
};


const getBeneficiaryName = (
    beneficiary
) => {

    if (!beneficiary) {
        return "—";
    }

    if (typeof beneficiary === "string") {
        return beneficiary;
    }

    return (
        beneficiary.name ||
        beneficiary.fullName ||
        [
            beneficiary.firstName,
            beneficiary.middleName,
            beneficiary.lastName
        ]
            .filter(Boolean)
            .join(" ") ||
        beneficiary.beneficiaryNumber ||
        beneficiary.code ||
        "—"
    );
};


const getBeneficiaryNumber = (
    beneficiary
) => {

    if (!beneficiary || typeof beneficiary === "string") {
        return "—";
    }

    return (
        beneficiary.beneficiaryNumber ||
        beneficiary.code ||
        beneficiary.beneficiaryCode ||
        "—"
    );
};


const getUnitName = (unit) => {

    if (!unit) {
        return "—";
    }

    if (typeof unit === "string") {
        return unit;
    }

    return (
        unit.value ||
        unit.name ||
        unit.label ||
        unit.code ||
        "—"
    );
};


const isMonetaryUnit = (unit) => {

    const value =
        String(
            getUnitName(unit)
        )
            .trim()
            .toLowerCase();

    return [
        "amount",
        "money",
        "cash",
        "etb",
        "birr",
        "financial",
        "currency"
    ].includes(value);
};


const formatQuantity = (
    quantity,
    unit
) => {

    if (
        quantity === null ||
        quantity === undefined ||
        quantity === ""
    ) {
        return "—";
    }

    const numeric =
        Number(quantity);

    if (Number.isNaN(numeric)) {
        return "—";
    }

    const unitName =
        getUnitName(unit);

    if (
        !unitName ||
        unitName === "—"
    ) {
        return formatNumber(numeric);
    }

    return `${formatNumber(
        numeric
    )} ${unitName}`;
};


const getAllocationStatus = ({
    actual,
    allocated,
    overAllocated = 0
}) => {

    const actualValue =
        Number(actual) || 0;

    const allocatedValue =
        Number(allocated) || 0;

    const overValue =
        Number(overAllocated) || 0;

    if (overValue > 0) {
        return "Over Allocated";
    }

    if (allocatedValue <= 0) {
        return "Not Allocated";
    }

    if (allocatedValue >= actualValue) {
        return "Fully Allocated";
    }

    return "Partially Allocated";
};


// =====================================================
// SMALL UI COMPONENTS
// =====================================================

const MetricCard = ({
    label,
    value,
    emphasized = false
}) => {

    return (
        <Paper
            variant="outlined"
            sx={{
                p: 2,
                height: "100%",
                borderRadius: 2,
                backgroundColor:
                    "background.paper"
            }}
        >

            <Typography
                variant="caption"
                sx={{
                    color: "text.secondary",
                    display: "block",
                    mb: 0.5,
                    fontWeight: 600
                }}>
                {label}
            </Typography>

            <Typography
                variant={
                    emphasized
                        ? "h6"
                        : "body1"
                }
                sx={{
                    fontWeight: 700,
                    lineHeight: 1.3,

                    wordBreak:
                        "break-word"
                }}>
                {value}
            </Typography>

        </Paper>
    );
};


const InfoItem = ({
    label,
    value,
    children
}) => {

    return (
        <Box>

            <Typography
                variant="caption"
                sx={{
                    color: "text.secondary",
                    display: "block",
                    mb: 0.35,
                    fontWeight: 600
                }}>
                {label}
            </Typography>

            {children !== undefined ? (
                children
            ) : (
                <Typography
                    variant="body2"
                    sx={{
                        fontWeight: 500,

                        wordBreak:
                            "break-word"
                    }}>
                    {formatValue(value)}
                </Typography>
            )}

        </Box>
    );
};


// =====================================================
// SUPPORTING ITEMS
// =====================================================

const SupportingItems = ({
    items = []
}) => {

    if (
        !Array.isArray(items) ||
        items.length === 0
    ) {
        return null;
    }

    return (
        <Box sx={{ mt: 2.25 }}>

            <Typography
                variant="subtitle2"
                sx={{
                    fontWeight: 700,
                    mb: 1
                }}>
                Supporting Items
            </Typography>

            <Stack spacing={0.75}>

                {items.map(
                    (
                        detail,
                        index
                    ) => {

                        const name =
                            detail?.name ||
                            detail?.itemName ||
                            detail?.description ||
                            "Supporting Item";

                        const quantity =
                            Number(
                                detail?.quantity
                            ) || 0;

                        const unit =
                            detail?.unit;

                        const unitCost =
                            Number(
                                detail?.unitCost
                            ) || 0;

                        const total =
                            detail?.totalCost !==
                                undefined &&
                            detail?.totalCost !==
                                null
                                ? Number(
                                    detail.totalCost
                                ) || 0
                                : quantity *
                                  unitCost;

                        return (
                            <Box
                                key={
                                    detail?._id ||
                                    detail?.id ||
                                    index
                                }
                                sx={{
                                    display: "flex",
                                    flexWrap: "wrap",
                                    alignItems: {
                                        xs: "flex-start",
                                        sm: "center"
                                    },
                                    gap: {
                                        xs: 1,
                                        sm: 2
                                    },
                                    px: 1.5,
                                    py: 1.15,
                                    borderRadius: 1.5,
                                    backgroundColor:
                                        "action.hover"
                                }}
                            >

                                <Box
                                    sx={{
                                        flex: 1,
                                        minWidth:
                                            {
                                                xs: "100%",
                                                sm: 180
                                            }
                                    }}
                                >
                                    <Typography
                                        variant="body2"
                                        sx={{
                                            fontWeight: 600
                                        }}
                                    >
                                        {name}
                                    </Typography>

                                    {detail?.remarks ? (
                                        <Typography
                                            variant="caption"
                                            sx={{
                                                color: "text.secondary"
                                            }}
                                        >
                                            {formatValue(
                                                detail.remarks
                                            )}
                                        </Typography>
                                    ) : null}
                                </Box>

                                <Box
                                    sx={{
                                        minWidth: {
                                            xs: 80,
                                            sm: 70
                                        }
                                    }}
                                >
                                    <Typography
                                        variant="caption"
                                        sx={{
                                            color: "text.secondary",
                                            display: "block"
                                        }}>
                                        Quantity
                                    </Typography>

                                    <Typography
                                        variant="body2"
                                        sx={{
                                            fontWeight: 600
                                        }}
                                    >
                                        {formatNumber(
                                            quantity
                                        )}
                                    </Typography>
                                </Box>

                                <Box
                                    sx={{
                                        minWidth: {
                                            xs: 80,
                                            sm: 80
                                        }
                                    }}
                                >
                                    <Typography
                                        variant="caption"
                                        sx={{
                                            color: "text.secondary",
                                            display: "block"
                                        }}>
                                        Unit
                                    </Typography>

                                    <Typography
                                        variant="body2"
                                        sx={{
                                            fontWeight: 600
                                        }}
                                    >
                                        {getUnitName(
                                            unit
                                        )}
                                    </Typography>
                                </Box>

                                <Box
                                    sx={{
                                        minWidth: {
                                            xs: 120,
                                            sm: 130
                                        },
                                        textAlign: {
                                            xs: "left",
                                            sm: "right"
                                        }
                                    }}
                                >
                                    <Typography
                                        variant="caption"
                                        sx={{
                                            color: "text.secondary",
                                            display: "block"
                                        }}>
                                        Total
                                    </Typography>

                                    <Typography
                                        variant="body2"
                                        sx={{
                                            fontWeight: 700
                                        }}
                                    >
                                        {formatCurrency(
                                            total
                                        )}
                                    </Typography>
                                </Box>

                            </Box>
                        );
                    }
                )}

            </Stack>

        </Box>
    );
};


// =====================================================
// BENEFICIARY ALLOCATION INDEX
// =====================================================

const buildBeneficiaryIndex = (
    items
) => {

    const map = new Map();

    if (!Array.isArray(items)) {
        return map;
    }

    items.forEach(
        (item) => {

            const allocations =
                Array.isArray(
                    item
                        ?.allocation
                        ?.beneficiaries
                )
                    ? item
                        .allocation
                        .beneficiaries
                    : [];

            allocations.forEach(
                (allocation) => {

                    const beneficiary =
                        allocation?.beneficiary;

                    const beneficiaryId =
                        getId(
                            beneficiary
                        );

                    if (!beneficiaryId) {
                        return;
                    }

                    if (
                        !map.has(
                            beneficiaryId
                        )
                    ) {
                        map.set(
                            beneficiaryId,
                            {
                                beneficiary,
                                allocations: []
                            }
                        );
                    }

                    map.get(
                        beneficiaryId
                    )
                        .allocations
                        .push({
                            item,
                            allocation
                        });

                }
            );

        }
    );

    return map;
};


// =====================================================
// BENEFICIARY ALLOCATION ENTRY
// =====================================================

const BeneficiaryAllocationEntry = ({
    item,
    allocation
}) => {

    const detailItem =
        allocation?.detailItem;

    const itemName =
        detailItem?.name ||
        detailItem?.itemName ||
        detailItem?.description ||
        "Service Item";

    const serviceType =
        getLookupDisplayValue(
            item?.serviceType
        );

    const serviceCategory =
        getLookupDisplayValue(
            item?.serviceCategory
        );

    const serviceName =
        serviceType !== "—"
            ? serviceType
            : serviceCategory;

    const quantity =
        Number(
            allocation?.quantity
        ) || 0;

    const unit =
        detailItem?.unit ||
        item?.unit;

    const allocatedValue =
        Number(
            allocation?.allocatedValue
        ) || 0;

    return (
        <Box
            sx={{
                px: {
                    xs: 1.5,
                    sm: 2
                },
                py: 1.25,
                borderRadius: 1.5,
                border: "1px solid",
                borderColor: "divider",
                backgroundColor:
                    "background.paper"
            }}
        >

            <Stack sx={{ alignItems: {
                    xs: "stretch",
                    sm: "center"
                } }}
                direction={{
                    xs: "column",
                    sm: "row"
                }}
                spacing={{
                    xs: 1,
                    sm: 2
                }}
            >

                {/* SERVICE + ITEM */}

                <Box
                    sx={{
                        flex: 1,
                        minWidth: 0
                    }}
                >

                    <Typography
                        variant="caption"
                        sx={{
                            color: "text.secondary",
                            display: "block",
                            lineHeight: 1.3,
                            mb: 0.25
                        }}>
                        {serviceName}
                    </Typography>

                    <Typography
                        variant="body2"
                        sx={{
                            fontWeight: 700,
                            lineHeight: 1.35,

                            wordBreak:
                                "break-word"
                        }}>
                        {itemName}
                    </Typography>

                </Box>


                {/* QUANTITY */}

                <Box
                    sx={{
                        minWidth: {
                            xs: "auto",
                            sm: 110
                        }
                    }}
                >

                    <Typography
                        variant="caption"
                        sx={{
                            color: "text.secondary",

                            display: {
                                xs: "inline",
                                sm: "block"
                            },

                            mr: {
                                xs: 0.75,
                                sm: 0
                            }
                        }}>
                        Quantity
                    </Typography>

                    <Typography
                        variant="body2"
                        sx={{
                            fontWeight: 600,

                            display: {
                                xs: "inline",
                                sm: "block"
                            },

                            whiteSpace:
                                "nowrap"
                        }}>
                        {formatQuantity(
                            quantity,
                            unit
                        )}
                    </Typography>

                </Box>


                {/* ALLOCATED VALUE */}

                <Box
                    sx={{
                        minWidth: {
                            xs: "auto",
                            sm: 145
                        },
                        textAlign: {
                            xs: "left",
                            sm: "right"
                        }
                    }}
                >

                    <Typography
                        variant="caption"
                        sx={{
                            color: "text.secondary",

                            display: {
                                xs: "inline",
                                sm: "block"
                            },

                            mr: {
                                xs: 0.75,
                                sm: 0
                            }
                        }}>
                        Allocated
                    </Typography>

                    <Typography
                        variant="body2"
                        sx={{
                            fontWeight: 800,

                            display: {
                                xs: "inline",
                                sm: "block"
                            },

                            whiteSpace:
                                "nowrap"
                        }}>
                        {formatCurrency(
                            allocatedValue
                        )}
                    </Typography>

                </Box>

            </Stack>

            {/* OPTIONAL REMARKS */}

            {allocation?.remarks ? (

                <Typography
                    variant="caption"
                    sx={{
                        color: "text.secondary",
                        display: "block",
                        mt: 1,
                        pt: 0.75,
                        borderTop: "1px solid",

                        borderColor:
                            "divider",

                        lineHeight: 1.4
                    }}>
                    {formatValue(
                        allocation.remarks
                    )}
                </Typography>

            ) : null}

        </Box>
    );
};

// =====================================================
// BENEFICIARY CARD
// =====================================================

const BeneficiaryCard = ({
    beneficiary,
    allocations
}) => {

    const totalAllocated =
        allocations.reduce(
            (
                total,
                entry
            ) =>
                total +
                (
                    Number(
                        entry
                            ?.allocation
                            ?.allocatedValue
                    ) || 0
                ),
            0
        );

    return (
        <Paper
            variant="outlined"
            sx={{
                borderRadius: 2,
                overflow: "hidden"
            }}
        >

            {/* BENEFICIARY HEADER */}

            <Box
                sx={{
                    px: 2,
                    py: 1.75
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
                    spacing={1.5}
                >

                    <Box>

                        <Typography
                            variant="subtitle1"
                            sx={{
                                fontWeight: 700
                            }}
                        >
                            {getBeneficiaryName(
                                beneficiary
                            )}
                        </Typography>

                        <Typography
                            variant="body2"
                            sx={{
                                color: "text.secondary"
                            }}
                        >
                            {getBeneficiaryNumber(
                                beneficiary
                            )}
                        </Typography>

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
                            variant="caption"
                            sx={{
                                color: "text.secondary",
                                display: "block"
                            }}>
                            Total Allocated
                        </Typography>

                        <Typography
                            variant="h6"
                            sx={{
                                fontWeight: 700
                            }}
                        >
                            {formatCurrency(
                                totalAllocated
                            )}
                        </Typography>

                    </Box>

                </Stack>

            </Box>

            <Divider />

            {/* ALLOCATIONS */}

            <Box
                sx={{
                    p: 1.5
                }}
            >

                <Stack spacing={1}>

                    {allocations.map(
                        (
                            entry,
                            index
                        ) => (

                            <BeneficiaryAllocationEntry
                                key={
                                    entry
                                        ?.allocation
                                        ?._id ||
                                    entry
                                        ?.allocation
                                        ?.id ||
                                    `${getId(
                                        entry?.item
                                    )}-${index}`
                                }
                                item={
                                    entry.item
                                }
                                allocation={
                                    entry.allocation
                                }
                            />

                        )
                    )}

                </Stack>

            </Box>

        </Paper>
    );
};


// =====================================================
// SERVICE ITEM CARD
// =====================================================

const ServiceItemCard = ({
    item
}) => {

    const allocation =
        item?.allocation || {};

    const actual =
        Number(
            item?.totalCost
        ) || 0;

    const allocated =
        Number(
            allocation
                ?.allocatedValue
        ) || 0;

    const unallocated =
        allocation
            ?.unallocatedValue !==
            undefined &&
        allocation
            ?.unallocatedValue !==
            null
            ? Number(
                allocation
                    .unallocatedValue
            ) || 0
            : Math.max(
                actual -
                allocated,
                0
            );

    const overAllocated =
        Number(
            allocation
                ?.overAllocatedValue
        ) || 0;

    const status =
        getAllocationStatus({
            actual,
            allocated,
            overAllocated
        });

    const quantity =
        Number(
            item?.quantity
        ) || 0;

    const unit =
        item?.unit;

    const detailItems =
        Array.isArray(
            item?.detailItems
        )
            ? item.detailItems
            : [];


    return (
        <Paper
            variant="outlined"
            sx={{
                borderRadius: 2,
                overflow: "hidden"
            }}
        >

            {/* SERVICE HEADER */}

            <Box
                sx={{
                    px: 2,
                    py: 1.75,
                    backgroundColor:
                        "background.default"
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
                    spacing={1}
                >

                    <Box>

                        <Typography
                            variant="subtitle1"
                            sx={{
                                fontWeight: 700
                            }}
                        >
                            {
                                getLookupDisplayValue(
                                    item?.serviceType
                                ) !== "—"
                                    ? getLookupDisplayValue(
                                        item?.serviceType
                                    )
                                    : "Service Item"
                            }
                        </Typography>

                        <Typography
                            variant="body2"
                            sx={{
                                color: "text.secondary"
                            }}
                        >
                            {
                                getLookupDisplayValue(
                                    item?.serviceCategory
                                )
                            }
                        </Typography>

                    </Box>


                    <StatusValue
                        value={status}
                    />

                </Stack>

            </Box>

            <Divider />

            {/* FINANCIAL SUMMARY */}

            <Box sx={{ p: 2 }}>

                <Grid
                    container
                    spacing={1.25}
                >

                    {!isMonetaryUnit(unit) ? (

                        <Grid
                            size={{ xs: 12, sm: 6, md: 3 }}
                        >

                            <MetricCard
                                label="Delivered Quantity"
                                value={formatQuantity(
                                    quantity,
                                    unit
                                )}
                            />

                        </Grid>

                    ) : null}


                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}
                    >

                        <MetricCard
                            label="Actual Value"
                            value={formatCurrency(
                                actual
                            )}
                            emphasized
                        />

                    </Grid>


                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}
                    >

                        <MetricCard
                            label="Allocated Value"
                            value={formatCurrency(
                                allocated
                            )}
                        />

                    </Grid>


                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}
                    >

                        <MetricCard
                            label="Unallocated Value"
                            value={formatCurrency(
                                unallocated
                            )}
                        />

                    </Grid>


                    {overAllocated > 0 ? (

                        <Grid
                            size={{ xs: 12, sm: 6, md: 3 }}
                        >

                            <MetricCard
                                label="Over Allocated Value"
                                value={formatCurrency(
                                    overAllocated
                                )}
                            />

                        </Grid>

                    ) : null}


                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}
                    >

                        <MetricCard
                            label="Unit Cost"
                            value={formatCurrency(
                                item?.unitCost
                            )}
                        />

                    </Grid>

                </Grid>


                {item?.remarks ? (

                    <Box
                        sx={{
                            mt: 1.75,
                            px: 1.5,
                            py: 1.25,
                            borderRadius: 1.5,
                            backgroundColor:
                                "action.hover"
                        }}
                    >

                        <Typography
                            variant="caption"
                            sx={{
                                color: "text.secondary",
                                display: "block",
                                fontWeight: 600
                            }}>
                            Remarks
                        </Typography>

                        <Typography
                            variant="body2"
                        >
                            {formatValue(
                                item.remarks
                            )}
                        </Typography>

                    </Box>

                ) : null}


                <SupportingItems
                    items={
                        detailItems
                    }
                />

            </Box>

        </Paper>
    );
};


// =====================================================
// DELIVERY CARD
// =====================================================

const ServiceDeliveryCard = ({
    delivery
}) => {

    const items =
        Array.isArray(
            delivery?.items
        )
            ? delivery.items
            : [];

    const beneficiaryIndex =
        useMemo(
            () =>
                buildBeneficiaryIndex(
                    items
                ),
            [items]
        );

    const beneficiaries =
        Array.from(
            beneficiaryIndex.values()
        );


    return (
        <Paper
            variant="outlined"
            sx={{
                borderRadius: 2,
                overflow: "hidden"
            }}
        >

            {/* DELIVERY HEADER */}

            <Box
                sx={{
                    px: 2.5,
                    py: 2,
                    backgroundColor:
                        "background.default"
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
                    spacing={1.5}
                >

                    <Box>

                        <Typography
                            variant="h6"
                            sx={{
                                fontWeight: 700
                            }}
                        >
                            {
                                delivery
                                    ?.deliveryNumber ||
                                "Service Delivery"
                            }
                        </Typography>

                        <Typography
                            variant="body2"
                            sx={{
                                color: "text.secondary"
                            }}
                        >
                            {formatDate(
                                delivery
                                    ?.deliveryDate
                            )}
                        </Typography>

                    </Box>


                    <StatusValue
                        value={
                            delivery?.status
                        }
                    />

                </Stack>

            </Box>

            <Divider />

            {/* DELIVERY OVERVIEW */}

            <Box sx={{ p: 2.5 }}>

                <Typography
                    variant="subtitle1"
                    sx={{
                        fontWeight: 700,
                        mb: 1.75
                    }}>
                    Delivery Overview
                </Typography>


                <Grid
                    container
                    spacing={2}
                >

                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}>
                        <InfoItem
                            label="Delivery No."
                            value={
                                delivery
                                    ?.deliveryNumber
                            }
                        />
                    </Grid>

                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}>
                        <InfoItem
                            label="Delivery Date"
                            value={formatDate(
                                delivery
                                    ?.deliveryDate
                            )}
                        />
                    </Grid>

                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}>
                        <InfoItem label="Program">
                            <ProgramDisplay
                                program={
                                    delivery
                                        ?.program
                                }
                            />
                        </InfoItem>
                    </Grid>

                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}>
                        <InfoItem label="Project">
                            <ProjectDisplay
                                project={
                                    delivery
                                        ?.project
                                }
                            />
                        </InfoItem>
                    </Grid>

                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}>
                        <InfoItem label="Activity">
                            <ActivityDisplay
                                activity={
                                    delivery
                                        ?.activity
                                }
                            />
                        </InfoItem>
                    </Grid>

                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}>
                        <InfoItem label="Activity Run">
                            <ActivityRunDisplay
                                activityRun={
                                    delivery
                                        ?.activityRun
                                }
                            />
                        </InfoItem>
                    </Grid>

                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}>
                        <InfoItem
                            label="Funding Source"
                            value={
                                getLookupDisplayValue(
                                    delivery
                                        ?.fundingSource
                                )
                            }
                        />
                    </Grid>

                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}>
                        <InfoItem
                            label="Location"
                            value={
                                delivery
                                    ?.deliveryLocation
                            }
                        />
                    </Grid>

                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}>
                        <InfoItem
                            label="Recipient Type"
                            value={
                                delivery
                                    ?.recipientType
                            }
                        />
                    </Grid>

                    {delivery?.recipientName ? (
                        <Grid
                            size={{ xs: 12, sm: 6, md: 3 }}>
                            <InfoItem
                                label="Recipient Name"
                                value={
                                    delivery
                                        .recipientName
                                }
                            />
                        </Grid>
                    ) : null}

                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}>
                        <InfoItem
                            label="Allocation Method"
                            value={
                                delivery
                                    ?.allocationMethod
                            }
                        />
                    </Grid>

                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}>
                        <InfoItem
                            label="Beneficiaries"
                            value={
                                beneficiaries.length
                            }
                        />
                    </Grid>

                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}>
                        <InfoItem
                            label="Service Items"
                            value={
                                items.length
                            }
                        />
                    </Grid>

                </Grid>

            </Box>

            <Divider />

            {/* SERVICES */}

            <Box sx={{ p: 2.5 }}>

                <Typography
                    variant="subtitle1"
                    sx={{
                        fontWeight: 700,
                        mb: 0.25
                    }}>
                    Services Delivered
                </Typography>

                <Typography
                    variant="body2"
                    sx={{
                        color: "text.secondary",
                        mb: 1.75
                    }}>
                    Service items, supporting items and allocation status.
                </Typography>


                {items.length > 0 ? (

                    <Stack spacing={1.75}>

                        {items.map(
                            (
                                item,
                                index
                            ) => (

                                <ServiceItemCard
                                    key={
                                        item?._id ||
                                        item?.id ||
                                        index
                                    }
                                    item={
                                        item
                                    }
                                />

                            )
                        )}

                    </Stack>

                ) : (

                    <EmptyState
                        minHeight={80}
                        message="No service items recorded for this delivery."
                    />

                )}

            </Box>

            <Divider />

            {/* BENEFICIARIES */}

            <Box sx={{ p: 2.5 }}>

                <Typography
                    variant="subtitle1"
                    sx={{
                        fontWeight: 700,
                        mb: 0.25
                    }}>
                    Beneficiary Allocations
                </Typography>

                <Typography
                    variant="body2"
                    sx={{
                        color: "text.secondary",
                        mb: 1.75
                    }}>
                    Services and support allocated to each beneficiary.
                </Typography>


                {beneficiaries.length > 0 ? (

                    <Stack spacing={1.75}>

                        {beneficiaries.map(
                            (
                                entry,
                                index
                            ) => (

                                <BeneficiaryCard
                                    key={
                                        getId(
                                            entry
                                                ?.beneficiary
                                        ) ||
                                        index
                                    }
                                    beneficiary={
                                        entry
                                            .beneficiary
                                    }
                                    allocations={
                                        entry
                                            .allocations
                                    }
                                />

                            )
                        )}

                    </Stack>

                ) : (

                    <EmptyState
                        message="No beneficiary allocations recorded for this delivery."
                    />

                )}

            </Box>

        </Paper>
    );
};


// =====================================================
// MAIN REPORT
// =====================================================

const ServiceDeliveryReportDetails = ({
    report
}) => {

    const rows =
        useMemo(
            () =>
                getRows(report),
            [report]
        );

    const summary =
        report?.summary || {};


    const totalServiceItems =
        useMemo(
            () =>
                rows.reduce(
                    (
                        total,
                        delivery
                    ) =>
                        total +
                        (
                            Array.isArray(
                                delivery?.items
                            )
                                ? delivery
                                    .items
                                    .length
                                : 0
                        ),
                    0
                ),
            [rows]
        );


    const deliveryRecords =
        useMemo(
            () => {

                if (
                    Number(
                        summary
                            ?.beneficiaryDeliveryRecords
                    ) > 0
                ) {
                    return Number(
                        summary
                            .beneficiaryDeliveryRecords
                    );
                }

                return rows.reduce(
                    (
                        total,
                        delivery
                    ) => {

                        const ids =
                            new Set();

                        const items =
                            Array.isArray(
                                delivery?.items
                            )
                                ? delivery.items
                                : [];

                        items.forEach(
                            (item) => {

                                const allocations =
                                    Array.isArray(
                                        item
                                            ?.allocation
                                            ?.beneficiaries
                                    )
                                        ? item
                                            .allocation
                                            .beneficiaries
                                        : [];

                                allocations.forEach(
                                    (allocation) => {

                                        const id =
                                            getId(
                                                allocation
                                                    ?.beneficiary
                                            );

                                        if (id) {
                                            ids.add(id);
                                        }

                                    }
                                );

                            }
                        );

                        return (
                            total +
                            ids.size
                        );
                    },
                    0
                );

            },
            [
                rows,
                summary
            ]
        );


    const quantityByUnit =
        useMemo(
            () => {

                const grouped =
                    new Map();

                rows.forEach(
                    (
                        delivery
                    ) => {

                        const items =
                            Array.isArray(
                                delivery?.items
                            )
                                ? delivery.items
                                : [];

                        items.forEach(
                            (
                                item
                            ) => {

                                const quantity =
                                    Number(
                                        item?.quantity
                                    ) || 0;

                                if (
                                    quantity === 0 ||
                                    isMonetaryUnit(
                                        item?.unit
                                    )
                                ) {
                                    return;
                                }

                                const key =
                                    getUnitName(
                                        item?.unit
                                    );

                                if (
                                    grouped.has(
                                        key
                                    )
                                ) {

                                    grouped.get(
                                        key
                                    ).quantity +=
                                        quantity;

                                } else {

                                    grouped.set(
                                        key,
                                        {
                                            unit:
                                                item?.unit,
                                            quantity
                                        }
                                    );

                                }

                            }
                        );

                    }
                );

                return Array.from(
                    grouped.values()
                );

            },
            [rows]
        );


    if (
        rows.length === 0
    ) {

        return (
            <EmptyState
                title="No service delivery report"
                message="No service delivery details are available."
            />
        );
    }


    return (
        <Stack spacing={3}>

            {/* =================================================
                EXECUTIVE SUMMARY
            ================================================= */}

            <Box>

                <Typography
                    variant="h6"
                    sx={{
                        fontWeight: 700,
                        mb: 1.5
                    }}>
                    Executive Summary
                </Typography>


                <Grid
                    container
                    spacing={1.5}
                >

                    <Grid
                        size={{ xs: 6, sm: 3 }}>
                        <MetricCard
                            label="Deliveries"
                            value={
                                summary
                                    .totalDeliveries ??
                                rows.length
                            }
                        />
                    </Grid>

                    <Grid
                        size={{ xs: 6, sm: 3 }}>
                        <MetricCard
                            label="Beneficiaries"
                            value={
                                summary
                                    .totalBeneficiaries ??
                                0
                            }
                        />
                    </Grid>

                    <Grid
                        size={{ xs: 6, sm: 3 }}>
                        <MetricCard
                            label="Delivery Records"
                            value={
                                deliveryRecords
                            }
                        />
                    </Grid>

                    <Grid
                        size={{ xs: 6, sm: 3 }}>
                        <MetricCard
                            label="Service Items"
                            value={
                                summary
                                    .totalServiceItems ??
                                totalServiceItems
                            }
                        />
                    </Grid>

                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}>
                        <MetricCard
                            label="Actual Support Value"
                            value={formatCurrency(
                                summary
                                    .totalSupportValue
                            )}
                            emphasized
                        />
                    </Grid>

                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}>
                        <MetricCard
                            label="Allocated Value"
                            value={formatCurrency(
                                summary
                                    .totalAllocatedValue
                            )}
                        />
                    </Grid>

                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}>
                        <MetricCard
                            label="Unallocated Value"
                            value={formatCurrency(
                                summary
                                    .totalUnallocatedValue
                            )}
                        />
                    </Grid>

                    <Grid
                        size={{ xs: 12, sm: 6, md: 3 }}>
                        <MetricCard
                            label="Allocation Rate"
                            value={
                                summary
                                    .allocationRate ===
                                    null ||
                                summary
                                    .allocationRate ===
                                    undefined
                                    ? "—"
                                    : `${formatNumber(
                                        summary
                                            .allocationRate,
                                        {
                                            minimumFractionDigits:
                                                2,
                                            maximumFractionDigits:
                                                2
                                        }
                                    )}%`
                            }
                        />
                    </Grid>

                </Grid>

            </Box>

            {/* =================================================
                QUANTITY BY UNIT
            ================================================= */}

            {quantityByUnit.length > 0 ? (

                <Box>

                    <Typography
                        variant="h6"
                        sx={{
                            fontWeight: 700,
                            mb: 1.25
                        }}>
                        Quantity by Unit
                    </Typography>

                    <Stack sx={{ flexWrap: "wrap" }}
                        direction="row"
                        spacing={1}
                        useFlexGap
                    >

                        {quantityByUnit.map(
                            (
                                entry,
                                index
                            ) => (

                                <Chip
                                    key={
                                        getId(
                                            entry.unit
                                        ) ||
                                        index
                                    }
                                    size="small"
                                    variant="outlined"
                                    label={
                                        formatQuantity(
                                            entry.quantity,
                                            entry.unit
                                        )
                                    }
                                />

                            )
                        )}

                    </Stack>

                </Box>

            ) : null}

            {/* =================================================
                DELIVERIES
            ================================================= */}

            <Stack spacing={2.5}>

                {rows.map(
                    (
                        delivery,
                        index
                    ) => (

                        <ServiceDeliveryCard
                            key={
                                delivery?._id ||
                                delivery?.id ||
                                delivery
                                    ?.deliveryNumber ||
                                index
                            }
                            delivery={
                                delivery
                            }
                        />

                    )
                )}

            </Stack>

        </Stack>
    );
};


export default ServiceDeliveryReportDetails;
