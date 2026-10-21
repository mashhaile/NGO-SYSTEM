import {
    Box,
    Card,
    CardContent,
    Chip,
    Divider,
    Grid,
    Stack,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Typography
} from "@mui/material";

import {
    FormSection
} from "../../../components/ui";


// =====================================================
// CONSTANTS
// =====================================================

const CURRENCY_KEYS = [
    // Finance reports (budgets / expenses)
    "spent",
    "pending",
    "remaining",
    "totalBudget",
    "totalSpent",
    "totalPending",
    "totalRemaining",
    "donationAmount",
    "supportValue",
    "totalSupportValue",
    "serviceValue",
    "totalServiceValue",
    "deliveryValue",
    "totalDeliveryValue",
    "amount",
    "totalAmount",
    "value",
    "budget",
    "approvedBudget",
    "funding",
    "totalFunding",
    "donationValue",
    "totalDonationValue"
];

const PERCENTAGE_KEYS = [
    // Finance reports (budgets / expenses)
    "percentSpent",
    "percentUsed",
    "percentOfYearPassed",
    "rate",
    "percentage",
    "percent",
    "participationRate",
    "attendanceRate",
    "completionRate",
    "coverageRate",
    "successRate"
];

const DATE_KEYS = [
    "date",
    "activityDate",
    "sessionDate",
    "deliveryDate",
    "enrollmentDate",
    "startDate",
    "endDate",
    "joinedDate",
    "leftDate",
    "reportDate"
];

const LABEL_FIELDS = [
    "beneficiaryName",
    "beneficiaryNumber",
    "programName",
    "program",
    "projectName",
    "project",
    "activityName",
    "activity",
    "activityRunName",
    "activityRun",
    "serviceCategory",
    "serviceType",
    "category",
    "type",
    "donorName",
    "donor",
    "participantName",
    "participantType",
    "name",
    "title",
    "label",
    "code",
    "gender",
    "status"
];

const VALUE_FIELDS = [
    "count",
    "total",
    "value",
    "amount",
    "supportValue",
    "deliveryValue",
    "serviceValue",
    "services",
    "serviceCount",
    "enrollments",
    "enrollmentCount",
    "beneficiaries",
    "beneficiaryCount",
    "attendance",
    "participants",
    "participantCount",
    "activities",
    "activityCount",
    "activityRuns",
    "projects",
    "projectCount",
    "donations",
    "donationCount",
    "targetParticipants",
    "totalAmount",
    "totalValue"
];


// =====================================================
// FORMAT LABEL
// =====================================================

const formatLabel = (
    value
) => {

    if (
        !value
    ) {

        return "";

    }


    const labelMap = {

        servicesByBeneficiary:
            "Services By Beneficiary",

        supportByBeneficiary:
            "Support By Beneficiary",

        enrollmentsByBeneficiary:
            "Enrollments By Beneficiary",

        servicesByProgram:
            "Services By Program",

        beneficiariesByProgram:
            "Beneficiaries By Program",

        attendanceByProgram:
            "Attendance By Program",

        attendanceByParticipant:
            "Attendance By Participant",

        servicesByCategory:
            "Services By Category",

        servicesByType:
            "Services By Type",

        donationsByDonor:
            "Donations By Donor",

        donationsByProgram:
            "Donations By Program",

        projectsByProgram:
            "Projects By Program",

        activitiesByProgram:
            "Activities By Program",

        activitiesByProject:
            "Activities By Project",

        participantsByType:
            "Participants By Type",

        participantsByProgram:
            "Participants By Program",

        participantsByProject:
            "Participants By Project",

        beneficiariesByProject:
            "Beneficiaries By Project",

        targetParticipantsByProgram:
            "Target Participants By Program",

        targetParticipantsByProject:
            "Target Participants By Project",

        activityRunsByActivity:
            "Activity Runs By Activity"

    };


    if (
        labelMap[value]
    ) {

        return labelMap[value];

    }


    return String(
        value
    )
        .replace(
            /([A-Z])/g,
            " $1"
        )
        .replace(
            /[_-]+/g,
            " "
        )
        .replace(
            /\s+/g,
            " "
        )
        .replace(
            /^./,
            (
                character
            ) =>
                character.toUpperCase()
        )
        .trim();

};


// =====================================================
// NORMALIZE KEY
// =====================================================

const normalizeKey = (
    key
) => {

    return String(
        key || ""
    )
        .replace(
            /[_\-\s]+/g,
            ""
        )
        .toLowerCase();

};


// =====================================================
// KEY TYPE HELPERS
// =====================================================

const matchesKey = (
    key,
    candidates
) => {

    const normalized =
        normalizeKey(
            key
        );

    return candidates.some(
        (
            candidate
        ) =>
            normalizeKey(
                candidate
            ) === normalized
    );

};


const isCurrencyKey = (
    key
) => {

    return matchesKey(
        key,
        CURRENCY_KEYS
    );

};


const isPercentageKey = (
    key
) => {

    return matchesKey(
        key,
        PERCENTAGE_KEYS
    );

};


const isDateKey = (
    key
) => {

    return matchesKey(
        key,
        DATE_KEYS
    );

};


// =====================================================
// FORMAT DATE
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

        return String(
            value
        );

    }


    return date.toLocaleDateString(
        undefined,
        {
            year: "numeric",
            month: "short",
            day: "numeric"
        }
    );

};


// =====================================================
// FORMAT NUMBER
// =====================================================

const formatNumber = (
    value
) => {

    if (
        typeof value !==
        "number"
    ) {

        return String(
            value
        );

    }


    return value.toLocaleString(
        undefined,
        {
            maximumFractionDigits:
                2
        }
    );

};


// =====================================================
// FORMAT CURRENCY
// =====================================================

const formatCurrency = (
    value
) => {

    if (
        typeof value !==
        "number"
    ) {

        return String(
            value
        );

    }


    return `ETB ${value.toLocaleString(
        undefined,
        {
            minimumFractionDigits:
                0,
            maximumFractionDigits:
                2
        }
    )}`;

};


// =====================================================
// FORMAT PERCENTAGE
// =====================================================

const formatPercentage = (
    value
) => {

    if (
        typeof value !==
        "number"
    ) {

        return String(
            value
        );

    }


    return `${value.toLocaleString(
        undefined,
        {
            maximumFractionDigits:
                2
        }
    )}%`;

};


// =====================================================
// FORMAT VALUE
// =====================================================

const formatValue = (
    key,
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
        typeof value ===
        "boolean"
    ) {

        return value
            ? "Yes"
            : "No";

    }


    if (
        isDateKey(
            key
        )
    ) {

        return formatDate(
            value
        );

    }


    if (
        isPercentageKey(
            key
        )
    ) {

        return formatPercentage(
            value
        );

    }


    if (
        isCurrencyKey(
            key
        )
    ) {

        return formatCurrency(
            value
        );

    }


    if (
        typeof value ===
        "number"
    ) {

        return formatNumber(
            value
        );

    }


    if (
        Array.isArray(
            value
        )
    ) {

        return value
            .map(
                (
                    item
                ) =>
                    formatValue(
                        key,
                        item
                    )
            )
            .join(
                ", "
            );

    }


    if (
        typeof value ===
        "object"
    ) {

        if (
            value.name
        ) {

            return String(
                value.name
            );

        }


        if (
            value.label
        ) {

            return String(
                value.label
            );

        }


        if (
            value.title
        ) {

            return String(
                value.title
            );

        }


        return Object.entries(
            value
        )
            .map(
                (
                    [
                        childKey,
                        childValue
                    ]
                ) =>
                    `${formatLabel(childKey)}: ${formatValue(childKey, childValue)}`
            )
            .join(
                " | "
            );

    }


    return String(
        value
    );

};


// =====================================================
// GET ROW COLUMNS
// =====================================================

const getColumns = (
    rows
) => {

    if (
        !Array.isArray(
            rows
        ) ||
        rows.length ===
        0
    ) {

        return [];

    }


    const columns = [];


    rows.forEach(
        (
            row
        ) => {

            if (
                !row ||
                typeof row !==
                "object" ||
                Array.isArray(
                    row
                )
            ) {

                return;

            }


            Object.keys(
                row
            ).forEach(
                (
                    key
                ) => {

                    if (
                        !columns.includes(
                            key
                        )
                    ) {

                        columns.push(
                            key
                        );

                    }

                }
            );

        }
    );


    return columns;

};


// =====================================================
// GET LABEL FIELD
// =====================================================

const getLabelField = (
    row,
    columns
) => {

    if (
        !row ||
        typeof row !==
        "object"
    ) {

        return null;

    }


    for (
        const field of LABEL_FIELDS
    ) {

        if (
            columns.includes(
                field
            ) &&
            row[field] !== null &&
            row[field] !== undefined &&
            row[field] !== ""
        ) {

            return field;

        }

    }


    return (
        columns.find(
            (
                column
            ) =>
                typeof row[column] ===
                "string"
        ) ||
        null
    );

};


// =====================================================
// GET VALUE FIELD
// =====================================================

const getValueField = (
    row,
    columns
) => {

    if (
        !row ||
        typeof row !==
        "object"
    ) {

        return null;

    }


    for (
        const field of VALUE_FIELDS
    ) {

        if (
            columns.includes(
                field
            ) &&
            typeof row[field] ===
            "number"
        ) {

            return field;

        }

    }


    return (
        columns.find(
            (
                column
            ) =>
                typeof row[column] ===
                "number"
        ) ||
        null
    );

};


// =====================================================
// GET ROW LABEL
// =====================================================

const getRowLabel = (
    row,
    columns
) => {

    const labelField =
        getLabelField(
            row,
            columns
        );


    if (
        labelField
    ) {

        return formatValue(
            labelField,
            row[labelField]
        );

    }


    return "Record";

};


// =====================================================
// GET ROW VALUE
// =====================================================

const getRowValue = (
    row,
    columns
) => {

    const valueField =
        getValueField(
            row,
            columns
        );


    if (
        !valueField
    ) {

        return null;

    }


    return {
        field:
            valueField,
        value:
            row[valueField]
    };

};


// =====================================================
// STATISTIC ROW CARD
// =====================================================

const StatisticRowCard = ({
    row,
    columns
}) => {

    const label =
        getRowLabel(
            row,
            columns
        );

    const numeric =
        getRowValue(
            row,
            columns
        );


    if (
        !numeric
    ) {

        return (
            <Card
                variant="outlined"
                sx={{
                    height:
                        "100%",
                    borderRadius:
                        2
                }}
            >

                <CardContent
                    sx={{
                        p: 2,
                        "&:last-child": {
                            pb: 2
                        }
                    }}
                >

                    <Typography
                        variant="body2"
                        gutterBottom
                        sx={{
                            color: "text.secondary",
                            fontWeight: 600
                        }}>
                        {
                            label
                        }
                    </Typography>


                    <Stack
                        spacing={0.5}
                    >

                        {
                            columns
                                .filter(
                                    (
                                        column
                                    ) =>
                                        row[column] !==
                                        undefined &&
                                        column !==
                                        getLabelField(
                                            row,
                                            columns
                                        )
                                )
                                .map(
                                    (
                                        column
                                    ) => (

                                        <Box
                                            key={
                                                column
                                            }
                                            sx={{
                                                display:
                                                    "flex",
                                                justifyContent:
                                                    "space-between",
                                                gap: 2
                                            }}
                                        >

                                            <Typography
                                                variant="caption"
                                                sx={{
                                                    color: "text.secondary"
                                                }}
                                            >
                                                {
                                                    formatLabel(
                                                        column
                                                    )
                                                }
                                            </Typography>

                                            <Typography
                                                variant="body2"
                                                sx={{
                                                    fontWeight: 600,
                                                    textAlign: "right"
                                                }}>
                                                {
                                                    formatValue(
                                                        column,
                                                        row[column]
                                                    )
                                                }
                                            </Typography>

                                        </Box>

                                    )
                                )
                        }

                    </Stack>

                </CardContent>

            </Card>
        );

    }


    return (
        <Card
            variant="outlined"
            sx={{
                height:
                    "100%",
                borderRadius:
                    2,
                transition:
                    "box-shadow 0.2s ease",
                "&:hover": {
                    boxShadow:
                        2
                }
            }}
        >

            <CardContent
                sx={{
                    p: 2,
                    "&:last-child": {
                        pb: 2
                    }
                }}
            >

                <Typography
                    variant="body2"
                    sx={{
                        color: "text.secondary",
                        fontWeight: 600,
                        mb: 1
                    }}>
                    {
                        label
                    }
                </Typography>


                <Typography
                    variant="h6"
                    sx={{
                        fontWeight: 700,

                        wordBreak:
                            "break-word"
                    }}>
                    {
                        formatValue(
                            numeric.field,
                            numeric.value
                        )
                    }
                </Typography>

            </CardContent>

        </Card>
    );

};


// =====================================================
// STATISTICS TABLE
// =====================================================

const StatisticsTable = ({
    rows
}) => {

    const columns =
        getColumns(
            rows
        );


    if (
        columns.length ===
        0
    ) {

        return (
            <Typography
                sx={{
                    color: "text.secondary"
                }}
            >No data available.
                            </Typography>
        );

    }


    return (

        <TableContainer
            sx={{
                border:
                    "1px solid",
                borderColor:
                    "divider",
                borderRadius:
                    2,
                overflowX:
                    "auto"
            }}
        >

            <Table
                size="small"
            >

                <TableHead>

                    <TableRow>

                        {
                            columns.map(
                                (
                                    column
                                ) => (

                                    <TableCell
                                        key={
                                            column
                                        }
                                        sx={{
                                            fontWeight:
                                                700,
                                            whiteSpace:
                                                "nowrap",
                                            bgcolor:
                                                "action.hover"
                                        }}
                                    >
                                        {
                                            formatLabel(
                                                column
                                            )
                                        }
                                    </TableCell>

                                )
                            )
                        }

                    </TableRow>

                </TableHead>


                <TableBody>

                    {
                        rows.map(
                            (
                                row,
                                index
                            ) => (

                                <TableRow
                                    key={
                                        row?._id ||
                                        row?.id ||
                                        index
                                    }
                                    hover
                                >

                                    {
                                        columns.map(
                                            (
                                                column
                                            ) => (

                                                <TableCell
                                                    key={
                                                        column
                                                    }
                                                    sx={{
                                                        verticalAlign:
                                                            "top",
                                                        whiteSpace:
                                                            "nowrap"
                                                    }}
                                                >
                                                    {
                                                        formatValue(
                                                            column,
                                                            row?.[
                                                                column
                                                            ]
                                                        )
                                                    }
                                                </TableCell>

                                            )
                                        )
                                    }

                                </TableRow>

                            )
                        )
                    }

                </TableBody>

            </Table>

        </TableContainer>

    );

};


// =====================================================
// STATISTIC BLOCK
// =====================================================

const StatisticBlock = ({
    name,
    value
}) => {

    const title =
        formatLabel(
            name
        );


    if (
        Array.isArray(
            value
        )
    ) {

        if (
            value.length ===
            0
        ) {

            return (
                <Box
                    sx={{
                        mb: 3
                    }}
                >

                    <Typography
                        variant="subtitle1"
                        sx={{
                            fontWeight: 700,
                            mb: 1.5
                        }}>
                        {
                            title
                        }
                    </Typography>

                    <Box
                        sx={{
                            p: 2,
                            border:
                                "1px dashed",
                            borderColor:
                                "divider",
                            borderRadius:
                                2
                        }}
                    >

                        <Typography
                            variant="body2"
                            sx={{
                                color: "text.secondary"
                            }}
                        >
                            No data available.
                        </Typography>

                    </Box>

                </Box>
            );

        }


        const columns =
            getColumns(
                value
            );

        const isSimpleStatistics =
            columns.length <= 3 &&
            value.every(
                (
                    row
                ) =>
                    row &&
                    typeof row ===
                    "object" &&
                    !Array.isArray(
                        row
                    ) &&
                    getLabelField(
                        row,
                        columns
                    ) &&
                    getValueField(
                        row,
                        columns
                    )
            );


        return (
            <Box
                sx={{
                    mb: 3
                }}
            >

                <Typography
                    variant="subtitle1"
                    sx={{
                        fontWeight: 700,
                        mb: 1.5
                    }}>
                    {
                        title
                    }
                </Typography>

                {
                    isSimpleStatistics ? (

                        <Grid
                            container
                            spacing={1.5}
                        >

                            {
                                value.map(
                                    (
                                        row,
                                        index
                                    ) => (

                                        <Grid
                                            size={{ xs: 12, sm: 6, md: 4, lg: 3 }}
                                            key={
                                                row?._id ||
                                                row?.id ||
                                                index
                                            }
                                        >

                                            <StatisticRowCard
                                                row={
                                                    row
                                                }
                                                columns={
                                                    columns
                                                }
                                            />

                                        </Grid>

                                    )
                                )
                            }

                        </Grid>

                    ) : (

                        <StatisticsTable
                            rows={
                                value
                            }
                        />

                    )
                }

            </Box>
        );

    }


    if (
        value &&
        typeof value ===
        "object"
    ) {

        return (
            <Box
                sx={{
                    mb: 3
                }}
            >

                <Typography
                    variant="subtitle1"
                    sx={{
                        fontWeight: 700,
                        mb: 1.5
                    }}>
                    {
                        title
                    }
                </Typography>

                <Grid
                    container
                    spacing={1.5}
                >

                    {
                        Object.entries(
                            value
                        ).map(
                            (
                                [
                                    key,
                                    item
                                ]
                            ) => (

                                <Grid
                                    size={{ xs: 12, sm: 6, md: 4 }}
                                    key={
                                        key
                                    }
                                >

                                    <Card
                                        variant="outlined"
                                        sx={{
                                            borderRadius:
                                                2,
                                            height:
                                                "100%"
                                        }}
                                    >

                                        <CardContent
                                            sx={{
                                                p: 2,
                                                "&:last-child": {
                                                    pb: 2
                                                }
                                            }}
                                        >

                                            <Typography
                                                variant="body2"
                                                gutterBottom
                                                sx={{
                                                    color: "text.secondary",
                                                    fontWeight: 600
                                                }}>
                                                {
                                                    formatLabel(
                                                        key
                                                    )
                                                }
                                            </Typography>


                                            <Typography
                                                variant="h6"
                                                sx={{
                                                    fontWeight: 700
                                                }}
                                            >
                                                {
                                                    formatValue(
                                                        key,
                                                        item
                                                    )
                                                }
                                            </Typography>

                                        </CardContent>

                                    </Card>

                                </Grid>

                            )
                        )
                    }

                </Grid>

            </Box>
        );

    }


    return (
        <Box
            sx={{
                mb: 3
            }}
        >

            <Typography
                variant="subtitle1"
                sx={{
                    fontWeight: 700,
                    mb: 1.5
                }}>
                {
                    title
                }
            </Typography>

            <Chip
                label={
                    formatValue(
                        name,
                        value
                    )
                }
                variant="outlined"
            />

        </Box>
    );

};


// =====================================================
// COMPONENT
// =====================================================

const ReportStatistics = ({
    statistics = {}
}) => {

    if (
        !statistics ||
        typeof statistics !==
        "object" ||
        Array.isArray(
            statistics
        )
    ) {

        return null;

    }


    const entries =
        Object.entries(
            statistics
        );


    if (
        entries.length ===
        0
    ) {

        return null;

    }


    const visibleEntries =
        entries.filter(
            (
                [
                    key,
                    value
                ]
            ) =>
                key &&
                value !== undefined
        );


    if (
        visibleEntries.length ===
        0
    ) {

        return null;

    }


    return (
        <Box
            sx={{
                mt: 3
            }}
        >

            <FormSection
                title="Statistics"
            >

                {
                    visibleEntries.map(
                        (
                            [
                                key,
                                value
                            ],
                            index
                        ) => (

                            <Box
                                key={
                                    key
                                }
                            >

                                <StatisticBlock
                                    name={
                                        key
                                    }
                                    value={
                                        value
                                    }
                                />


                                {
                                    index <
                                    visibleEntries.length - 1 && (

                                        <Divider
                                            sx={{
                                                mb: 3
                                            }}
                                        />

                                    )
                                }

                            </Box>

                        )
                    )
                }

            </FormSection>

        </Box>
    );

};


export default ReportStatistics;
