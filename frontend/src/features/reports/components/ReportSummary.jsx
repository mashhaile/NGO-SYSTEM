import {
    Box,
    Card,
    CardContent,
    Chip,
    Divider,
    Grid,
    Stack,
    Typography
} from "@mui/material";

import {
    FormSection
} from "../../../components/ui";


// =====================================================
// CONSTANTS
// =====================================================

const CURRENCY_KEYS = [
    "totalSupportValue",
    "supportValue",
    "totalAmount",
    "totalDonationAmount",
    "totalFunding",
    "totalBudget",
    "approvedBudget",
    "budget",
    "amount",
    "value",
    "funding",
    "serviceValue",
    "totalServiceValue",
    "donationValue",
    "totalDonationValue"
];

const PERCENTAGE_KEYS = [
    "rate",
    "percentage",
    "percent",
    "participationRate",
    "completionRate",
    "attendanceRate",
    "coverageRate",
    "successRate"
];

const DATE_KEYS = [
    "date",
    "startDate",
    "endDate",
    "reportDate",
    "generatedAt",
    "periodStart",
    "periodEnd"
];

const DISTRIBUTION_KEYS = [
    "byGender",
    "byStatus",
    "byProgram",
    "byProject",
    "byActivity",
    "byActivityType",
    "byParticipantType",
    "byParticipantSource",
    "byServiceType",
    "byServiceCategory",
    "gender",
    "status",
    "programs",
    "projects",
    "activities",
    "activityTypes",
    "participantTypes",
    "participantSources",
    "serviceTypes",
    "serviceCategories"
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

        totalBeneficiaries:
            "Total Beneficiaries",

        totalEnrollments:
            "Total Enrollments",

        totalServices:
            "Total Services",

        totalSupportValue:
            "Total Support Value",

        totalPrograms:
            "Total Programs",

        totalProjects:
            "Total Projects",

        totalActivities:
            "Total Activities",

        totalActivityRuns:
            "Total Activity Runs",

        totalAttendance:
            "Total Attendance",

        totalAttendanceRecords:
            "Total Attendance Records",

        totalParticipants:
            "Total Participants",

        totalUniqueParticipants:
            "Total Unique Participants",

        totalUniqueBeneficiaries:
            "Total Unique Beneficiaries",

        totalEnterprises:
            "Total Enterprises",

        totalDonors:
            "Total Donors",

        totalDonations:
            "Total Donations",

        totalAmount:
            "Total Amount",

        totalBudget:
            "Total Budget",

        approvedBudget:
            "Approved Budget",

        totalFunding:
            "Total Funding",

        serviceValue:
            "Service Value",

        totalServiceValue:
            "Total Service Value",

        participationRate:
            "Participation Rate",

        attendanceRate:
            "Attendance Rate",

        completionRate:
            "Completion Rate",

        coverageRate:
            "Coverage Rate",

        startDate:
            "Start Date",

        endDate:
            "End Date",

        reportDate:
            "Report Date",

        generatedAt:
            "Generated At"

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
// KEY HELPERS
// =====================================================

const normalizedKey = (
    key
) => {

    return String(
        key || ""
    )
        .replace(
            /[_-\s]+/g,
            ""
        )
        .toLowerCase();

};


const isCurrencyKey = (
    key
) => {

    const normalized =
        normalizedKey(
            key
        );

    return CURRENCY_KEYS.some(
        (
            item
        ) =>
            normalizedKey(
                item
            ) === normalized
    );

};


const isPercentageKey = (
    key
) => {

    const normalized =
        normalizedKey(
            key
        );

    return PERCENTAGE_KEYS.some(
        (
            item
        ) =>
            normalizedKey(
                item
            ) === normalized
    );

};


const isDateKey = (
    key
) => {

    const normalized =
        normalizedKey(
            key
        );

    return DATE_KEYS.some(
        (
            item
        ) =>
            normalizedKey(
                item
            ) === normalized
    );

};


const isDistributionKey = (
    key
) => {

    const normalized =
        normalizedKey(
            key
        );

    return DISTRIBUTION_KEYS.some(
        (
            item
        ) =>
            normalizedKey(
                item
            ) === normalized
    );

};


// =====================================================
// DATE FORMAT
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
// NUMBER FORMAT
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
            maximumFractionDigits: 2
        }
    );

};


// =====================================================
// CURRENCY FORMAT
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
// PERCENTAGE FORMAT
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
// VALUE FORMAT
// =====================================================

const formatPrimitiveValue = (
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


    return String(
        value
    );

};


// =====================================================
// DISTRIBUTION VALUE
// =====================================================

const DistributionValue = ({
    value
}) => {

    if (
        !value ||
        typeof value !==
        "object"
    ) {

        return null;

    }


    const entries =
        Array.isArray(
            value
        )
            ? value
            : Object.entries(
                value
            );


    if (
        entries.length ===
        0
    ) {

        return (
            <Typography
                variant="body2"
                color="text.secondary"
            >
                No data
            </Typography>
        );

    }


    return (

        <Stack
            spacing={1}
            mt={1.5}
        >

            {
                entries.map(
                    (
                        entry,
                        index
                    ) => {

                        const isArrayEntry =
                            Array.isArray(
                                value
                            );

                        const entryKey =
                            isArrayEntry
                                ? index
                                : entry[0];

                        const entryValue =
                            isArrayEntry
                                ? entry
                                : entry[1];

                        let label =
                            formatLabel(
                                entryKey
                            );

                        let displayValue =
                            entryValue;


                        if (
                            entryValue &&
                            typeof entryValue ===
                            "object" &&
                            !Array.isArray(
                                entryValue
                            )
                        ) {

                            if (
                                entryValue.name
                            ) {

                                label =
                                    entryValue.name;

                                displayValue =
                                    entryValue.count ??
                                    entryValue.total ??
                                    entryValue.value ??
                                    entryValue.amount ??
                                    0;

                            } else {

                                displayValue =
                                    entryValue.count ??
                                    entryValue.total ??
                                    entryValue.value ??
                                    entryValue.amount ??
                                    "-";

                            }

                        }


                        return (

                            <Box
                                key={
                                    `${entryKey}-${index}`
                                }
                                sx={{
                                    display:
                                        "flex",
                                    alignItems:
                                        "center",
                                    justifyContent:
                                        "space-between",
                                    gap: 2,
                                    px: 1.25,
                                    py: 0.75,
                                    borderRadius:
                                        1,
                                    bgcolor:
                                        "action.hover"
                                }}
                            >

                                <Typography
                                    variant="body2"
                                    color="text.secondary"
                                    sx={{
                                        minWidth: 0,
                                        overflow:
                                            "hidden",
                                        textOverflow:
                                            "ellipsis",
                                        whiteSpace:
                                            "nowrap"
                                    }}
                                >
                                    {
                                        label
                                    }
                                </Typography>


                                <Typography
                                    variant="body2"
                                    fontWeight={600}
                                    sx={{
                                        flexShrink:
                                            0
                                    }}
                                >
                                    {
                                        typeof displayValue ===
                                        "number"
                                            ? formatNumber(
                                                displayValue
                                            )
                                            : String(
                                                displayValue
                                            )
                                    }
                                </Typography>

                            </Box>

                        );

                    }
                )
            }

        </Stack>

    );

};


// =====================================================
// OBJECT VALUE
// =====================================================

const ObjectValue = ({
    value
}) => {

    if (
        !value ||
        typeof value !==
        "object"
    ) {

        return null;

    }


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

                <Typography
                    variant="body2"
                    color="text.secondary"
                >
                    No data
                </Typography>

            );

        }


        return (

            <Stack
                direction="row"
                flexWrap="wrap"
                gap={0.75}
                mt={1}
            >

                {
                    value.map(
                        (
                            item,
                            index
                        ) => {

                            const label =
                                typeof item ===
                                "object"
                                    ? (
                                        item.name ||
                                        item.label ||
                                        item.title ||
                                        item.value ||
                                        "-"
                                    )
                                    : String(
                                        item
                                    );


                            return (

                                <Chip
                                    key={
                                        `${label}-${index}`
                                    }
                                    label={
                                        label
                                    }
                                    size="small"
                                    variant="outlined"
                                />

                            );

                        }
                    )
                }

            </Stack>

        );

    }


    return (
        <DistributionValue
            value={
                value
            }
        />
    );

};


// =====================================================
// SUMMARY VALUE
// =====================================================

const SummaryValue = ({
    keyName,
    value
}) => {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {

        return (

            <Typography
                variant="h6"
                fontWeight={700}
                color="text.secondary"
            >
                -
            </Typography>

        );

    }


    if (
        typeof value ===
        "object"
    ) {

        return (

            <ObjectValue
                value={
                    value
                }
            />

        );

    }


    return (

        <Typography
            variant="h5"
            fontWeight={700}
            lineHeight={1.2}
            sx={{
                wordBreak:
                    "break-word"
            }}
        >
            {
                formatPrimitiveValue(
                    keyName,
                    value
                )
            }
        </Typography>

    );

};


// =====================================================
// SUMMARY CARD
// =====================================================

const SummaryCard = ({
    label,
    value,
    keyName
}) => {

    const distribution =
        typeof value ===
        "object" &&
        value !== null;

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
                    p: 2.25,
                    "&:last-child": {
                        pb: 2.25
                    }
                }}
            >

                <Typography
                    variant="body2"
                    color="text.secondary"
                    fontWeight={600}
                    sx={{
                        mb: distribution
                            ? 0
                            : 1
                    }}
                >
                    {
                        label
                    }
                </Typography>


                <SummaryValue
                    keyName={
                        keyName
                    }
                    value={
                        value
                    }
                />

            </CardContent>

        </Card>

    );

};


// =====================================================
// COMPONENT
// =====================================================

const ReportSummary = ({
    summary = {}
}) => {

    if (
        !summary ||
        typeof summary !==
        "object" ||
        Array.isArray(
            summary
        )
    ) {

        return null;

    }


    const entries =
        Object.entries(
            summary
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

        <FormSection
            title="Summary"
        >

            <Grid
                container
                spacing={2}
            >

                {
                    visibleEntries.map(
                        (
                            [
                                key,
                                value
                            ]
                        ) => (

                            <Grid
                                item
                                xs={12}
                                sm={6}
                                md={
                                    typeof value ===
                                    "object" &&
                                    value !== null
                                        ? 6
                                        : 3
                                }
                                key={
                                    key
                                }
                            >

                                <SummaryCard
                                    keyName={
                                        key
                                    }
                                    label={
                                        formatLabel(
                                            key
                                        )
                                    }
                                    value={
                                        value
                                    }
                                />

                            </Grid>

                        )
                    )
                }

            </Grid>


            {
                visibleEntries.some(
                    (
                        [
                            key,
                            value
                        ]
                    ) =>
                        isDistributionKey(
                            key
                        ) &&
                        value &&
                        typeof value ===
                        "object"
                ) && (

                    <Box
                        mt={2}
                    >

                        <Divider />

                    </Box>

                )
            }

        </FormSection>

    );

};


export default ReportSummary;
