import {
    Box,
    Grid,
    Typography
} from "@mui/material";

import {
    FormSection
} from "../../../components/ui";


// =====================================================
// LABEL HELPERS
// =====================================================

const formatLabel = (key) => {

    const labels = {

        servicesByBeneficiary:
            "Services By Beneficiary",

        supportByBeneficiary:
            "Support Value By Beneficiary",

        enrollmentsByBeneficiary:
            "Enrollments By Beneficiary",

        servicesByProgram:
            "Services By Program",

        beneficiariesByProgram:
            "Beneficiaries By Program",

        beneficiariesByProject:
            "Beneficiaries By Project",

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

        targetParticipantsByProgram:
            "Target Participants By Program",

        targetParticipantsByProject:
            "Target Participants By Project",

        activityRunsByActivity:
            "Activity Runs By Activity",

        enterprisesByType:
            "Enterprises By Type",

        enterprisesByOwnership:
            "Enterprises By Ownership",

        enterprisesBySector:
            "Enterprises By Sector",

        donorsByProgram:
            "Donors By Program",

        programsByStatus:
            "Programs By Status",

        projectsByStatus:
            "Projects By Status",

        activitiesByStatus:
            "Activities By Status",

        attendanceByStatus:
            "Attendance By Status",

        servicesByStatus:
            "Services By Status",

        donationsByStatus:
            "Donations By Status"

    };

    if (labels[key]) {
        return labels[key];
    }

    return String(key)
        .replace(
            /([A-Z])/g,
            " $1"
        )
        .replace(
            /^./,
            char =>
                char.toUpperCase()
        )
        .trim();

};


// =====================================================
// VALUE HELPERS
// =====================================================

const formatNumber = (
    value
) => {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return "-";
    }

    const number =
        Number(value);

    if (
        Number.isNaN(number)
    ) {
        return String(value);
    }

    return number.toLocaleString();
};


const formatCurrency = (
    value
) => {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return "-";
    }

    const number =
        Number(value);

    if (
        Number.isNaN(number)
    ) {
        return String(value);
    }

    return number.toLocaleString(
        undefined,
        {
            minimumFractionDigits: 2,
            maximumFractionDigits: 2
        }
    );

};


const formatPercentage = (
    value
) => {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return "-";
    }

    const number =
        Number(value);

    if (
        Number.isNaN(number)
    ) {
        return String(value);
    }

    return `${number.toLocaleString(
        undefined,
        {
            maximumFractionDigits: 2
        }
    )}%`;

};


// =====================================================
// OBJECT HELPERS
// =====================================================

const isObject = (
    value
) => {

    return (
        value !== null &&
        typeof value === "object" &&
        !Array.isArray(value)
    );

};


const getObjectLabel = (
    value
) => {

    if (!isObject(value)) {
        return null;
    }

    const preferredKeys = [
        "name",
        "label",
        "title",
        "programName",
        "projectName",
        "activityName",
        "beneficiaryName",
        "donorName",
        "category",
        "serviceCategory",
        "serviceType",
        "participantType",
        "status"
    ];

    for (
        const key of preferredKeys
    ) {

        if (
            value[key] !== undefined &&
            value[key] !== null &&
            value[key] !== ""
        ) {

            return String(
                value[key]
            );

        }

    }

    return null;

};


const getObjectNumericValue = (
    value
) => {

    if (!isObject(value)) {
        return null;
    }

    const preferredKeys = [
        "count",
        "total",
        "value",
        "amount",
        "supportValue",
        "deliveryValue",
        "services",
        "serviceCount",
        "enrollments",
        "enrollmentCount",
        "beneficiaries",
        "beneficiaryCount",
        "attendance",
        "participants",
        "targetParticipants",
        "activities",
        "activityRuns",
        "projects",
        "donations",
        "totalAmount"
    ];

    for (
        const key of preferredKeys
    ) {

        const number =
            Number(value[key]);

        if (
            value[key] !== undefined &&
            value[key] !== null &&
            value[key] !== "" &&
            !Number.isNaN(number)
        ) {

            return number;

        }

    }

    const numericEntry =
        Object.entries(value)
            .find(
                ([, item]) =>
                    typeof item === "number"
            );

    if (numericEntry) {
        return numericEntry[1];
    }

    return null;

};


// =====================================================
// CHART VALUE FORMAT
// =====================================================

const isCurrencyChart = (
    chartKey
) => {

    return [
        "supportByBeneficiary",
        "donationsByDonor",
        "donationsByProgram",
        "financialByCategory",
        "financialByProgram",
        "supportByProgram",
        "fundingByProgram",
        "fundingByProject"
    ].includes(
        chartKey
    );

};


const isPercentageChart = (
    chartKey
) => {

    return (
        chartKey
            .toLowerCase()
            .includes(
                "percentage"
            ) ||
        chartKey
            .toLowerCase()
            .includes(
                "rate"
            )
    );

};


const formatChartValue = (
    value,
    chartKey
) => {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return "-";
    }

    if (
        isPercentageChart(
            chartKey
        )
    ) {

        return formatPercentage(
            value
        );

    }

    if (
        isCurrencyChart(
            chartKey
        )
    ) {

        return formatCurrency(
            value
        );

    }

    return formatNumber(
        value
    );

};


// =====================================================
// LABEL FIELD
// =====================================================

const getLabelField = (
    row
) => {

    if (!isObject(row)) {
        return null;
    }

    const preferredFields = [

        "beneficiaryNumber",
        "beneficiaryName",

        "name",

        "programName",
        "program",

        "projectName",
        "project",

        "activityName",
        "activity",

        "activityRunName",
        "activityRun",

        "enterpriseName",
        "enterprise",

        "donorName",
        "donor",

        "category",

        "serviceCategory",

        "serviceType",

        "participantType",

        "gender",

        "status",

        "label",

        "title"

    ];

    for (
        const field of preferredFields
    ) {

        const value =
            row[field];

        if (
            value !== undefined &&
            value !== null &&
            value !== ""
        ) {

            if (
                isObject(value)
            ) {

                const objectLabel =
                    getObjectLabel(
                        value
                    );

                if (
                    objectLabel
                ) {

                    return {
                        field,
                        value:
                            objectLabel
                    };

                }

            } else {

                return {
                    field,
                    value:
                        String(value)
                };

            }

        }

    }

    const fallback =
        Object.entries(row)
            .find(
                ([, value]) =>
                    typeof value === "string" &&
                    value.trim() !== ""
            );

    if (fallback) {

        return {
            field:
                fallback[0],
            value:
                fallback[1]
        };

    }

    return null;

};


// =====================================================
// NUMERIC FIELD
// =====================================================

const getNumericField = (
    row,
    chartKey,
    labelField
) => {

    if (!isObject(row)) {
        return null;
    }

    const fieldMap = {

        activitiesByProgram:
            "activities",

        activitiesByProject:
            "activities",

        participantsByType:
            "participants",

        participantsByProgram:
            "participants",

        participantsByProject:
            "participants",

        beneficiariesByProgram:
            "beneficiaries",

        beneficiariesByProject:
            "beneficiaries",

        targetParticipantsByProgram:
            "targetParticipants",

        targetParticipantsByProject:
            "targetParticipants",

        activityRunsByActivity:
            "activityRuns",

        servicesByBeneficiary:
            "services",

        supportByBeneficiary:
            "supportValue",

        enrollmentsByBeneficiary:
            "enrollments",

        servicesByProgram:
            "services",

        attendanceByProgram:
            "attendance",

        attendanceByParticipant:
            "attendance",

        servicesByCategory:
            "services",

        servicesByType:
            "services",

        donationsByDonor:
            "donations",

        donationsByProgram:
            "donations",

        projectsByProgram:
            "projects",

        enterprisesByType:
            "enterprises",

        enterprisesByOwnership:
            "enterprises",

        enterprisesBySector:
            "enterprises",

        donorsByProgram:
            "donors",

        programsByStatus:
            "programs",

        projectsByStatus:
            "projects",

        activitiesByStatus:
            "activities",

        attendanceByStatus:
            "attendance",

        servicesByStatus:
            "services",

        donationsByStatus:
            "donations"

    };

    const preferredField =
        fieldMap[chartKey];

    if (
        preferredField &&
        row[preferredField] !== undefined &&
        row[preferredField] !== null &&
        row[preferredField] !== ""
    ) {

        const number =
            Number(
                row[
                    preferredField
                ]
            );

        if (
            !Number.isNaN(
                number
            )
        ) {

            return number;

        }

    }

    const genericFields = [

        "count",
        "total",
        "value",
        "amount",

        "supportValue",
        "deliveryValue",

        "services",
        "serviceCount",

        "enrollments",
        "enrollmentCount",

        "beneficiaries",
        "beneficiaryCount",

        "attendance",

        "participants",

        "targetParticipants",

        "activities",

        "activityRuns",

        "projects",

        "enterprises",

        "donors",

        "programs",

        "donations",

        "totalAmount"

    ];

    for (
        const field of genericFields
    ) {

        if (
            field === labelField
        ) {
            continue;
        }

        const value =
            row[field];

        if (
            value === undefined ||
            value === null ||
            value === ""
        ) {
            continue;
        }

        const number =
            Number(value);

        if (
            !Number.isNaN(
                number
            )
        ) {

            return number;

        }

    }

    const numericEntry =
        Object.entries(row)
            .find(
                ([key, value]) => {

                    if (
                        key === labelField
                    ) {
                        return false;
                    }

                    return (
                        typeof value ===
                        "number"
                    );

                }
            );

    if (numericEntry) {
        return numericEntry[1];
    }

    return null;

};


// =====================================================
// CHART ROWS
// =====================================================

const buildChartRows = (
    rows,
    chartKey
) => {

    if (!Array.isArray(rows)) {
        return [];
    }

    return rows
        .map(
            (
                row,
                index
            ) => {

                if (
                    !isObject(row)
                ) {
                    return null;
                }

                const labelData =
                    getLabelField(
                        row
                    );

                let label =
                    labelData
                        ? labelData.value
                        : `Item ${index + 1}`;

                let value =
                    getNumericField(
                        row,
                        chartKey,
                        labelData
                            ? labelData.field
                            : null
                    );

                if (
                    value === null
                ) {

                    const objectValue =
                        getObjectNumericValue(
                            row
                        );

                    if (
                        objectValue !== null
                    ) {

                        value =
                            objectValue;

                    }

                }

                if (
                    value === null
                ) {

                    return null;

                }

                return {

                    label,
                    value,
                    valueField:
                        labelData
                            ? labelData.field
                            : null

                };

            }
        )
        .filter(
            Boolean
        );

};


// =====================================================
// BAR COMPONENT
// =====================================================

const ChartBar = ({
    label,
    value,
    maxValue,
    chartKey
}) => {

    const numericValue =
        Number(value) || 0;

    const numericMax =
        Number(maxValue) || 0;

    const width =
        numericMax > 0
            ? Math.min(
                100,
                Math.max(
                    0,
                    (
                        Math.abs(
                            numericValue
                        ) /
                        numericMax
                    ) * 100
                )
            )
            : 0;

    return (
        <Box
            sx={{
                mb: 2
            }}
        >

            <Box
                sx={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 2,
                    mb: 0.75
                }}
            >

                <Typography
                    variant="body2"
                    sx={{
                        fontWeight: 500,
                        minWidth: 0,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap"
                    }}
                    title={label}
                >
                    {label}
                </Typography>

                <Typography
                    variant="body2"
                    sx={{
                        fontWeight: 700,
                        whiteSpace: "nowrap"
                    }}
                >
                    {
                        formatChartValue(
                            numericValue,
                            chartKey
                        )
                    }
                </Typography>

            </Box>

            <Box
                sx={{
                    width: "100%",
                    height: 8,
                    borderRadius: 4,
                    backgroundColor:
                        "action.hover",
                    overflow: "hidden"
                }}
            >

                <Box
                    sx={{
                        width: `${width}%`,
                        height: "100%",
                        borderRadius: 4,
                        backgroundColor:
                            "primary.main",
                        transition:
                            "width 0.3s ease"
                    }}
                />

            </Box>

        </Box>
    );

};


// =====================================================
// CHART BLOCK
// =====================================================

const ChartBlock = ({
    title,
    rows,
    chartKey
}) => {

    const chartRows =
        buildChartRows(
            rows,
            chartKey
        );

    if (
        chartRows.length === 0
    ) {

        return null;

    }

    const maxValue =
        Math.max(
            ...chartRows.map(
                row =>
                    Math.abs(
                        Number(
                            row.value
                        ) || 0
                    )
            ),
            0
        );

    return (
        <Box
            sx={{
                height: "100%",
                border: 1,
                borderColor:
                    "divider",
                borderRadius: 2,
                p: 2.5,
                backgroundColor:
                    "background.paper"
            }}
        >

            <Typography
                variant="subtitle1"
                sx={{
                    fontWeight: 700,
                    mb: 2.5
                }}
            >
                {title}
            </Typography>

            <Box>

                {
                    chartRows.map(
                        (
                            row,
                            index
                        ) => (

                            <ChartBar
                                key={`${chartKey}-${row.label}-${index}`}
                                label={row.label}
                                value={row.value}
                                maxValue={maxValue}
                                chartKey={chartKey}
                            />

                        )
                    )
                }

            </Box>

        </Box>
    );

};


// =====================================================
// MAIN COMPONENT
// =====================================================

const ReportCharts = ({
    charts
}) => {

    if (
        !charts ||
        typeof charts !== "object"
    ) {

        return null;

    }

    const availableCharts =
        Object.entries(
            charts
        ).filter(
            ([, rows]) =>
                Array.isArray(rows) &&
                rows.length > 0
        );

    if (
        availableCharts.length === 0
    ) {

        return null;

    }

    return (

        <FormSection
            title="Charts"
        >

            <Grid
                container
                spacing={2.5}
            >

                {
                    availableCharts.map(
                        (
                            [
                                chartKey,
                                rows
                            ]
                        ) => (

                            <Grid
                                size={{ xs: 12, md: 6 }}
                                key={chartKey}
                            >

                                <ChartBlock
                                    title={
                                        formatLabel(
                                            chartKey
                                        )
                                    }
                                    rows={rows}
                                    chartKey={
                                        chartKey
                                    }
                                />

                            </Grid>

                        )
                    )
                }

            </Grid>

        </FormSection>

    );

};


export default ReportCharts;