import React from "react";

import {
    Box,
    Chip,
    Divider,
    Grid,
    Stack,
    Typography
} from "@mui/material";


/* =========================================================
   BASIC VALUE HELPERS
========================================================= */

export const formatNumber = (
    value,
    options = {}
) => {
    const {
        minimumFractionDigits = 0,
        maximumFractionDigits = 2
    } = options;

    if (
        value === null ||
        value === undefined ||
        value === "" ||
        Number.isNaN(Number(value))
    ) {
        return "0";
    }

    return new Intl.NumberFormat("en-US", {
        minimumFractionDigits,
        maximumFractionDigits
    }).format(Number(value));
};


export const formatCurrency = (
    value,
    currency = "ETB"
) => {
    if (
        value === null ||
        value === undefined ||
        value === "" ||
        Number.isNaN(Number(value))
    ) {
        return `${currency} 0.00`;
    }

    const formatted = new Intl.NumberFormat("en-US", {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
    }).format(Number(value));

    return `${currency} ${formatted}`;
};


export const formatDate = (
    value,
    fallback = "—"
) => {
    if (!value) {
        return fallback;
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return fallback;
    }

    return new Intl.DateTimeFormat("en-GB", {
        day: "2-digit",
        month: "short",
        year: "numeric"
    }).format(date);
};


export const formatValue = (
    value,
    fallback = "—"
) => {
    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return fallback;
    }

    if (typeof value === "boolean") {
        return value ? "Yes" : "No";
    }

    if (Array.isArray(value)) {
        if (!value.length) {
            return fallback;
        }

        return value
            .map((item) => formatValue(item, ""))
            .filter(Boolean)
            .join(", ");
    }

    if (typeof value === "object") {
        return (
            value.name ??
            value.label ??
            value.displayName ??
            value.title ??
            value.value ??
            value.description ??
            value.code ??
            value._id ??
            value.id ??
            fallback
        );
    }

    return String(value);
};


/* =========================================================
   LOOKUP HELPERS
========================================================= */

export const getLookupDisplayValue = (
    value,
    fallback = "—"
) => {
    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return fallback;
    }

    if (typeof value === "string") {
        return value;
    }

    if (typeof value === "number") {
        return String(value);
    }

    if (typeof value === "object") {
        return (
            value.name ??
            value.label ??
            value.displayName ??
            value.title ??
            value.value ??
            value.description ??
            value.code ??
            value.programName ??
            value.projectName ??
            value.activityName ??
            value.activityRunName ??
            value._id ??
            value.id ??
            fallback
        );
    }

    return fallback;
};


/* =========================================================
   ENTITY DISPLAY COMPONENTS
========================================================= */

const EntityDisplay = ({
    value,
    fallback = "—"
}) => {
    const displayValue =
        getLookupDisplayValue(
            value,
            fallback
        );

    return (
        <Typography
            variant="body2"
            sx={{
                wordBreak: "break-word"
            }}
        >
            {displayValue}
        </Typography>
    );
};


export const ProgramDisplay = ({
    program,
    value,
    fallback = "—"
}) => {
    return (
        <EntityDisplay
            value={
                program ??
                value
            }
            fallback={fallback}
        />
    );
};


export const ProjectDisplay = ({
    project,
    value,
    fallback = "—"
}) => {
    return (
        <EntityDisplay
            value={
                project ??
                value
            }
            fallback={fallback}
        />
    );
};


export const ActivityDisplay = ({
    activity,
    value,
    fallback = "—"
}) => {
    return (
        <EntityDisplay
            value={
                activity ??
                value
            }
            fallback={fallback}
        />
    );
};


export const ActivityRunDisplay = ({
    activityRun,
    value,
    fallback = "—"
}) => {
    return (
        <EntityDisplay
            value={
                activityRun ??
                value
            }
            fallback={fallback}
        />
    );
};


/* =========================================================
   DETAIL FIELD
========================================================= */

export const DetailField = ({
    label,
    value,
    children,
    currency = false,
    status = false,
    xs,
    sm,
    md,
    valueSx = {}
}) => {
    let content;

    if (children !== undefined) {
        content = children;
    } else if (status) {
        content = (
            <StatusValue
                value={value}
            />
        );
    } else if (currency) {
        content = formatCurrency(value);
    } else {
        content = formatValue(value);
    }

    return (
        <Grid
            item
            xs={xs}
            sm={sm}
            md={md}
        >
            <Box>
                <Typography
                    variant="caption"
                    color="text.secondary"
                    sx={{
                        display: "block",
                        mb: 0.5,
                        fontWeight: 600
                    }}
                >
                    {label}
                </Typography>

                {typeof content === "string" ||
                typeof content === "number" ? (
                    <Typography
                        variant="body2"
                        sx={{
                            wordBreak: "break-word",
                            ...valueSx
                        }}
                    >
                        {content}
                    </Typography>
                ) : (
                    <Box sx={valueSx}>
                        {content}
                    </Box>
                )}
            </Box>
        </Grid>
    );
};


/* =========================================================
   DETAIL GRID
========================================================= */

export const DetailGrid = ({
    children,
    spacing = 2,
    columns = {}
}) => {
    const {
        xs = 1,
        sm = 2,
        md = 4
    } = columns;

    const getGridSpan = (count) => {
        if (!count || count <= 0) {
            return undefined;
        }

        return Math.max(
            1,
            Math.floor(12 / count)
        );
    };

    const childrenWithLayout =
        React.Children.map(
            children,
            (child) => {
                if (
                    !React.isValidElement(child)
                ) {
                    return child;
                }

                return React.cloneElement(
                    child,
                    {
                        xs:
                            child.props.xs ??
                            getGridSpan(xs),

                        sm:
                            child.props.sm ??
                            getGridSpan(sm),

                        md:
                            child.props.md ??
                            getGridSpan(md)
                    }
                );
            }
        );

    return (
        <Grid
            container
            spacing={spacing}
        >
            {childrenWithLayout}
        </Grid>
    );
};


/* =========================================================
   SECTION HEADER
========================================================= */

export const SectionHeader = ({
    title,
    subtitle,
    action,
    divider = true
}) => {
    return (
        <Box sx={{ mb: 2 }}>
            <Stack
                direction={{
                    xs: "column",
                    sm: "row"
                }}
                spacing={1}
                alignItems={{
                    xs: "flex-start",
                    sm: "center"
                }}
                justifyContent="space-between"
            >
                <Box>
                    <Typography
                        variant="h6"
                        sx={{
                            fontWeight: 700
                        }}
                    >
                        {title}
                    </Typography>

                    {subtitle && (
                        <Typography
                            variant="body2"
                            color="text.secondary"
                            sx={{
                                mt: 0.25
                            }}
                        >
                            {subtitle}
                        </Typography>
                    )}
                </Box>

                {action && (
                    <Box>
                        {action}
                    </Box>
                )}
            </Stack>

            {divider && (
                <Divider
                    sx={{
                        mt: 1.5
                    }}
                />
            )}
        </Box>
    );
};


/* =========================================================
   EMPTY STATE
========================================================= */

export const EmptyState = ({
    title = "No data available",
    message,
    minHeight = 120
}) => {
    return (
        <Box
            sx={{
                minHeight,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                textAlign: "center",
                px: 2,
                py: 3
            }}
        >
            <Box>
                <Typography
                    variant="subtitle1"
                    sx={{
                        fontWeight: 600
                    }}
                >
                    {title}
                </Typography>

                {message && (
                    <Typography
                        variant="body2"
                        color="text.secondary"
                        sx={{
                            mt: 0.5
                        }}
                    >
                        {message}
                    </Typography>
                )}
            </Box>
        </Box>
    );
};


/* =========================================================
   STATUS DISPLAY
========================================================= */

const normalizeStatus = (
    status
) => {
    if (
        status === null ||
        status === undefined ||
        status === ""
    ) {
        return "";
    }

    if (typeof status === "object") {
        return String(
            status.name ??
            status.label ??
            status.displayName ??
            status.value ??
            status.code ??
            ""
        );
    }

    return String(status);
};


const getStatusColor = (
    status
) => {
    const normalized =
        normalizeStatus(status)
            .trim()
            .toLowerCase()
            .replace(/[_-]/g, " ");

    if (
        [
            "delivered",
            "completed",
            "complete",
            "active",
            "approved",
            "success",
            "successful",
            "fully allocated",
            "fully allocated"
        ].includes(normalized)
    ) {
        return "success";
    }

    if (
        [
            "pending",
            "partially allocated",
            "partial",
            "in progress",
            "processing"
        ].includes(normalized)
    ) {
        return "warning";
    }

    if (
        [
            "cancelled",
            "canceled",
            "rejected",
            "failed",
            "inactive",
            "deleted",
            "over allocated",
            "overallocated"
        ].includes(normalized)
    ) {
        return "error";
    }

    if (
        [
            "not allocated",
            "unallocated",
            "draft"
        ].includes(normalized)
    ) {
        return "default";
    }

    return "default";
};


export const StatusValue = ({
    value,
    status,
    label,
    size = "small"
}) => {
    const actualStatus =
        value ??
        status;

    const displayValue =
        label ??
        normalizeStatus(actualStatus);

    if (!displayValue) {
        return (
            <Typography
                variant="body2"
                color="text.secondary"
            >
                —
            </Typography>
        );
    }

    return (
        <Chip
            label={displayValue}
            color={getStatusColor(actualStatus)}
            size={size}
            variant="outlined"
        />
    );
};


/* =========================================================
   DEFAULT EXPORT
========================================================= */

export default {
    formatDate,
    formatNumber,
    formatCurrency,
    formatValue,
    getLookupDisplayValue,
    ProgramDisplay,
    ProjectDisplay,
    ActivityDisplay,
    ActivityRunDisplay,
    DetailField,
    DetailGrid,
    SectionHeader,
    EmptyState,
    StatusValue
};