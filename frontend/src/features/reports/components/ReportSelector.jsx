import {
    FormControl,
    InputLabel,
    MenuItem,
    Select
} from "@mui/material";

const getReportKey = (report) => {
    if (typeof report === "string") {
        return report;
    }

    return (
        report?.key ||
        report?.name ||
        report?.reportName ||
        ""
    );
};

const getReportLabel = (report) => {
    if (typeof report === "string") {
        return report;
    }

    return (
        report?.label ||
        report?.title ||
        report?.name ||
        report?.reportName ||
        report?.key ||
        ""
    );
};

const ReportSelector = ({
    reports = [],
    value = "",
    onChange,
    disabled = false
}) => {
    const reportList = Array.isArray(reports)
        ? reports
        : [];

    return (
        <FormControl
            fullWidth
            size="small"
            disabled={
                disabled ||
                reportList.length === 0
            }
        >
            <InputLabel id="report-selector-label">
                Report
            </InputLabel>

            <Select
                labelId="report-selector-label"
                id="report-selector"
                value={value || ""}
                label="Report"
                onChange={(event) => {
                    if (typeof onChange === "function") {
                        onChange(
                            event.target.value
                        );
                    }
                }}
            >
                {reportList.length === 0 ? (
                    <MenuItem
                        value=""
                        disabled
                    >
                        No reports available
                    </MenuItem>
                ) : (
                    reportList.map(
                        (report, index) => {
                            const key =
                                getReportKey(
                                    report
                                );

                            const label =
                                getReportLabel(
                                    report
                                );

                            if (!key) {
                                return null;
                            }

                            return (
                                <MenuItem
                                    key={`${key}-${index}`}
                                    value={key}
                                >
                                    {label}
                                </MenuItem>
                            );
                        }
                    )
                )}
            </Select>
        </FormControl>
    );
};

export default ReportSelector;
