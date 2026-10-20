import {
    Box,
    Typography
} from "@mui/material";

const InfoRow = ({
    label,
    value,
    direction = "row",
    emptyValue = "-",
    labelWidth = 180,
    sx = {}
}) => {
    const displayValue =
        value === null ||
        value === undefined ||
        value === ""
            ? emptyValue
            : value;

    return (
        <Box
            sx={{
                display: "flex",
                flexDirection: {
                    xs: "column",
                    sm: direction === "row"
                        ? "row"
                        : "column"
                },
                gap: {
                    xs: 0.5,
                    sm: direction === "row"
                        ? 2
                        : 0.5
                },
                py: 1.25,
                borderBottom: "1px solid",
                borderColor: "divider",
                ...sx
            }}
        >
            <Typography
                variant="body2"
                sx={{
                    color: "text.secondary",
                    fontWeight: 600,

                    width:
                        direction === "row"
                            ? labelWidth
                            : "auto",

                    flexShrink: 0
                }}>
                {label}
            </Typography>

            <Typography
                variant="body2"
                component="div"
                sx={{
                    color: "text.primary",
                    flex: 1,
                    minWidth: 0,
                    wordBreak: "break-word"
                }}>
                {displayValue}
            </Typography>
        </Box>
    );
};

export default InfoRow;