import {
    Alert,
    AlertTitle
} from "@mui/material";

const AppAlert = ({
    severity = "info",
    title,
    children,
    action,
    variant = "standard",
    sx = {},
    ...props
}) => {
    return (
        <Alert
            severity={severity}
            variant={variant}
            action={action}
            sx={{
                borderRadius: 2,
                alignItems: "flex-start",
                ...sx
            }}
            {...props}
        >
            {title && (
                <AlertTitle
                    sx={{
                        fontWeight: 700
                    }}
                >
                    {title}
                </AlertTitle>
            )}

            {children}
        </Alert>
    );
};

export default AppAlert;