import {
    Alert,
    AlertTitle
} from "@mui/material";

const AppAlert = ({
    severity = "info",
    title,
    children,
    // many pages pass the text as message="..."
    message,
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

            {children ?? message}
        </Alert>
    );
};

export default AppAlert;