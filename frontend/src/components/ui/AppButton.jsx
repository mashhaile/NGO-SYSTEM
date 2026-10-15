import {
    Button
} from "@mui/material";


const AppButton = ({
    children,

    variant = "contained",
    size = "medium",

    loading = false,

    loadingText = "Processing...",

    disabled = false,

    startIcon,
    endIcon,

    fullWidth = false,

    ...props
}) => {

    return (
        <Button
            variant={variant}
            size={size}

            disabled={
                disabled ||
                loading
            }

            startIcon={
                loading
                    ? undefined
                    : startIcon
            }

            endIcon={
                loading
                    ? undefined
                    : endIcon
            }

            fullWidth={fullWidth}

            {...props}
        >
            {loading
                ? loadingText
                : children}
        </Button>
    );
};


export default AppButton;