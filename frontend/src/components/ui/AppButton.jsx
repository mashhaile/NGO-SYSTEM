import { useTerm } from "../../utils/terms";
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

    // in the organization's own words (Settings > Wording)
    const term = useTerm();
    children = typeof children === "string" ? term(children) : children;


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