import {
    Box,
    Button,
    Typography
} from "@mui/material";

import {
    Error
} from "@mui/icons-material";


const ErrorState = ({
    title = "Something went wrong",

    message =
        "We couldn't load the requested data.",

    action,
    actionLabel = "Try Again"
}) => {

    return (
        <Box
            sx={{
                minHeight: 260,
                px: 3,

                display: "flex",
                flexDirection: "column",

                alignItems: "center",
                justifyContent: "center",

                textAlign: "center"
            }}
        >

            <Box
                sx={{
                    width: 52,
                    height: 52,
                    mb: 2,

                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",

                    borderRadius: 2.5,

                    bgcolor: "error.light",
                    color: "error.main"
                }}
            >
                <ErrorOutline />
            </Box>


            <Typography
                variant="h6"
                fontWeight={700}
            >
                {title}
            </Typography>


            <Typography
                color="text.secondary"
                sx={{
                    mt: 0.75,
                    maxWidth: 500
                }}
            >
                {message}
            </Typography>


            {action && (
                <Button
                    variant="outlined"
                    sx={{ mt: 2 }}
                    onClick={action}
                >
                    {actionLabel}
                </Button>
            )}

        </Box>
    );
};


export default ErrorState;