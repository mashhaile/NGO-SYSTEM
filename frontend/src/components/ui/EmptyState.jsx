import {
    Box,
    CircularProgress,
    Typography
} from "@mui/material";


const LoadingState = ({
    message = "Loading...",
    minHeight = 240
}) => {

    return (
        <Box
            sx={{
                minHeight,

                display: "flex",
                flexDirection: "column",

                alignItems: "center",
                justifyContent: "center",

                gap: 1.5
            }}
        >

            <CircularProgress
                size={32}
                thickness={4}
            />

            <Typography
                variant="body2"
                color="text.secondary"
            >
                {message}
            </Typography>

        </Box>
    );
};


export default LoadingState;