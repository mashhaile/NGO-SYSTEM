import {
    Box
} from "@mui/material";


const ActionToolbar = ({
    children
}) => {

    return (
        <Box
            sx={{
                display: "flex",
                alignItems: "center",
                gap: 2,
                flexWrap: "wrap"
            }}
        >
            {children}
        </Box>
    );
};


export default ActionToolbar;