import {
    Box
} from "@mui/material";


const PageContainer = ({
    children,

    maxWidth = 1800,

    sx = {}
}) => {

    return (

        <Box
            component="main"

            sx={{
                width: "100%",

                maxWidth,

                mx: "auto",

                px: {
                    xs: 1.5,
                    sm: 2,
                    md: 3
                },

                pb: {
                    xs: 3,
                    sm: 4,
                    md: 5
                },

                ...sx
            }}
        >

            {children}

        </Box>

    );

};


export default PageContainer;