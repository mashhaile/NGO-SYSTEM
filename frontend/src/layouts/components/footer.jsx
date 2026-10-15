import {
    Box,
    Typography,
    Stack
} from "@mui/material";


const Footer = () => {

    const currentYear =
        new Date().getFullYear();


    return (

        <Box
            component="footer"
            sx={{

                px: {
                    xs: 2,
                    sm: 3,
                    md: 4
                },

                py: 2,

                mt: "auto",

                borderTop:
                    "1px solid",

                borderColor:
                    "divider",

                backgroundColor:
                    "background.paper"

            }}
        >

            <Stack

                direction={{
                    xs: "column",
                    sm: "row"
                }}

                spacing={1}

                alignItems={{
                    xs: "center",
                    sm: "center"
                }}

                justifyContent="space-between"

            >

                {/* ==================================================
                    BRAND
                ================================================== */}

                <Typography

                    variant="caption"

                    sx={{

                        color:
                            "text.secondary",

                        fontWeight:
                            500

                    }}

                >

                    NGO SaaS Platform

                </Typography>


                {/* ==================================================
                    COPYRIGHT
                ================================================== */}

                <Typography

                    variant="caption"

                    sx={{

                        color:
                            "text.disabled",

                        textAlign:
                            "center"

                    }}

                >

                    © {currentYear} NGO Management SaaS Platform

                </Typography>


                {/* ==================================================
                    VERSION
                ================================================== */}

                <Typography

                    variant="caption"

                    sx={{

                        color:
                            "text.disabled",

                        display: {
                            xs: "none",
                            md: "block"
                        }

                    }}

                >

                    Management System

                </Typography>

            </Stack>

        </Box>

    );

};


export default Footer;
