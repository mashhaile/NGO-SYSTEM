import {
    useState
} from "react";

import {
    Box,
    CssBaseline,
    useMediaQuery,
    useTheme
} from "@mui/material";

import {
    Outlet
} from "react-router-dom";

import Sidebar
    from "./Sidebar";

import TopBar
    from "./TopBar";

import Footer
    from "./footer";


export const DRAWER_WIDTH = 260;


const DashboardLayout = () => {

    const theme =
        useTheme();


    const isMobile =
        useMediaQuery(
            theme.breakpoints.down("md")
        );


    const [
        mobileOpen,
        setMobileOpen
    ] = useState(false);


    // ======================================================
    // MOBILE SIDEBAR
    // ======================================================

    const handleDrawerToggle = () => {

        setMobileOpen(
            previous =>
                !previous
        );

    };


    const handleMobileClose = () => {

        if (isMobile) {

            setMobileOpen(false);

        }

    };


    return (

        <Box
            sx={{
                display: "flex",
                minHeight: "100vh",
                backgroundColor:
                    "background.default"
            }}
        >

            <CssBaseline />


            {/* ==================================================
                SIDEBAR
            ================================================== */}

            <Sidebar

                mobileOpen={
                    mobileOpen
                }

                onMobileClose={
                    handleMobileClose
                }

            />


            {/* ==================================================
                MAIN APPLICATION
            ================================================== */}

            <Box
                sx={{
                    flexGrow: 1,
                    minWidth: 0,

                    display: "flex",
                    flexDirection: "column",

                    minHeight: "100vh"
                }}
            >


                {/* ==================================================
                    TOP BAR
                ================================================== */}

                <TopBar
                    onMenuClick={
                        handleDrawerToggle
                    }
                />


                {/* ==================================================
                    PAGE CONTENT
                ================================================== */}

                <Box
                    component="main"
                    sx={{

                        flexGrow: 1,

                        width: "100%",

                        minWidth: 0,

                        boxSizing: "border-box",

                        px: {
                            xs: 2,
                            sm: 3,
                            md: 3,
                            lg: 3,
                            xl: 4
                        },

                        pb: {
                            xs: 3,
                            sm: 4,
                            lg: 5
                        }

                    }}
                >


                    {/* ==================================================
                        TOP BAR SPACER

                        Keeps page title/content below
                        the fixed TopBar.
                    ================================================== */}

                    <Box
                        sx={{
                            height: {
                                xs: 64,
                                sm: 72
                            }
                        }}
                    />


                    {/* ==================================================
                        PAGE CONTAINER
                    ================================================== */}

                    <Box
                        sx={{
                            width: "100%",

                            maxWidth:
                                "1800px",

                            mx: "auto"
                        }}
                    >

                        <Outlet />

                    </Box>

                </Box>


                {/* ==================================================
                    FOOTER
                ================================================== */}

                <Footer />

            </Box>

        </Box>

    );

};


export default DashboardLayout;
