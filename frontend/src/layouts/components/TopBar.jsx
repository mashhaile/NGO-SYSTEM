import {
    AppBar,
    Toolbar,
    Typography,
    Box,
    IconButton,
    Menu,
    MenuItem,
    Avatar,
    Divider,
    Tooltip
} from "@mui/material";

import {
    Logout,
    LockReset,
    Menu as MenuIcon
} from "@mui/icons-material";

import {
    useState
} from "react";

import {
    useDispatch,
    useSelector
} from "react-redux";

import {
    useNavigate
} from "react-router-dom";

import {
    logoutThunk,
    selectUser
} from "../../features/auth/store";

import NotificationBell from "./NotificationBell";


const GREEN = "#166534";
const GREEN_DARK = "#14532d";


const TopBar = ({
    onMenuClick
}) => {

    const dispatch =
        useDispatch();

    const navigate =
        useNavigate();

    const user =
        useSelector(selectUser);


    const [
        anchorEl,
        setAnchorEl
    ] = useState(null);


    /* ======================================================
       USER MENU
    ====================================================== */

    const handleUserMenu = (event) => {

        setAnchorEl(
            event.currentTarget
        );

    };


    const handleClose = () => {

        setAnchorEl(null);

    };


    /* ======================================================
       LOGOUT
    ====================================================== */

    const handleLogout = async () => {

        handleClose();

        await dispatch(
            logoutThunk()
        );

        navigate(
            "/login",
            {
                replace: true
            }
        );

    };


    /* ======================================================
       USER DISPLAY
    ====================================================== */

    const userName =
        user?.name || "User";

    const userRole =
        user?.role || "";


    const initials =
        userName
            .split(" ")
            .filter(Boolean)
            .map(
                name =>
                    name.charAt(0)
            )
            .join("")
            .substring(0, 2)
            .toUpperCase();


    return (
        <AppBar

            position="fixed"

            color="inherit"

            elevation={0}

            sx={{

                zIndex:
                    theme =>
                        theme.zIndex.drawer + 1,

                backgroundColor:
                    "rgba(255,255,255,0.96)",

                backdropFilter:
                    "blur(10px)",

                borderBottom:
                    "1px solid",

                borderColor:
                    "divider",

                color:
                    "text.primary"

            }}

        >

            <Toolbar

                sx={{

                    minHeight: {
                        xs: 64,
                        sm: 72
                    },

                    px: {
                        xs: 1.5,
                        sm: 2.5,
                        md: 3
                    },

                    gap: 1

                }}

            >

                {/* ==================================================
                    MOBILE MENU
                ================================================== */}

                <IconButton

                    onClick={
                        onMenuClick
                    }

                    sx={{

                        display: {
                            xs: "flex",
                            md: "none"
                        },

                        mr: 0.5,

                        color:
                            "text.primary"

                    }}

                >

                    <MenuIcon />

                </IconButton>


                {/* ==================================================
                    PAGE BRAND / TITLE
                ================================================== */}

                <Box
                    sx={{
                        minWidth: 0,
                        flexGrow: 1
                    }}
                >

                    <Typography

                        sx={{

                            fontSize: {
                                xs: "0.95rem",
                                sm: "1rem"
                            },

                            fontWeight: 700,

                            color:
                                GREEN_DARK,

                            lineHeight: 1.2,

                            whiteSpace:
                                "nowrap",

                            overflow:
                                "hidden",

                            textOverflow:
                                "ellipsis"

                        }}

                    >

                        NGO Management System

                    </Typography>


                    <Typography

                        variant="caption"

                        sx={{

                            display: {
                                xs: "none",
                                sm: "block"
                            },

                            color:
                                "text.secondary",

                            mt: 0.2

                        }}

                    >

                        Organization Management Platform

                    </Typography>

                </Box>


                {/* ==================================================
                    NOTIFICATIONS
                ================================================== */}

                <NotificationBell />


                {/* ==================================================
                    USER AREA
                ================================================== */}

                <Box
                    sx={{

                        display:
                            "flex",

                        alignItems:
                            "center",

                        ml: {
                            xs: 0.25,
                            sm: 1
                        }

                    }}
                >

                    {/* USER DETAILS */}

                    <Box
                        sx={{

                            display: {
                                xs: "none",
                                md: "block"
                            },

                            textAlign:
                                "right",

                            mr: 1.25,

                            minWidth: 0

                        }}
                    >

                        <Typography

                            variant="body2"

                            sx={{

                                fontWeight:
                                    700,

                                lineHeight:
                                    1.25,

                                whiteSpace:
                                    "nowrap",

                                maxWidth:
                                    180,

                                overflow:
                                    "hidden",

                                textOverflow:
                                    "ellipsis"

                            }}

                        >

                            {userName}

                        </Typography>


                        <Typography

                            variant="caption"

                            sx={{

                                color:
                                    "text.secondary",

                                whiteSpace:
                                    "nowrap"

                            }}

                        >

                            {userRole}

                        </Typography>

                    </Box>


                    {/* AVATAR */}

                    <Tooltip
                        title="Account"
                    >

                        <IconButton

                            onClick={
                                handleUserMenu
                            }

                            sx={{
                                p: 0
                            }}

                        >

                            <Avatar

                                sx={{

                                    width: {
                                        xs: 36,
                                        sm: 40
                                    },

                                    height: {
                                        xs: 36,
                                        sm: 40
                                    },

                                    backgroundColor:
                                        GREEN,

                                    color:
                                        "#ffffff",

                                    fontSize:
                                        "0.85rem",

                                    fontWeight:
                                        700,

                                    boxShadow:
                                        "0 0 0 3px #f0fdf4"

                                }}

                            >

                                {initials}

                            </Avatar>

                        </IconButton>

                    </Tooltip>

                </Box>


                {/* ==================================================
                    USER MENU
                ================================================== */}

                <Menu

                    anchorEl={
                        anchorEl
                    }

                    open={
                        Boolean(anchorEl)
                    }

                    onClose={
                        handleClose
                    }

                    slotProps={{

                        paper: {

                            elevation: 4,

                            sx: {

                                mt: 1,

                                minWidth: 230,

                                borderRadius: 2,

                                border:
                                    "1px solid",

                                borderColor:
                                    "divider"

                            }

                        }

                    }}

                    anchorOrigin={{

                        vertical:
                            "bottom",

                        horizontal:
                            "right"

                    }}

                    transformOrigin={{

                        vertical:
                            "top",

                        horizontal:
                            "right"

                    }}

                >

                    {/* PROFILE */}

                    <Box
                        sx={{

                            px: 2,

                            py: 1.5

                        }}
                    >

                        <Box
                            sx={{

                                display:
                                    "flex",

                                alignItems:
                                    "center",

                                gap: 1.25

                            }}
                        >

                            <Avatar

                                sx={{

                                    width: 38,

                                    height: 38,

                                    backgroundColor:
                                        GREEN,

                                    fontSize:
                                        "0.8rem",

                                    fontWeight:
                                        700

                                }}

                            >

                                {initials}

                            </Avatar>


                            <Box
                                sx={{
                                    minWidth: 0
                                }}
                            >

                                <Typography

                                    variant="body2"

                                    sx={{

                                        fontWeight:
                                            700,

                                        whiteSpace:
                                            "nowrap",

                                        overflow:
                                            "hidden",

                                        textOverflow:
                                            "ellipsis"

                                    }}

                                >

                                    {userName}

                                </Typography>


                                <Typography
                                    variant="caption"
                                    sx={{
                                        color: "text.secondary",

                                        display:
                                            "block",

                                        maxWidth:
                                            160,

                                        whiteSpace:
                                            "nowrap",

                                        overflow:
                                            "hidden",

                                        textOverflow:
                                            "ellipsis"
                                    }}>

                                    {user?.email}

                                </Typography>

                            </Box>

                        </Box>

                    </Box>


                    <Divider />


                    {/* CHANGE PASSWORD */}

                    <MenuItem

                        onClick={() => {
                            handleClose();
                            navigate("/account/password");
                        }}

                        sx={{
                            py: 1.25
                        }}

                    >

                        <LockReset

                            fontSize="small"

                            sx={{
                                mr: 1.25
                            }}

                        />

                        Change Password

                    </MenuItem>


                    {/* LOGOUT */}

                    <MenuItem

                        onClick={
                            handleLogout
                        }

                        sx={{

                            py: 1.25,

                            color:
                                "error.main",

                            "&:hover": {

                                backgroundColor:
                                    "#fef2f2"

                            }

                        }}

                    >

                        <Logout

                            fontSize="small"

                            sx={{
                                mr: 1.25
                            }}

                        />

                        Logout

                    </MenuItem>

                </Menu>

            </Toolbar>

        </AppBar>
    );

};


export default TopBar;