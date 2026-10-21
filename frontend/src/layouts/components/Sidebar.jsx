import {
    Drawer,
    List,
    ListItemButton,
    ListItemIcon,
    ListItemText,
    Typography,
    Box,
    Collapse,
    Divider,
    IconButton,
    Select,
    MenuItem,
    FormControl
} from "@mui/material";


import {
    Dashboard,
    People,
    Folder,
    Assignment,
    Assessment,
    EventNote,
    EventAvailable,
    Description,
    FactCheck,
    VolunteerActivism,
    AccountBalance,
    Settings,
    LocalShipping,
    ManageSearch,
    Business,
    ManageAccounts,
    Tune,
    ExpandLess,
    ExpandMore,
    Close,
    AdminPanelSettings,
    Apartment,
    Payments,
    CardMembership,
    Storefront,
    Savings,
    AddBusiness,
    Group
} from "@mui/icons-material";


import {
    NavLink,
    useLocation
} from "react-router-dom";


import {
    useEffect,
    useState
} from "react";


import {
    useDispatch,
    useSelector
} from "react-redux";


import useAuth
    from "../../features/auth/hooks/useAuth";


import PERMISSIONS
    from "../../constants/permissions";


import {
    getOrganizationsApi
} from "../../features/superadmin/api/organizationApi";

import {
    setOrganizationContext,
    selectSelectedOrganizationId
} from "../../features/superadmin/store/organizationContextSlice";


import {
    DRAWER_WIDTH
} from "./DashboardLayout";



/* ==========================================================
   COLORS
========================================================== */

const GREEN = "#166534";
const GREEN_DARK = "#14532d";
const GREEN_LIGHT = "#f0fdf4";
const GREEN_HOVER = "#f0fdf4";



/* ==========================================================
   MAIN NAVIGATION
========================================================== */

const menuItems = [

    {
        label: "Dashboard",
        path: "/dashboard",
        icon: <Dashboard />
    },

    {
        label: "Beneficiaries",
        path: "/beneficiaries",
        icon: <People />,
        permission: "beneficiary.read"
    },

    {
        label: "Programs",
        path: "/programs",
        icon: <Folder />,
        permission: "program.read"
    },

    {
        label: "Projects",
        path: "/projects",
        icon: <Assignment />,
        permission: "project.read"
    },

    {
        label: "Activities",
        path: "/activities",
        icon: <EventNote />,
        permission: "activity.read"
    },

    {
        label: "Activity Runs",
        path: "/activity-runs",
        icon: <EventAvailable />,
        permission: "activity_run.read"
    },

    {
        label: "Terms of Reference",
        path: "/tors",
        icon: <Description />,
        permission: "tor.read"
    },

    {
        label: "Attendance",
        path: "/attendance",
        icon: <FactCheck />,
        permission: "attendance.read"
    },

    {
        label: "Enrollments",
        path: "/enrollments",
        icon: <People />,
        permission: "enrollment.read"
    },

    {
        label: "Service Delivery",
        path: "/service-deliveries",
        icon: <LocalShipping />,
        permission: "service.read"
    },

    {
        label: "Donors",
        path: "/donors",
        icon: <VolunteerActivism />,
        permission: "donor.read"
    },

    {
        label: "Donations",
        path: "/donations",
        icon: <AccountBalance />,
        permission: "donation.read"
    },

    {
        label: "Budgets",
        path: "/budgets",
        icon: <Savings />,
        permission: "budget.read"
    },
    
    {
        label: "Reports",
        path: "/reports",
        icon: <Assessment />,
        permission: "report.read"
    }
    
];



/* ==========================================================
   ENTERPRISE NAVIGATION
========================================================== */

const enterpriseItems = [

    {
        label: "Enterprise List",
        path: "/enterprises",
        icon: <Storefront />
    },

    {
        label: "Create Enterprise",
        path: "/enterprises/create",
        icon: <AddBusiness />
    },

    {
        label: "Enterprise Members",
        path: "/enterprise-members",
        icon: <Group />
    }

];



/* ==========================================================
   ORGANIZATION SETTINGS
========================================================== */

const settingsItems = [

    {
        label: "Organization",
        path: "/settings/organization",
        icon: <Business />,
        permission:
            PERMISSIONS.ORGANIZATION_READ
    },

    {
        label: "User Management",
        path: "/users",
        icon: <ManageAccounts />,
        permission:
            PERMISSIONS.USER_READ
    },

    {
        label: "Lookup Management",
        path: "/lookups",
        icon: <ManageSearch />,
        permission:
            PERMISSIONS.LOOKUP_READ
    },

    {
        label: "Custom Fields",
        path: "/settings/custom-fields",
        icon: <Tune />,
        permission:
            PERMISSIONS.CUSTOMFIELD_READ
    }

];



/* ==========================================================
   SUPER ADMIN NAVIGATION
========================================================== */

const superAdminItems = [

    {
        label: "Super Admin Dashboard",
        path: "/superadmin",
        icon: <AdminPanelSettings />
    },

    {
        label: "Organizations",
        path: "/superadmin/organizations",
        icon: <Apartment />
    },

    {
        label: "Plans",
        path: "/superadmin/plans",
        icon: <CardMembership />
    },

    {
        label: "Subscriptions",
        path: "/superadmin/subscriptions",
        icon: <Payments />
    }

];



/* ==========================================================
   NAV ITEM STYLE
========================================================== */

const navItemSx = {

    position: "relative",

    minHeight: 44,

    px: 1.5,

    borderRadius: 1.5,

    mb: 0.35,

    color: "text.secondary",

    transition:
        "background-color 0.18s ease, color 0.18s ease",

    "&:hover": {

        backgroundColor:
            GREEN_HOVER,

        color:
            GREEN

    },

    "& .MuiListItemIcon-root": {

        minWidth: 38,

        color:
            "inherit",

        transition:
            "color 0.18s ease"

    },

    "& .MuiListItemText-primary": {

        fontSize:
            "0.88rem",

        fontWeight:
            500

    },

    "&.active": {

        backgroundColor:
            GREEN_LIGHT,

        color:
            GREEN,

        fontWeight:
            700,

        "&::before": {

            content:
                '""',

            position:
                "absolute",

            left:
                0,

            top:
                7,

            bottom:
                7,

            width:
                3,

            borderRadius:
                "0 4px 4px 0",

            backgroundColor:
                GREEN

        },

        "& .MuiListItemIcon-root": {

            color:
                GREEN

        },

        "& .MuiListItemText-primary": {

            fontWeight:
                700

        }

    }

};



/* ==========================================================
   SIDEBAR
========================================================== */

const Sidebar = ({
    mobileOpen = false,
    onMobileClose
}) => {

    const location =
        useLocation();


    const dispatch =
        useDispatch();


    const {
        user
    } = useAuth();



    /* ======================================================
       ORGANIZATION CONTEXT
    ====================================================== */

    const selectedOrganizationId =
        useSelector(
            selectSelectedOrganizationId
        );


    const [
        organizations,
        setOrganizations
    ] = useState([]);


    const [
        organizationsLoading,
        setOrganizationsLoading
    ] = useState(false);



    /* ======================================================
       USER PERMISSIONS
    ====================================================== */

    const permissions =
        user?.permissions || [];



    /* ======================================================
       SUPER ADMIN DETECTION
    ====================================================== */

    const isSuperAdmin =
        user?.role === "superadmin" ||
        user?.role === "super_admin" ||
        user?.isSuperAdmin === true ||
        user?.userType === "superadmin";



    /* ======================================================
       LOAD ORGANIZATIONS FOR SUPER ADMIN
    ====================================================== */

    useEffect(() => {

        if (!isSuperAdmin) {

            setOrganizations([]);

            return;

        }


 const loadOrganizations = async () => {

    try {

        setOrganizationsLoading(true);

        const response =
            await getOrganizationsApi();

        const data =
            response?.data;

        const organizationList =
            Array.isArray(data)
                ? data
                : Array.isArray(data?.organizations)
                    ? data.organizations
                    : [];

        setOrganizations(
            organizationList
        );

    } catch (error) {

        console.error(
            "Failed to load organizations:",
            error
        );

        setOrganizations([]);

    } finally {

        setOrganizationsLoading(false);

    }

};


        loadOrganizations();

    }, [
        isSuperAdmin
    ]);



    /* ======================================================
       ORGANIZATION CHANGE
    ====================================================== */

    const handleOrganizationChange = (
        event
    ) => {

        const organizationId =
            event.target.value;


        const organization =
            organizations.find(
                item =>
                    String(
                        item._id ||
                        item.id
                    ) ===
                    String(
                        organizationId
                    )
            );


        if (!organization) {

            return;

        }


        dispatch(
            setOrganizationContext(
                organization
            )
        );

    };



    /* ======================================================
       ENTERPRISE ACTIVE
    ====================================================== */

    const enterpriseActive =
        location.pathname.startsWith(
            "/enterprises"
        ) ||
        location.pathname.startsWith(
            "/enterprise-members"
        );



    /* ======================================================
       SETTINGS ACTIVE
    ====================================================== */

    const settingsActive =
        location.pathname.startsWith(
            "/settings"
        ) ||
        location.pathname.startsWith(
            "/users"
        ) ||
        location.pathname.startsWith(
            "/lookups"
        );



    /* ======================================================
       SUPER ADMIN ACTIVE
    ====================================================== */

    const superAdminActive =
        location.pathname.startsWith(
            "/superadmin"
        );



    /* ======================================================
       ENTERPRISE OPEN
    ====================================================== */

    const [
        enterpriseOpen,
        setEnterpriseOpen
    ] = useState(
        enterpriseActive
    );



    /* ======================================================
       SETTINGS OPEN
    ====================================================== */

    const [
        settingsOpen,
        setSettingsOpen
    ] = useState(
        settingsActive
    );



    /* ======================================================
       SUPER ADMIN OPEN
    ====================================================== */

    const [
        superAdminOpen,
        setSuperAdminOpen
    ] = useState(
        superAdminActive
    );



    /* ======================================================
       AUTO OPEN ENTERPRISE
    ====================================================== */

    useEffect(() => {

        if (enterpriseActive) {

            setEnterpriseOpen(true);

        }

    }, [
        enterpriseActive
    ]);



    /* ======================================================
       AUTO OPEN SETTINGS
    ====================================================== */

    useEffect(() => {

        if (settingsActive) {

            setSettingsOpen(true);

        }

    }, [
        settingsActive
    ]);



    /* ======================================================
       AUTO OPEN SUPER ADMIN
    ====================================================== */

    useEffect(() => {

        if (superAdminActive) {

            setSuperAdminOpen(true);

        }

    }, [
        superAdminActive
    ]);



    /* ======================================================
       VISIBLE SETTINGS
       
       SUPER ADMIN:
       Full access regardless of permissions.
       
       NORMAL USERS:
       Permission-based access.
    ====================================================== */

    const visibleSettingsItems =
        isSuperAdmin

            ? settingsItems

            : settingsItems.filter(
                item => {

                    if (!item.permission) {

                        return true;

                    }

                    return permissions.includes(
                        item.permission
                    );

                }
            );



    /* ======================================================
       VISIBLE MAIN MENU / ENTERPRISE SECTION

       Same rule as settings: show only what the user's
       role can open (a finance officer does not see
       Beneficiaries, Attendance, ...).
    ====================================================== */

    const can = (permission) =>
        isSuperAdmin ||
        !permission ||
        permissions.includes("*") ||
        permissions.includes(permission);

    const visibleMenuItems =
        menuItems.filter(item => can(item.permission));

    const canSeeEnterprises =
        can("enterprise.read");



    /* ======================================================
       NAVIGATION CLICK
    ====================================================== */

    const handleNavigation = () => {

        if (onMobileClose) {

            onMobileClose();

        }

    };



    /* ======================================================
       DRAWER CONTENT
    ====================================================== */

    const drawerContent = (

        <Box
            sx={{
                height: "100%",

                display: "flex",

                flexDirection: "column",

                backgroundColor:
                    "#ffffff"
            }}
        >

            {/* ==================================================
                BRAND
            ================================================== */}

            <Box
                sx={{
                    height: 72,

                    px: 2.25,

                    display: "flex",

                    alignItems: "center",

                    justifyContent:
                        "space-between"
                }}
            >

                <Box>

                    <Typography
                        sx={{
                            fontSize:
                                "1.15rem",

                            fontWeight:
                                800,

                            color:
                                GREEN_DARK,

                            letterSpacing:
                                "-0.025em"
                        }}
                    >
                        NGO SaaS
                    </Typography>


                    <Typography
                        variant="caption"
                        sx={{
                            fontSize:
                                "0.7rem",

                            color:
                                "text.secondary",

                            letterSpacing:
                                "0.02em"
                        }}
                    >
                        Management Platform
                    </Typography>

                </Box>


                <IconButton
                    onClick={
                        onMobileClose
                    }

                    sx={{
                        display: {
                            xs: "flex",
                            md: "none"
                        },

                        color:
                            "text.secondary"
                    }}
                >

                    <Close />

                </IconButton>

            </Box>


            <Divider />



            {/* ==================================================
                SUPER ADMIN ORGANIZATION SELECTOR
            ================================================== */}

            {
                isSuperAdmin && (

                    <Box
                        sx={{
                            px: 1.5,
                            py: 1.5,
                            borderBottom: "1px solid",
                            borderColor: "divider"
                        }}
                    >

                        <Typography
                            variant="caption"
                            sx={{
                                display: "block",
                                mb: 0.75,
                                color: "text.secondary",
                                fontWeight: 700
                            }}
                        >
                            Current Organization
                        </Typography>


                        <FormControl
                            fullWidth
                            size="small"
                        >

                            <Select

                                value={
                                    selectedOrganizationId || ""
                                }

                                onChange={
                                    handleOrganizationChange
                                }

                                displayEmpty

                                sx={{
                                    fontSize:
                                        "0.82rem",

                                    borderRadius:
                                        1.5
                                }}

                            >

                                <MenuItem
                                    value=""
                                    disabled
                                >
                                    {
                                        organizationsLoading
                                            ? "Loading organizations..."
                                            : "Select organization"
                                    }
                                </MenuItem>


                                {
                                    organizations.map(
                                        organization => (

                                            <MenuItem

                                                key={
                                                    organization._id ||
                                                    organization.id
                                                }

                                                value={
                                                    organization._id ||
                                                    organization.id
                                                }

                                            >

                                                {
                                                    organization.name
                                                }

                                            </MenuItem>

                                        )
                                    )
                                }

                            </Select>

                        </FormControl>

                    </Box>

                )
            }



            {/* ==================================================
                NAVIGATION
            ================================================== */}

            <Box
                sx={{
                    flexGrow: 1,

                    overflowY: "auto",

                    px: 1.25,

                    py: 1.75,

                    "&::-webkit-scrollbar": {
                        width: 5
                    },

                    "&::-webkit-scrollbar-thumb": {
                        backgroundColor:
                            "rgba(0,0,0,0.10)",

                        borderRadius:
                            10
                    }
                }}
            >


                {/* ==================================================
                    MAIN
                ================================================== */}

                <Typography
                    variant="overline"
                    sx={{
                        display:
                            "block",

                        px: 1.5,

                        mb: 0.75,

                        color:
                            "text.disabled",

                        fontWeight:
                            700,

                        fontSize:
                            "0.64rem",

                        letterSpacing:
                            "0.09em"
                    }}
                >
                    Main
                </Typography>


                <List
                    disablePadding
                >

                    {
                        visibleMenuItems.map(
                            item => (

                                <ListItemButton

                                    key={
                                        item.path
                                    }

                                    component={
                                        NavLink
                                    }

                                    to={
                                        item.path
                                    }

                                    onClick={
                                        handleNavigation
                                    }

                                    sx={
                                        navItemSx
                                    }

                                >

                                    <ListItemIcon>

                                        {
                                            item.icon
                                        }

                                    </ListItemIcon>


                                    <ListItemText
                                        primary={
                                            item.label
                                        }
                                    />

                                </ListItemButton>

                            )
                        )
                    }

                </List>



                {/* ==================================================
                    ENTERPRISE
                ================================================== */}

                {canSeeEnterprises && (

                <Box
                    sx={{
                        mt: 2.5
                    }}
                >

                    <Typography
                        variant="overline"
                        sx={{
                            display:
                                "block",

                            px: 1.5,

                            mb: 0.75,

                            color:
                                "text.disabled",

                            fontWeight:
                                700,

                            fontSize:
                                "0.64rem",

                            letterSpacing:
                                "0.09em"
                        }}
                    >
                        Enterprise Management
                    </Typography>


                    <List
                        disablePadding
                    >

                        <ListItemButton

                            onClick={() =>
                                setEnterpriseOpen(
                                    previous =>
                                        !previous
                                )
                            }

                            sx={{

                                ...navItemSx,

                                color:
                                    enterpriseActive
                                        ? GREEN
                                        : "text.secondary",

                                backgroundColor:
                                    enterpriseActive
                                        ? GREEN_LIGHT
                                        : "transparent"

                            }}

                        >

                            <ListItemIcon>

                                <Business />

                            </ListItemIcon>


                            <ListItemText
                                primary="Enterprises"
                            />


                            {
                                enterpriseOpen
                                    ? (
                                        <ExpandLess
                                            fontSize="small"
                                        />
                                    )
                                    : (
                                        <ExpandMore
                                            fontSize="small"
                                        />
                                    )
                            }

                        </ListItemButton>



                        <Collapse
                            in={
                                enterpriseOpen
                            }

                            timeout="auto"

                            unmountOnExit
                        >

                            <List
                                disablePadding

                                sx={{
                                    pl: 1
                                }}
                            >

                                {
                                    enterpriseItems.map(
                                        item => (

                                            <ListItemButton

                                                key={
                                                    item.path
                                                }

                                                component={
                                                    NavLink
                                                }

                                                to={
                                                    item.path
                                                }

                                                onClick={
                                                    handleNavigation
                                                }

                                                sx={{

                                                    ...navItemSx,

                                                    minHeight:
                                                        40,

                                                    pl:
                                                        2.5,

                                                    ml:
                                                        1

                                                }}

                                            >

                                                <ListItemIcon>

                                                    {
                                                        item.icon
                                                    }

                                                </ListItemIcon>


                                                <ListItemText
                                                    primary={
                                                        item.label
                                                    }
                                                />

                                            </ListItemButton>

                                        )
                                    )
                                }

                            </List>

                        </Collapse>

                    </List>

                </Box>

                )}



                {/* ==================================================
                    SUPER ADMIN
                ================================================== */}

                {
                    isSuperAdmin && (

                        <Box
                            sx={{
                                mt: 2.5
                            }}
                        >

                            <Typography
                                variant="overline"
                                sx={{
                                    display:
                                        "block",

                                    px: 1.5,

                                    mb: 0.75,

                                    color:
                                        "text.disabled",

                                    fontWeight:
                                        700,

                                    fontSize:
                                        "0.64rem",

                                    letterSpacing:
                                        "0.09em"
                                }}
                            >
                                Platform Administration
                            </Typography>


                            <List
                                disablePadding
                            >

                                <ListItemButton

                                    onClick={() =>
                                        setSuperAdminOpen(
                                            previous =>
                                                !previous
                                        )
                                    }

                                    sx={{

                                        ...navItemSx,

                                        color:
                                            superAdminActive
                                                ? GREEN
                                                : "text.secondary",

                                        backgroundColor:
                                            superAdminActive
                                                ? GREEN_LIGHT
                                                : "transparent"

                                    }}

                                >

                                    <ListItemIcon>

                                        <AdminPanelSettings />

                                    </ListItemIcon>


                                    <ListItemText
                                        primary="Super Admin"
                                    />


                                    {
                                        superAdminOpen
                                            ? (
                                                <ExpandLess
                                                    fontSize="small"
                                                />
                                            )
                                            : (
                                                <ExpandMore
                                                    fontSize="small"
                                                />
                                            )
                                    }

                                </ListItemButton>



                                <Collapse
                                    in={
                                        superAdminOpen
                                    }

                                    timeout="auto"

                                    unmountOnExit
                                >

                                    <List
                                        disablePadding

                                        sx={{
                                            pl: 1
                                        }}
                                    >

                                        {
                                            superAdminItems.map(
                                                item => (

                                                    <ListItemButton

                                                        key={
                                                            item.path
                                                        }

                                                        component={
                                                            NavLink
                                                        }

                                                        to={
                                                            item.path
                                                        }

                                                        onClick={
                                                            handleNavigation
                                                        }

                                                        sx={{

                                                            ...navItemSx,

                                                            minHeight:
                                                                40,

                                                            pl:
                                                                2.5,

                                                            ml:
                                                                1

                                                        }}

                                                    >

                                                        <ListItemIcon>

                                                            {
                                                                item.icon
                                                            }

                                                        </ListItemIcon>


                                                        <ListItemText
                                                            primary={
                                                                item.label
                                                            }
                                                        />

                                                    </ListItemButton>

                                                )
                                            )
                                        }

                                    </List>

                                </Collapse>

                            </List>

                        </Box>

                    )
                }



                {/* ==================================================
                    ORGANIZATION ADMINISTRATION
                ================================================== */}

                {
                    visibleSettingsItems.length > 0 && (

                        <Box
                            sx={{
                                mt: 2.5
                            }}
                        >

                            <Typography
                                variant="overline"
                                sx={{
                                    display:
                                        "block",

                                    px: 1.5,

                                    mb: 0.75,

                                    color:
                                        "text.disabled",

                                    fontWeight:
                                        700,

                                    fontSize:
                                        "0.64rem",

                                    letterSpacing:
                                        "0.09em"
                                }}
                            >
                                Administration
                            </Typography>


                            <List
                                disablePadding
                            >

                                <ListItemButton

                                    onClick={() =>
                                        setSettingsOpen(
                                            previous =>
                                                !previous
                                        )
                                    }

                                    sx={{

                                        ...navItemSx,

                                        color:
                                            settingsActive
                                                ? GREEN
                                                : "text.secondary",

                                        backgroundColor:
                                            settingsActive
                                                ? GREEN_LIGHT
                                                : "transparent"

                                    }}

                                >

                                    <ListItemIcon>

                                        <Settings />

                                    </ListItemIcon>


                                    <ListItemText
                                        primary="Settings"
                                    />


                                    {
                                        settingsOpen
                                            ? (
                                                <ExpandLess
                                                    fontSize="small"
                                                />
                                            )
                                            : (
                                                <ExpandMore
                                                    fontSize="small"
                                                />
                                            )
                                    }

                                </ListItemButton>



                                <Collapse
                                    in={
                                        settingsOpen
                                    }

                                    timeout="auto"

                                    unmountOnExit
                                >

                                    <List
                                        disablePadding

                                        sx={{
                                            pl: 1
                                        }}
                                    >

                                        {
                                            visibleSettingsItems.map(
                                                item => (

                                                    <ListItemButton

                                                        key={
                                                            item.path
                                                        }

                                                        component={
                                                            NavLink
                                                        }

                                                        to={
                                                            item.path
                                                        }

                                                        onClick={
                                                            handleNavigation
                                                        }

                                                        sx={{

                                                            ...navItemSx,

                                                            minHeight:
                                                                40,

                                                            pl:
                                                                2.5,

                                                            ml:
                                                                1

                                                        }}

                                                    >

                                                        <ListItemIcon>

                                                            {
                                                                item.icon
                                                            }

                                                        </ListItemIcon>


                                                        <ListItemText
                                                            primary={
                                                                item.label
                                                            }
                                                        />

                                                    </ListItemButton>

                                                )
                                            )
                                        }

                                    </List>

                                </Collapse>

                            </List>

                        </Box>

                    )
                }

            </Box>



            {/* ==================================================
                SIDEBAR FOOTER
            ================================================== */}

            <Box
                sx={{
                    px: 1.75,

                    py: 1.25,

                    borderTop:
                        "1px solid",

                    borderColor:
                        "divider"
                }}
            >

                <Typography
                    variant="caption"
                    sx={{
                        display:
                            "block",

                        textAlign:
                            "center",

                        color:
                            "text.disabled",

                        fontSize:
                            "0.68rem"
                    }}
                >
                    NGO SaaS Platform
                </Typography>

            </Box>

        </Box>

    );



    return (

        <>

            {/* ==================================================
                DESKTOP DRAWER
            ================================================== */}

            <Drawer

                variant="permanent"

                sx={{

                    display: {
                        xs: "none",
                        md: "block"
                    },

                    width:
                        DRAWER_WIDTH,

                    flexShrink:
                        0,

                    "& .MuiDrawer-paper": {

                        width:
                            DRAWER_WIDTH,

                        boxSizing:
                            "border-box",

                        borderRight:
                            "1px solid",

                        borderColor:
                            "divider",

                        backgroundColor:
                            "#ffffff"
                    }

                }}

            >

                {
                    drawerContent
                }

            </Drawer>



            {/* ==================================================
                MOBILE DRAWER
            ================================================== */}

            <Drawer

                variant="temporary"

                open={
                    mobileOpen
                }

                onClose={
                    onMobileClose
                }

                ModalProps={{
                    keepMounted: true
                }}

                sx={{

                    display: {
                        xs: "block",
                        md: "none"
                    },

                    "& .MuiDrawer-paper": {

                        width:
                            DRAWER_WIDTH,

                        boxSizing:
                            "border-box",

                        backgroundColor:
                            "#ffffff"
                    }

                }}

            >

                {
                    drawerContent
                }

            </Drawer>

        </>

    );

};


export default Sidebar;