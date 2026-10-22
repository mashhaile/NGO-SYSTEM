import {
    Drawer,
    List,
    ListItemButton,
    ListItemIcon,
    ListItemText,
    Typography,
    Box,
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
    LocalShipping,
    ManageSearch,
    Business,
    ManageAccounts,
    Tune,
    Close,
    AdminPanelSettings,
    Apartment,
    Payments,
    CardMembership,
    Storefront,
    Savings,
    ReceiptLong,
    Group,
    HowToReg,
    LockOutlined
} from "@mui/icons-material";

import {
    NavLink
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
   NAVIGATION
   ----------------------------------------------------------
   Sections in menu order: a title with its items always
   visible (no dropdowns). Items the user may not open are
   shown greyed out (not clickable), so everyone sees what
   the system has. Admin sections (adminOnly) are left out
   entirely for users who cannot use them.
========================================================== */

const SECTIONS = [

    {
        title: "Main",
        items: [
            { label: "Dashboard", path: "/dashboard", icon: <Dashboard /> },
            { label: "Reports", path: "/reports", icon: <Assessment />, permission: "report.read" }
        ]
    },

    {
        title: "Beneficiaries",
        items: [
            { label: "Beneficiaries", path: "/beneficiaries", icon: <People />, permission: "beneficiary.read" },
            { label: "Enrollments", path: "/enrollments", icon: <HowToReg />, permission: "enrollment.read" },
            { label: "Enterprises", path: "/enterprises", icon: <Storefront />, permission: "enterprise.read" },
            { label: "Enterprise Members", path: "/enterprise-members", icon: <Group />, permission: "enterprise.read" }
        ]
    },

    {
        title: "Services",
        items: [
            { label: "Service Delivery", path: "/service-deliveries", icon: <LocalShipping />, permission: "service.read" }
        ]
    },

    {
        title: "Programs",
        items: [
            { label: "Programs", path: "/programs", icon: <Folder />, permission: "program.read" },
            { label: "Projects", path: "/projects", icon: <Assignment />, permission: "project.read" }
        ]
    },

    {
        title: "Activities",
        items: [
            { label: "Terms of Reference", path: "/tors", icon: <Description />, permission: "tor.read" },
            { label: "Activities", path: "/activities", icon: <EventNote />, permission: "activity.read" },
            { label: "Activity Runs", path: "/activity-runs", icon: <EventAvailable />, permission: "activity_run.read" },
            { label: "Attendance", path: "/attendance", icon: <FactCheck />, permission: "attendance.read" }
        ]
    },

    {
        title: "Funding",
        items: [
            { label: "Donors", path: "/donors", icon: <VolunteerActivism />, permission: "donor.read" },
            { label: "Donations", path: "/donations", icon: <AccountBalance />, permission: "donation.read" }
        ]
    },

    {
        title: "Finance",
        items: [
            { label: "Budgets", path: "/budgets", icon: <Savings />, permission: "budget.read" },
            { label: "Expenses", path: "/expenses", icon: <ReceiptLong />, permission: "expense.read" }
        ]
    },

    {
        title: "Platform Administration",
        superAdminOnly: true,
        adminOnly: true,
        items: [
            { label: "Super Admin Dashboard", path: "/superadmin", icon: <AdminPanelSettings />, exact: true },
            { label: "Organizations", path: "/superadmin/organizations", icon: <Apartment /> },
            { label: "Plans", path: "/superadmin/plans", icon: <CardMembership /> },
            { label: "Subscriptions", path: "/superadmin/subscriptions", icon: <Payments /> }
        ]
    },

    {
        title: "Administration",
        adminOnly: true,
        items: [
            { label: "Organization", path: "/settings/organization", icon: <Business />, permission: PERMISSIONS.ORGANIZATION_READ },
            { label: "User Management", path: "/users", icon: <ManageAccounts />, permission: PERMISSIONS.USER_READ },
            // Admin only: other roles read lookups / custom fields
            // for their forms, they do not manage them
            { label: "Lookup Management", path: "/lookups", icon: <ManageSearch />, permission: PERMISSIONS.LOOKUP_UPDATE },
            { label: "Custom Fields", path: "/settings/custom-fields", icon: <Tune />, permission: PERMISSIONS.CUSTOMFIELD_UPDATE }
        ]
    }

];


/* ==========================================================
   STYLES
========================================================== */

const navItemSx = {

    position: "relative",
    minHeight: 38,
    px: 1.5,
    py: 0.5,
    borderRadius: 1.5,
    mb: 0.25,
    color: "text.secondary",
    transition: "background-color 0.18s ease, color 0.18s ease",

    "&:hover": {
        backgroundColor: GREEN_HOVER,
        color: GREEN
    },

    "& .MuiListItemIcon-root": {
        minWidth: 36,
        color: "inherit",
        transition: "color 0.18s ease",
        "& svg": { fontSize: 21 }
    },

    "& .MuiListItemText-root": {
        my: 0
    },

    "& .MuiListItemText-primary": {
        fontSize: "0.86rem",
        fontWeight: 500
    },

    "&.active": {
        backgroundColor: GREEN_LIGHT,
        color: GREEN,
        fontWeight: 700,

        "&::before": {
            content: '""',
            position: "absolute",
            left: 0,
            top: 6,
            bottom: 6,
            width: 3,
            borderRadius: "0 4px 4px 0",
            backgroundColor: GREEN
        },

        "& .MuiListItemIcon-root": {
            color: GREEN
        },

        "& .MuiListItemText-primary": {
            fontWeight: 700
        }
    }

};

const sectionTitleSx = {
    display: "block",
    px: 1.5,
    mb: 0.5,
    lineHeight: 1.6,
    color: "text.disabled",
    fontWeight: 700,
    fontSize: "0.64rem",
    letterSpacing: "0.09em"
};


/* ==========================================================
   SIDEBAR
========================================================== */

const Sidebar = ({
    mobileOpen = false,
    onMobileClose
}) => {

    const dispatch = useDispatch();

    const { user } = useAuth();


    /* ---------------- organization context (super admin) ---------------- */

    const selectedOrganizationId = useSelector(selectSelectedOrganizationId);

    const [organizations, setOrganizations] = useState([]);
    const [organizationsLoading, setOrganizationsLoading] = useState(false);

    const permissions = user?.permissions || [];

    const isSuperAdmin =
        user?.role === "superadmin" ||
        user?.role === "super_admin" ||
        user?.isSuperAdmin === true ||
        user?.userType === "superadmin";

    useEffect(() => {

        // Only the super admin picks an organization
        if (!isSuperAdmin) return;

        const loadOrganizations = async () => {
            try {
                setOrganizationsLoading(true);
                const data = (await getOrganizationsApi())?.data;
                setOrganizations(
                    Array.isArray(data)
                        ? data
                        : Array.isArray(data?.organizations) ? data.organizations : []
                );
            }
            catch (error) {
                console.error("Failed to load organizations:", error);
                setOrganizations([]);
            }
            finally {
                setOrganizationsLoading(false);
            }
        };

        loadOrganizations();

    }, [isSuperAdmin]);

    const handleOrganizationChange = (event) => {
        const organization =
            organizations.find(item => String(item._id || item.id) === String(event.target.value));
        if (organization) {
            dispatch(setOrganizationContext(organization));
        }
    };


    /* ---------------- what this user may see ---------------- */

    const can = (permission) =>
        isSuperAdmin ||
        !permission ||
        permissions.includes("*") ||
        permissions.includes(permission);

    // Admin sections: only allowed items. Others: every item,
    // the ones the user may not open marked as locked.
    const sections =
        SECTIONS
            .filter(section => !section.superAdminOnly || isSuperAdmin)
            .map(section => ({
                ...section,
                items: section.adminOnly
                    ? section.items.filter(item => can(item.permission))
                    : section.items.map(item => ({ ...item, locked: !can(item.permission) }))
            }))
            .filter(section => section.items.length > 0);

    const handleNavigation = () => {
        if (onMobileClose) onMobileClose();
    };


    /* ---------------- rendering ---------------- */

    const drawerContent = (

        <Box sx={{ height: "100%", display: "flex", flexDirection: "column", backgroundColor: "#ffffff" }}>

            {/* BRAND */}

            <Box sx={{ height: 72, px: 2.25, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <Box>
                    <Typography sx={{ fontSize: "1.15rem", fontWeight: 800, color: GREEN_DARK, letterSpacing: "-0.025em" }}>
                        NGO SaaS
                    </Typography>
                    <Typography variant="caption" sx={{ fontSize: "0.7rem", color: "text.secondary", letterSpacing: "0.02em" }}>
                        Management Platform
                    </Typography>
                </Box>

                <IconButton onClick={onMobileClose} sx={{ display: { xs: "flex", md: "none" }, color: "text.secondary" }}>
                    <Close />
                </IconButton>
            </Box>

            <Divider />


            {/* SUPER ADMIN: CURRENT ORGANIZATION */}

            {isSuperAdmin && (
                <Box sx={{ px: 1.5, py: 1.5, borderBottom: "1px solid", borderColor: "divider" }}>
                    <Typography variant="caption" sx={{ display: "block", mb: 0.75, color: "text.secondary", fontWeight: 700 }}>
                        Current Organization
                    </Typography>
                    <FormControl fullWidth size="small">
                        <Select
                            value={selectedOrganizationId || ""}
                            onChange={handleOrganizationChange}
                            displayEmpty
                            sx={{ fontSize: "0.82rem", borderRadius: 1.5 }}
                        >
                            <MenuItem value="" disabled>
                                {organizationsLoading ? "Loading organizations..." : "Select organization"}
                            </MenuItem>
                            {organizations.map(organization => (
                                <MenuItem key={organization._id || organization.id} value={organization._id || organization.id}>
                                    {organization.name}
                                </MenuItem>
                            ))}
                        </Select>
                    </FormControl>
                </Box>
            )}


            {/* NAVIGATION */}

            <Box
                component="nav"
                aria-label="Main navigation"
                sx={{
                    flexGrow: 1,
                    overflowY: "auto",
                    px: 1.25,
                    py: 1.5,
                    "&::-webkit-scrollbar": { width: 5 },
                    "&::-webkit-scrollbar-thumb": { backgroundColor: "rgba(0,0,0,0.10)", borderRadius: 10 }
                }}
            >

                {sections.map((section, index) => (
                    <Box key={section.title} sx={{ mt: index === 0 ? 0 : 1.75 }}>

                        <Typography variant="overline" sx={sectionTitleSx}>
                            {section.title}
                        </Typography>

                        <List disablePadding>
                            {section.items.map(item => item.locked ? (
                                <Box
                                    key={item.path}
                                    component="li"
                                    title="Your role does not include this"
                                    sx={{ listStyle: "none" }}
                                >
                                    <ListItemButton
                                        disabled
                                        aria-disabled="true"
                                        sx={{
                                            ...navItemSx,
                                            "&.Mui-disabled": { opacity: 0.45 }
                                        }}
                                    >
                                        <ListItemIcon>{item.icon}</ListItemIcon>
                                        <ListItemText primary={item.label} />
                                        <LockOutlined sx={{ fontSize: 15, color: "text.disabled" }} />
                                    </ListItemButton>
                                </Box>
                            ) : (
                                <ListItemButton
                                    key={item.path}
                                    component={NavLink}
                                    to={item.path}
                                    end={Boolean(item.exact)}
                                    onClick={handleNavigation}
                                    sx={navItemSx}
                                >
                                    <ListItemIcon>{item.icon}</ListItemIcon>
                                    <ListItemText primary={item.label} />
                                </ListItemButton>
                            ))}
                        </List>

                    </Box>
                ))}

            </Box>


            {/* FOOTER */}

            <Box sx={{ px: 1.75, py: 1.25, borderTop: "1px solid", borderColor: "divider" }}>
                <Typography variant="caption" sx={{ display: "block", textAlign: "center", color: "text.disabled", fontSize: "0.68rem" }}>
                    NGO SaaS Platform
                </Typography>
            </Box>

        </Box>

    );


    return (

        <>

            {/* DESKTOP */}

            <Drawer
                variant="permanent"
                sx={{
                    display: { xs: "none", md: "block" },
                    width: DRAWER_WIDTH,
                    flexShrink: 0,
                    "& .MuiDrawer-paper": {
                        width: DRAWER_WIDTH,
                        boxSizing: "border-box",
                        borderRight: "1px solid",
                        borderColor: "divider",
                        backgroundColor: "#ffffff"
                    }
                }}
            >
                {drawerContent}
            </Drawer>


            {/* MOBILE */}

            <Drawer
                variant="temporary"
                open={mobileOpen}
                onClose={onMobileClose}
                ModalProps={{ keepMounted: true }}
                sx={{
                    display: { xs: "block", md: "none" },
                    "& .MuiDrawer-paper": {
                        width: DRAWER_WIDTH,
                        boxSizing: "border-box",
                        backgroundColor: "#ffffff"
                    }
                }}
            >
                {drawerContent}
            </Drawer>

        </>

    );

};


export default Sidebar;
