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
    ReceiptLong,
    Group,
    HowToReg,
    Groups
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
   NAVIGATION
   ----------------------------------------------------------
   Items and groups, in menu order. A group opens as a
   dropdown; it is hidden when the user may see none of its
   items, and shown as a plain item when only one is left.
========================================================== */

const MAIN_NAVIGATION = [

    { label: "Dashboard", path: "/dashboard", icon: <Dashboard /> },

    {
        key: "beneficiaries",
        label: "Beneficiaries",
        icon: <Groups />,
        items: [
            { label: "Beneficiaries", path: "/beneficiaries", icon: <People />, permission: "beneficiary.read" },
            { label: "Enrollments", path: "/enrollments", icon: <HowToReg />, permission: "enrollment.read" },
            { label: "Enterprises", path: "/enterprises", icon: <Storefront />, permission: "enterprise.read" },
            { label: "Enterprise Members", path: "/enterprise-members", icon: <Group />, permission: "enterprise.read" }
        ]
    },

    { label: "Service Delivery", path: "/service-deliveries", icon: <LocalShipping />, permission: "service.read" },

    {
        key: "programs",
        label: "Programs",
        icon: <Folder />,
        items: [
            { label: "Programs", path: "/programs", icon: <Folder />, permission: "program.read" },
            { label: "Projects", path: "/projects", icon: <Assignment />, permission: "project.read" }
        ]
    },

    {
        key: "activities",
        label: "Activities",
        icon: <EventNote />,
        items: [
            { label: "Terms of Reference", path: "/tors", icon: <Description />, permission: "tor.read" },
            { label: "Activities", path: "/activities", icon: <EventNote />, permission: "activity.read" },
            { label: "Activity Runs", path: "/activity-runs", icon: <EventAvailable />, permission: "activity_run.read" },
            { label: "Attendance", path: "/attendance", icon: <FactCheck />, permission: "attendance.read" }
        ]
    },

    {
        key: "funding",
        label: "Funding",
        icon: <VolunteerActivism />,
        items: [
            { label: "Donors", path: "/donors", icon: <VolunteerActivism />, permission: "donor.read" },
            { label: "Donations", path: "/donations", icon: <AccountBalance />, permission: "donation.read" }
        ]
    },

    {
        key: "finance",
        label: "Finance",
        icon: <Savings />,
        items: [
            { label: "Budgets", path: "/budgets", icon: <Savings />, permission: "budget.read" },
            { label: "Expenses", path: "/expenses", icon: <ReceiptLong />, permission: "expense.read" }
        ]
    },

    { label: "Reports", path: "/reports", icon: <Assessment />, permission: "report.read" }

];

const SETTINGS_GROUP = {
    key: "settings",
    label: "Settings",
    icon: <Settings />,
    items: [
        { label: "Organization", path: "/settings/organization", icon: <Business />, permission: PERMISSIONS.ORGANIZATION_READ },
        { label: "User Management", path: "/users", icon: <ManageAccounts />, permission: PERMISSIONS.USER_READ },
        { label: "Lookup Management", path: "/lookups", icon: <ManageSearch />, permission: PERMISSIONS.LOOKUP_READ },
        { label: "Custom Fields", path: "/settings/custom-fields", icon: <Tune />, permission: PERMISSIONS.CUSTOMFIELD_READ }
    ]
};

const SUPER_ADMIN_GROUP = {
    key: "superadmin",
    label: "Super Admin",
    icon: <AdminPanelSettings />,
    items: [
        { label: "Super Admin Dashboard", path: "/superadmin", icon: <AdminPanelSettings />, exact: true },
        { label: "Organizations", path: "/superadmin/organizations", icon: <Apartment /> },
        { label: "Plans", path: "/superadmin/plans", icon: <CardMembership /> },
        { label: "Subscriptions", path: "/superadmin/subscriptions", icon: <Payments /> }
    ]
};


/* ==========================================================
   REMEMBERED OPEN GROUPS (per browser)
========================================================== */

const OPEN_GROUPS_KEY = "sidebar.openGroups";

const readOpenGroups = () => {
    try {
        return JSON.parse(localStorage.getItem(OPEN_GROUPS_KEY) || "{}") || {};
    }
    catch {
        return {};
    }
};

const saveOpenGroups = (value) => {
    try {
        localStorage.setItem(OPEN_GROUPS_KEY, JSON.stringify(value));
    }
    catch {
        // storage blocked: the menu still works, it just does not remember
    }
};


/* ==========================================================
   STYLES
========================================================== */

const navItemSx = {

    position: "relative",
    minHeight: 44,
    px: 1.5,
    borderRadius: 1.5,
    mb: 0.35,
    color: "text.secondary",
    transition: "background-color 0.18s ease, color 0.18s ease",

    "&:hover": {
        backgroundColor: GREEN_HOVER,
        color: GREEN
    },

    "& .MuiListItemIcon-root": {
        minWidth: 38,
        color: "inherit",
        transition: "color 0.18s ease"
    },

    "& .MuiListItemText-primary": {
        fontSize: "0.88rem",
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
            top: 7,
            bottom: 7,
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

const childItemSx = {
    ...navItemSx,
    minHeight: 40,
    pl: 2.5,
    ml: 1
};

const sectionTitleSx = {
    display: "block",
    px: 1.5,
    mb: 0.75,
    color: "text.disabled",
    fontWeight: 700,
    fontSize: "0.64rem",
    letterSpacing: "0.09em"
};


const isInside = (pathname, item) =>
    item.exact
        ? pathname === item.path
        : pathname === item.path || pathname.startsWith(`${item.path}/`);


/* ==========================================================
   SIDEBAR
========================================================== */

const Sidebar = ({
    mobileOpen = false,
    onMobileClose
}) => {

    const location = useLocation();

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

    // Groups keep only allowed items; empty groups are dropped and
    // a group with one item becomes that item.
    const visible = (entries) =>
        entries
            .map(entry => {
                if (!entry.items) return can(entry.permission) ? entry : null;
                const items = entry.items.filter(item => can(item.permission));
                if (items.length === 0) return null;
                if (items.length === 1) return items[0];
                return { ...entry, items };
            })
            .filter(Boolean);

    const mainEntries = visible(MAIN_NAVIGATION);
    const [settingsEntry] = visible([SETTINGS_GROUP]);


    /* ---------------- open groups ---------------- */

    const [openGroups, setOpenGroups] = useState(readOpenGroups);

    const activeGroupKey =
        [...MAIN_NAVIGATION, SETTINGS_GROUP, SUPER_ADMIN_GROUP]
            .find(entry => entry.items?.some(item => isInside(location.pathname, item)))
            ?.key;

    // The group of the current page opens by itself; the user
    // can still collapse it while staying on that page.
    const [collapsedHere, setCollapsedHere] = useState(null);
    const hereKey = (key) => `${key}@${location.pathname}`;

    const isOpen = (key) =>
        key === activeGroupKey
            ? collapsedHere !== hereKey(key)
            : Boolean(openGroups[key]);

    const toggleGroup = (key) => {
        if (key === activeGroupKey) {
            setCollapsedHere(previous => (previous === hereKey(key) ? null : hereKey(key)));
            return;
        }
        setOpenGroups(previous => {
            const next = { ...previous, [key]: !previous[key] };
            saveOpenGroups(next);
            return next;
        });
    };

    const handleNavigation = () => {
        if (onMobileClose) onMobileClose();
    };


    /* ---------------- rendering ---------------- */

    const renderLink = (item, sx = navItemSx) => (
        <ListItemButton
            key={item.path}
            component={NavLink}
            to={item.path}
            end={Boolean(item.exact)}
            onClick={handleNavigation}
            sx={sx}
        >
            <ListItemIcon>{item.icon}</ListItemIcon>
            <ListItemText primary={item.label} />
        </ListItemButton>
    );

    const renderGroup = (group) => {

        const active = group.key === activeGroupKey;
        const open = isOpen(group.key);

        return (
            <Box key={group.key}>
                <ListItemButton
                    onClick={() => toggleGroup(group.key)}
                    aria-expanded={open}
                    sx={{
                        ...navItemSx,
                        color: active ? GREEN : "text.secondary",
                        "& .MuiListItemText-primary": {
                            fontSize: "0.88rem",
                            fontWeight: active ? 700 : 500
                        }
                    }}
                >
                    <ListItemIcon>{group.icon}</ListItemIcon>
                    <ListItemText primary={group.label} />
                    {open ? <ExpandLess fontSize="small" /> : <ExpandMore fontSize="small" />}
                </ListItemButton>

                <Collapse in={open} timeout="auto" unmountOnExit>
                    <List disablePadding sx={{ pl: 1 }}>
                        {group.items.map(item => renderLink(item, childItemSx))}
                    </List>
                </Collapse>
            </Box>
        );

    };

    const renderEntries = (entries) =>
        entries.map(entry => (entry.items ? renderGroup(entry) : renderLink(entry)));


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
                    py: 1.75,
                    "&::-webkit-scrollbar": { width: 5 },
                    "&::-webkit-scrollbar-thumb": { backgroundColor: "rgba(0,0,0,0.10)", borderRadius: 10 }
                }}
            >

                <Typography variant="overline" sx={sectionTitleSx}>
                    Main
                </Typography>

                <List disablePadding>
                    {renderEntries(mainEntries)}
                </List>

                {isSuperAdmin && (
                    <Box sx={{ mt: 2.5 }}>
                        <Typography variant="overline" sx={sectionTitleSx}>
                            Platform Administration
                        </Typography>
                        <List disablePadding>
                            {renderGroup(SUPER_ADMIN_GROUP)}
                        </List>
                    </Box>
                )}

                {settingsEntry && (
                    <Box sx={{ mt: 2.5 }}>
                        <Typography variant="overline" sx={sectionTitleSx}>
                            Administration
                        </Typography>
                        <List disablePadding>
                            {renderEntries([settingsEntry])}
                        </List>
                    </Box>
                )}

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
