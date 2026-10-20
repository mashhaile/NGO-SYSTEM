import {
    useEffect,
    useState
} from "react";


import {
    Box,
    CircularProgress,
    Alert,
    Typography,
    Tabs,
    Tab,
    Paper
} from "@mui/material";


import {
    useDispatch,
    useSelector
} from "react-redux";


import {
    useNavigate
} from "react-router-dom";


import {
    getOrganizationsThunk
} from "../store/organizationThunks";


import {
    selectOrganizations,
    selectOrganizationLoading,
    selectOrganizationError
} from "../store/organizationSlice";


import OrganizationTable
    from "../components/OrganizationTable";


import {
    AppButton
} from "../../../components/ui";


// =====================================================
// PAGE
// SUPER ADMIN ORGANIZATION MANAGEMENT
// =====================================================

const OrganizationListPage = () => {

    const dispatch =
        useDispatch();


    const navigate =
        useNavigate();


    // =================================================
    // STATE
    // =================================================

    const [
        view,
        setView
    ] = useState("active");


    // =================================================
    // REDUX
    // =================================================

    const organizations =
        useSelector(
            selectOrganizations
        );


    const loading =
        useSelector(
            selectOrganizationLoading
        );


    const error =
        useSelector(
            selectOrganizationError
        );


    // =================================================
    // LOAD ORGANIZATIONS
    // =================================================

  useEffect(() => {

    dispatch(
        getOrganizationsThunk({

            deletedOnly:
                view === "deleted"

        })
    );

}, [
    dispatch,
    view
]);

    // =================================================
    // CREATE ORGANIZATION
    // =================================================

    const handleCreateOrganization =
        () => {

            navigate(
                "/superadmin/organizations/create"
            );

        };


    // =================================================
    // CHANGE VIEW
    // =================================================

    const handleViewChange = (
        event,
        newView
    ) => {

        setView(
            newView
        );

    };


    // =================================================
    // LOADING
    // =================================================

    if (loading) {

        return (

            <Box
                sx={{
                    display: "flex",
                    justifyContent: "center",
                    alignItems: "center",
                    minHeight: 300
                }}
            >

                <CircularProgress />

            </Box>

        );

    }


    // =================================================
    // PAGE
    // =================================================

    return (
        <Box
            sx={{
                width: "100%"
            }}
        >

            {/* =========================================
                HEADER
            ========================================= */}

            <Box
                sx={{
                    mb: 3,
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: {
                        xs: "flex-start",
                        sm: "center"
                    },
                    flexDirection: {
                        xs: "column",
                        sm: "row"
                    },
                    gap: 2
                }}
            >

                <Box>

                    <Typography
                        variant="h5"
                        sx={{
                            fontWeight: 700
                        }}
                    >
                        Organizations
                    </Typography>


                    <Typography
                        variant="body2"
                        sx={{
                            color: "text.secondary",
                            mt: 0.5
                        }}>
                        Manage organizations registered on the NGO SaaS platform.
                    </Typography>

                </Box>


                {
                    view === "active" && (

                        <AppButton
                            variant="contained"
                            onClick={
                                handleCreateOrganization
                            }
                        >
                            Create Organization
                        </AppButton>

                    )
                }

            </Box>

            {/* =========================================
                VIEW TABS
            ========================================= */}

            <Paper
                variant="outlined"
                sx={{
                    mb: 3
                }}
            >

                <Tabs
                    value={
                        view
                    }
                    onChange={
                        handleViewChange
                    }
                    variant="fullWidth"
                >

                    <Tab
                        value="active"
                        label="Active Organizations"
                    />


                    <Tab
                        value="deleted"
                        label="Deleted Organizations"
                    />

                </Tabs>

            </Paper>

            {/* =========================================
                ERROR
            ========================================= */}

            {
                error && (

                    <Alert
                        severity="error"
                        sx={{
                            mb: 2
                        }}
                    >

                        {
                            typeof error === "string"
                                ? error
                                : (
                                    error?.message ||
                                    "Unable to load organizations."
                                )
                        }

                    </Alert>

                )
            }

            {/* =========================================
                TABLE
            ========================================= */}

            <OrganizationTable
                organizations={
                    organizations
                }
            />

        </Box>
    );

};


export default OrganizationListPage;