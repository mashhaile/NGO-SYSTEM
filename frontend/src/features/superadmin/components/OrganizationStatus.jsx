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
    Box,
    Typography,
    Paper,
    Button,
    Alert,
    CircularProgress
} from "@mui/material";


import {
    CheckCircle,
    PauseCircle,
    Block,
    Restore,
    ArrowBack
} from "@mui/icons-material";


import {
    activateOrganizationThunk,
    suspendOrganizationThunk,
    deactivateOrganizationThunk,
    restoreOrganizationThunk
} from "../store/organizationThunks";


import {
    selectOrganization,
    selectOrganizationLoading,
    selectOrganizationError
} from "../store/organizationSlice";


// =====================================================
// COMPONENT
// =====================================================

const OrganizationStatus = () => {

    const dispatch =
        useDispatch();


    const navigate =
        useNavigate();


    // =================================================
    // REDUX
    // =================================================

    const organization =
        useSelector(
            selectOrganization
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
    // LOCAL STATE
    // =================================================

    const [
        success,
        setSuccess
    ] = useState(false);


    const [
        processingAction,
        setProcessingAction
    ] = useState(null);


    // =================================================
    // ORGANIZATION DATA
    // =================================================

    const organizationData =
        organization?.organization ||
        organization;


    const organizationId =
        organizationData?._id ||
        organizationData?.id;


    const isDeleted =
        organizationData?.isDeleted === true;


    // =================================================
    // STATUS
    // =================================================

    const currentStatus =
        String(
            organizationData?.status ||
            (
                organizationData?.isActive
                    ? "active"
                    : "inactive"
            )
        ).toLowerCase();


    // =================================================
    // ACTION HANDLER
    // =================================================

    const handleAction = async (
        action,
        thunk
    ) => {

        if (!organizationId) {

            return;

        }


        try {

            setSuccess(false);

            setProcessingAction(action);


            const result =
                await dispatch(
                    thunk(
                        organizationId
                    )
                );


            if (
                thunk.fulfilled.match(
                    result
                )
            ) {

                setSuccess(true);

            }

        }
        catch (err) {

            console.error(
                "Organization lifecycle action error:",
                err
            );

        }
        finally {

            setProcessingAction(null);

        }

    };


    // =================================================
    // NO ORGANIZATION
    // =================================================

    if (!organizationData) {

        return null;

    }


    // =================================================
    // BUTTON HELPER
    // =================================================

    const isProcessing = (
        action
    ) => {

        return (
            processingAction === action
        );

    };


    // =================================================
    // DELETED ORGANIZATION
    // =================================================

    if (isDeleted) {

        return (
            <Paper
                elevation={0}
                sx={{
                    p: {
                        xs: 2,
                        sm: 3
                    },
                    border: "1px solid",
                    borderColor: "divider",
                    borderRadius: 2
                }}
            >

                <Box
                    sx={{
                        mb: 3
                    }}
                >

                    <Typography
                        variant="h6"
                        sx={{
                            fontWeight: 700
                        }}
                    >
                        Organization Status
                    </Typography>


                    <Typography
                        variant="body2"
                        sx={{
                            color: "text.secondary",
                            mt: 0.5
                        }}>
                        This organization has been deleted.
                    </Typography>

                </Box>

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
                                        "Unable to restore organization."
                                    )
                            }
                        </Alert>

                    )
                }

                {
                    success && (

                        <Alert
                            severity="success"
                            sx={{
                                mb: 2
                            }}
                        >
                            Organization restored successfully.
                        </Alert>

                    )
                }

                <Box
                    sx={{
                        mb: 3
                    }}
                >

                    <Typography
                        variant="body2"
                        sx={{
                            color: "text.secondary",
                            mb: 1
                        }}>
                        Current Status
                    </Typography>


                    <Typography
                        variant="h6"
                        sx={{
                            fontWeight: 700,
                            textTransform: "capitalize"
                        }}
                    >
                        Deleted
                    </Typography>

                </Box>

                <Box
                    sx={{
                        display: "flex",
                        flexWrap: "wrap",
                        gap: 1.5
                    }}
                >

                    <Button
                        variant="contained"
                        color="success"
                        startIcon={
                            isProcessing("restore")
                                ? (
                                    <CircularProgress
                                        size={18}
                                        color="inherit"
                                    />
                                )
                                : (
                                    <Restore />
                                )
                        }
                        disabled={loading}
                        onClick={() =>
                            handleAction(
                                "restore",
                                restoreOrganizationThunk
                            )
                        }
                    >
                        {
                            isProcessing("restore")
                                ? "Restoring..."
                                : "Restore"
                        }
                    </Button>

                </Box>

                <Box
                    sx={{
                        display: "flex",
                        justifyContent: "flex-end",
                        mt: 3,
                        pt: 2,
                        borderTop: "1px solid",
                        borderColor: "divider"
                    }}
                >

                    <Button
                        variant="text"
                        startIcon={
                            <ArrowBack />
                        }
                        onClick={() =>
                            navigate(
                                `/superadmin/organizations/${organizationId}`
                            )
                        }
                    >
                        Back to Organization
                    </Button>

                </Box>

            </Paper>
        );

    }


    // =================================================
    // NORMAL ORGANIZATION
    // =================================================

    return (
        <Paper
            elevation={0}
            sx={{
                p: {
                    xs: 2,
                    sm: 3
                },
                border: "1px solid",
                borderColor: "divider",
                borderRadius: 2
            }}
        >

            {/* =========================================
                HEADER
            ========================================= */}

            <Box
                sx={{
                    mb: 3
                }}
            >

                <Typography
                    variant="h6"
                    sx={{
                        fontWeight: 700
                    }}
                >
                    Organization Status
                </Typography>


                <Typography
                    variant="body2"
                    sx={{
                        color: "text.secondary",
                        mt: 0.5
                    }}>
                    Manage the platform lifecycle of this organization.
                </Typography>

            </Box>

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
                                    "Unable to update organization."
                                )
                        }

                    </Alert>

                )
            }

            {/* =========================================
                SUCCESS
            ========================================= */}

            {
                success && (

                    <Alert
                        severity="success"
                        sx={{
                            mb: 2
                        }}
                    >
                        Organization status updated successfully.
                    </Alert>

                )
            }

            {/* =========================================
                CURRENT STATUS
            ========================================= */}

            <Box
                sx={{
                    mb: 3
                }}
            >

                <Typography
                    variant="body2"
                    sx={{
                        color: "text.secondary",
                        mb: 1
                    }}>
                    Current Status
                </Typography>


                <Typography
                    variant="h6"
                    sx={{
                        fontWeight: 700,
                        textTransform: "capitalize"
                    }}
                >
                    {currentStatus}
                </Typography>

            </Box>

            {/* =========================================
                ACTIONS
            ========================================= */}

            <Box
                sx={{
                    display: "flex",
                    flexWrap: "wrap",
                    gap: 1.5
                }}
            >

                {/* =====================================
                    SUSPENDED / INACTIVE
                    → ACTIVATE ONLY
                ===================================== */}

                {
                    currentStatus !== "active" && (

                        <Button
                            variant="contained"
                            color="success"
                            startIcon={
                                isProcessing("activate")
                                    ? (
                                        <CircularProgress
                                            size={18}
                                            color="inherit"
                                        />
                                    )
                                    : (
                                        <CheckCircle />
                                    )
                            }
                            disabled={loading}
                            onClick={() =>
                                handleAction(
                                    "activate",
                                    activateOrganizationThunk
                                )
                            }
                        >
                            {
                                isProcessing("activate")
                                    ? "Activating..."
                                    : "Activate"
                            }
                        </Button>

                    )
                }


                {/* =====================================
                    ACTIVE
                    → SUSPEND
                ===================================== */}

                {
                    currentStatus === "active" && (

                        <Button
                            variant="outlined"
                            color="warning"
                            startIcon={
                                isProcessing("suspend")
                                    ? (
                                        <CircularProgress
                                            size={18}
                                            color="inherit"
                                        />
                                    )
                                    : (
                                        <PauseCircle />
                                    )
                            }
                            disabled={loading}
                            onClick={() =>
                                handleAction(
                                    "suspend",
                                    suspendOrganizationThunk
                                )
                            }
                        >
                            {
                                isProcessing("suspend")
                                    ? "Suspending..."
                                    : "Suspend"
                            }
                        </Button>

                    )
                }


                {/* =====================================
                    ACTIVE
                    → DEACTIVATE
                ===================================== */}

                {
                    currentStatus === "active" && (

                        <Button
                            variant="outlined"
                            color="error"
                            startIcon={
                                isProcessing("deactivate")
                                    ? (
                                        <CircularProgress
                                            size={18}
                                            color="inherit"
                                        />
                                    )
                                    : (
                                        <Block />
                                    )
                            }
                            disabled={loading}
                            onClick={() =>
                                handleAction(
                                    "deactivate",
                                    deactivateOrganizationThunk
                                )
                            }
                        >
                            {
                                isProcessing("deactivate")
                                    ? "Deactivating..."
                                    : "Deactivate"
                            }
                        </Button>

                    )
                }

            </Box>

            {/* =========================================
                BACK
            ========================================= */}

            <Box
                sx={{
                    display: "flex",
                    justifyContent: "flex-end",
                    mt: 3,
                    pt: 2,
                    borderTop: "1px solid",
                    borderColor: "divider"
                }}
            >

                <Button
                    variant="text"
                    startIcon={
                        <ArrowBack />
                    }
                    onClick={() =>
                        navigate(
                            `/superadmin/organizations/${organizationId}`
                        )
                    }
                >
                    Back to Organization
                </Button>

            </Box>

        </Paper>
    );

};


export default OrganizationStatus;
