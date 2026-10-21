import {
    useState
} from "react";


import {
    useNavigate
} from "react-router-dom";


import {
    Box,
    Paper,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Typography,
    Chip,
    IconButton,
    Tooltip,
    Dialog,
    DialogTitle,
    DialogContent,
    DialogContentText,
    DialogActions,
    Button,
    CircularProgress
} from "@mui/material";


import {
    Visibility,
    Edit,
    PauseCircle,
    Block,
    DeleteForever,
    Restore,
    CheckCircle
} from "@mui/icons-material";


import {
    useDispatch
} from "react-redux";


import {
    activateOrganizationThunk,
    suspendOrganizationThunk,
    deactivateOrganizationThunk,
    restoreOrganizationThunk,
    deleteOrganizationThunk,
    getOrganizationsThunk
} from "../store/organizationThunks";

import EmptyState
    from "../../../components/ui/EmptyState";


// =====================================================
// COMPONENT
// =====================================================

const OrganizationTable = ({
    organizations = []
}) => {

    const navigate =
        useNavigate();


    const dispatch =
        useDispatch();


    // =================================================
    // STATE
    // =================================================

    const [
        confirmDialog,
        setConfirmDialog
    ] = useState({

        open: false,

        type: null,

        organization: null

    });


    const [
        actionLoading,
        setActionLoading
    ] = useState(false);


    // =================================================
    // HELPERS
    // =================================================

    const getOrganizationId = (
        organization
    ) => {

        return (
            organization?._id ||
            organization?.id
        );

    };


    const getOrganizationName = (
        organization
    ) => {

        return (
            organization?.name ||
            organization?.organizationName ||
            "Unnamed Organization"
        );

    };


    const getStatus = (
        organization
    ) => {

        return (
            organization?.status ||
            (
                organization?.isActive
                    ? "active"
                    : "inactive"
            )
        );

    };


    const getStatusColor = (
        status
    ) => {

        switch (
            String(status)
                .toLowerCase()
        ) {

            case "active":
                return "success";

            case "inactive":
                return "default";

            case "suspended":
                return "warning";

            case "cancelled":
                return "error";

            case "expired":
                return "error";

            case "trial":
                return "info";

            default:
                return "default";

        }

    };


    // =================================================
    // PLAN
    // =================================================

    const getPlanName = (
        organization
    ) => {

        return (
            organization?.subscription
                ?.planSnapshot
                ?.name ||

            organization?.subscription
                ?.plan
                ?.name ||

            organization?.plan
                ?.name ||

            "No Plan"
        );

    };


    const getPlanColor = (
        organization
    ) => {

        const plan =
            String(
                getPlanName(
                    organization
                )
            )
                .toLowerCase();


        switch (plan) {

            case "professional":
                return "primary";

            case "enterprise":
                return "secondary";

            case "basic":
                return "info";

            case "trial":
                return "warning";

            default:
                return "default";

        }

    };


    // =================================================
    // OPEN DIALOG
    // =================================================

    const openConfirmDialog = (
        type,
        organization
    ) => {

        setConfirmDialog({

            open: true,

            type,

            organization

        });

    };


    // =================================================
    // CLOSE DIALOG
    // =================================================

    const handleCloseDialog = () => {

        if (actionLoading) {

            return;

        }


        setConfirmDialog({

            open: false,

            type: null,

            organization: null

        });

    };


    // =================================================
    // CONFIRM ACTION
    // =================================================

    const handleConfirmAction = async () => {

        const organization =
            confirmDialog.organization;


        if (!organization) {

            return;

        }


        const id =
            getOrganizationId(
                organization
            );


        if (!id) {

            return;

        }


        try {

            setActionLoading(true);


            let result = null;


            // =========================================
            // ACTIVATE
            // =========================================

            if (
                confirmDialog.type ===
                "activate"
            ) {

                result =
                    await dispatch(
                        activateOrganizationThunk(
                            id
                        )
                    );

            }


            // =========================================
            // SUSPEND
            // =========================================

            else if (
                confirmDialog.type ===
                "suspend"
            ) {

                result =
                    await dispatch(
                        suspendOrganizationThunk(
                            id
                        )
                    );

            }


            // =========================================
            // DEACTIVATE
            // =========================================

            else if (
                confirmDialog.type ===
                "deactivate"
            ) {

                result =
                    await dispatch(
                        deactivateOrganizationThunk(
                            id
                        )
                    );

            }


            // =========================================
            // RESTORE
            // =========================================

            else if (
                confirmDialog.type ===
                "restore"
            ) {

                result =
                    await dispatch(
                        restoreOrganizationThunk(
                            id
                        )
                    );

            }


            // =========================================
            // DELETE
            // =========================================

            else if (
                confirmDialog.type ===
                "delete"
            ) {

                result =
                    await dispatch(
                        deleteOrganizationThunk(
                            id
                        )
                    );

            }


            // =========================================
            // SUCCESS
            // =========================================

            if (
                result &&
                (
                    activateOrganizationThunk
                        .fulfilled
                        .match(result) ||

                    suspendOrganizationThunk
                        .fulfilled
                        .match(result) ||

                    deactivateOrganizationThunk
                        .fulfilled
                        .match(result) ||

                    restoreOrganizationThunk
                        .fulfilled
                        .match(result) ||

                    deleteOrganizationThunk
                        .fulfilled
                        .match(result)
                )
            ) {

                setConfirmDialog({

                    open: false,

                    type: null,

                    organization: null

                });


                dispatch(
                    getOrganizationsThunk()
                );

            }

        }

        catch (error) {

            console.error(
                "Organization lifecycle action error:",
                error
            );

        }

        finally {

            setActionLoading(false);

        }

    };


    // =================================================
    // EMPTY STATE
    // =================================================

    if (
        !organizations ||
        organizations.length === 0
    ) {

        return (

            <EmptyState
                title="No organizations found"
                message="There are currently no organizations to display."
            />

        );

    }


    // =================================================
    // TABLE
    // =================================================

    return (
        <>

            <TableContainer
                component={Paper}
                sx={{
                    width: "100%",
                    overflowX: "auto"
                }}
            >

                <Table
                    size="small"
                >

                    {/* =================================
                        HEADER
                    ================================= */}

                    <TableHead>

                        <TableRow>

                            <TableCell
                                sx={{
                                    fontWeight: 700
                                }}
                            >
                                Organization
                            </TableCell>


                            <TableCell
                                sx={{
                                    fontWeight: 700
                                }}
                            >
                                Email
                            </TableCell>


                            <TableCell
                                sx={{
                                    fontWeight: 700
                                }}
                            >
                                Phone
                            </TableCell>


                            <TableCell
                                sx={{
                                    fontWeight: 700
                                }}
                            >
                                Plan
                            </TableCell>


                            <TableCell
                                sx={{
                                    fontWeight: 700
                                }}
                            >
                                Status
                            </TableCell>


                            <TableCell
                                align="right"
                                sx={{
                                    fontWeight: 700
                                }}
                            >
                                Actions
                            </TableCell>

                        </TableRow>

                    </TableHead>


                    {/* =================================
                        BODY
                    ================================= */}

                    <TableBody>

                        {
                            organizations.map(
                                organization => {

                                    const id =
                                        getOrganizationId(
                                            organization
                                        );


                                    const status =
                                        getStatus(
                                            organization
                                        );


                                    const plan =
                                        getPlanName(
                                            organization
                                        );


                                    const normalizedStatus =
                                        String(
                                            status
                                        ).toLowerCase();


                                    const isDeleted =
                                        organization?.isDeleted ===
                                        true;


                                    const isActive =
                                        normalizedStatus ===
                                        "active";






                                    return (
                                        <TableRow
                                            key={id}
                                            hover
                                        >

                                            {/* =============================
                                                ORGANIZATION
                                            ============================= */}

                                            <TableCell>

                                                <Box>

                                                    <Typography
                                                        variant="body2"
                                                        sx={{
                                                            fontWeight: 600
                                                        }}
                                                    >

                                                        {
                                                            getOrganizationName(
                                                                organization
                                                            )
                                                        }

                                                    </Typography>


                                                    {
                                                        (
                                                            organization?.organizationCode ||
                                                            organization?.code
                                                        ) && (

                                                            <Typography
                                                                variant="caption"
                                                                sx={{
                                                                    color: "text.secondary",
                                                                    display: "block",
                                                                    mt: 0.25
                                                                }}>

                                                                Code:{" "}

                                                                {
                                                                    organization?.organizationCode ||
                                                                    organization?.code
                                                                }

                                                            </Typography>

                                                        )
                                                    }

                                                </Box>

                                            </TableCell>

                                            {/* =============================
                                                EMAIL
                                            ============================= */}

                                            <TableCell>

                                                {
                                                    organization?.email ||
                                                    organization?.contactEmail ||
                                                    "—"
                                                }

                                            </TableCell>

                                            {/* =============================
                                                PHONE
                                            ============================= */}

                                            <TableCell>

                                                {
                                                    organization?.phone ||
                                                    organization?.contactPhone ||
                                                    "—"
                                                }

                                            </TableCell>

                                            {/* =============================
                                                PLAN
                                            ============================= */}

                                            <TableCell>

                                                <Chip
                                                    size="small"
                                                    label={
                                                        plan
                                                    }
                                                    color={
                                                        getPlanColor(
                                                            organization
                                                        )
                                                    }
                                                    variant="outlined"
                                                />

                                            </TableCell>

                                            {/* =============================
                                                STATUS
                                            ============================= */}

                                            <TableCell>

                                                <Chip
                                                    size="small"
                                                    label={
                                                        isDeleted
                                                            ? "Deleted"
                                                            : (
                                                                String(
                                                                    status
                                                                )
                                                                    .charAt(0)
                                                                    .toUpperCase() +
                                                                String(
                                                                    status
                                                                )
                                                                    .slice(1)
                                                            )
                                                    }
                                                    color={
                                                        isDeleted
                                                            ? "error"
                                                            : getStatusColor(
                                                                status
                                                            )
                                                    }
                                                />

                                            </TableCell>

                                            {/* =============================
                                                ACTIONS
                                            ============================= */}

                                            <TableCell
                                                align="right"
                                            >

                                                {/* =================================
                                                    DELETED ORGANIZATION
                                                ================================= */}

                                                {
                                                    isDeleted ? (

                                                        <>

                                                            <Tooltip
                                                                title="Restore organization"
                                                            >

                                                                <IconButton
                                                                    size="small"
                                                                    color="success"
                                                                    onClick={() =>
                                                                        openConfirmDialog(
                                                                            "restore",
                                                                            organization
                                                                        )
                                                                    }
                                                                >

                                                                    <Restore
                                                                        fontSize="small"
                                                                    />

                                                                </IconButton>

                                                            </Tooltip>

                                                        </>

                                                    ) : (

                                                        <>

                                                            {/* =============================
                                                                VIEW
                                                            ============================= */}

                                                            <Tooltip
                                                                title="View organization"
                                                            >

                                                                <IconButton
                                                                    size="small"
                                                                    onClick={() =>
                                                                        navigate(
                                                                            `/superadmin/organizations/${id}`
                                                                        )
                                                                    }
                                                                >

                                                                    <Visibility
                                                                        fontSize="small"
                                                                    />

                                                                </IconButton>

                                                            </Tooltip>


                                                            {/* =============================
                                                                EDIT
                                                            ============================= */}

                                                            <Tooltip
                                                                title="Edit organization"
                                                            >

                                                                <IconButton
                                                                    size="small"
                                                                    color="primary"
                                                                    onClick={() =>
                                                                        navigate(
                                                                            `/superadmin/organizations/${id}/edit`
                                                                        )
                                                                    }
                                                                >

                                                                    <Edit
                                                                        fontSize="small"
                                                                    />

                                                                </IconButton>

                                                            </Tooltip>


                                                            {/* =============================
                                                                ACTIVATE
                                                            ============================= */}

                                                            {
                                                                !isActive && (

                                                                    <Tooltip
                                                                        title="Activate organization"
                                                                    >

                                                                        <IconButton
                                                                            size="small"
                                                                            color="success"
                                                                            onClick={() =>
                                                                                openConfirmDialog(
                                                                                    "activate",
                                                                                    organization
                                                                                )
                                                                            }
                                                                        >

                                                                            <CheckCircle
                                                                                fontSize="small"
                                                                            />

                                                                        </IconButton>

                                                                    </Tooltip>

                                                                )
                                                            }


                                                            {/* =============================
                                                                SUSPEND
                                                            ============================= */}

                                                            {
                                                                 isActive && (
                                                                    <Tooltip
                                                                        title="Suspend organization"
                                                                    >

                                                                        <IconButton
                                                                            size="small"
                                                                            color="warning"
                                                                            onClick={() =>
                                                                                openConfirmDialog(
                                                                                    "suspend",
                                                                                    organization
                                                                                )
                                                                            }
                                                                        >

                                                                            <PauseCircle
                                                                                fontSize="small"
                                                                            />

                                                                        </IconButton>

                                                                    </Tooltip>

                                                                )
                                                            }


                                                            {/* =============================
                                                                DEACTIVATE
                                                            ============================= */}

                                                            {
                                                                        isActive && (

                                                                    <Tooltip
                                                                        title="Deactivate organization"
                                                                    >

                                                                        <IconButton
                                                                            size="small"
                                                                            color="default"
                                                                            onClick={() =>
                                                                                openConfirmDialog(
                                                                                    "deactivate",
                                                                                    organization
                                                                                )
                                                                            }
                                                                        >

                                                                            <Block
                                                                                fontSize="small"
                                                                            />

                                                                        </IconButton>

                                                                    </Tooltip>

                                                                )
                                                            }


                                                            {/* =============================
                                                                DELETE
                                                            ============================= */}

                                                            <Tooltip
                                                                title="Delete organization"
                                                            >

                                                                <IconButton
                                                                    size="small"
                                                                    color="error"
                                                                    onClick={() =>
                                                                        openConfirmDialog(
                                                                            "delete",
                                                                            organization
                                                                        )
                                                                    }
                                                                >

                                                                    <DeleteForever
                                                                        fontSize="small"
                                                                    />

                                                                </IconButton>

                                                            </Tooltip>

                                                        </>

                                                    )
                                                }

                                            </TableCell>

                                        </TableRow>
                                    );

                                }
                            )
                        }

                    </TableBody>

                </Table>

            </TableContainer>

            {/* =================================================
                CONFIRMATION DIALOG
            ================================================= */}

            <Dialog
                open={
                    confirmDialog.open
                }
                onClose={
                    handleCloseDialog
                }
                maxWidth="xs"
                fullWidth
            >

                <DialogTitle>

                    {
                        confirmDialog.type ===
                        "activate"

                            ? "Activate Organization?"

                            : confirmDialog.type ===
                              "suspend"

                                ? "Suspend Organization?"

                                : confirmDialog.type ===
                                  "deactivate"

                                    ? "Deactivate Organization?"

                                    : confirmDialog.type ===
                                      "restore"

                                        ? "Restore Organization?"

                                        : "Delete Organization?"
                    }

                </DialogTitle>


                <DialogContent>

                    <DialogContentText>

                        {
                            confirmDialog.type ===
                            "activate"

                                ? (
                                    <>
                                        Are you sure you want to activate{" "}
                                        <strong>
                                            {
                                                getOrganizationName(
                                                    confirmDialog.organization
                                                )
                                            }
                                        </strong>
                                        ?
                                    </>
                                )

                                : confirmDialog.type ===
                                  "suspend"

                                    ? (
                                        <>
                                            Are you sure you want to suspend{" "}
                                            <strong>
                                                {
                                                    getOrganizationName(
                                                        confirmDialog.organization
                                                    )
                                                }
                                            </strong>
                                            ? The organization will temporarily
                                            be prevented from normal operation.
                                        </>
                                    )

                                    : confirmDialog.type ===
                                      "deactivate"

                                        ? (
                                            <>
                                                Are you sure you want to deactivate{" "}
                                                <strong>
                                                    {
                                                        getOrganizationName(
                                                            confirmDialog.organization
                                                        )
                                                    }
                                                </strong>
                                                ? The organization will become inactive.
                                            </>
                                        )

                                        : confirmDialog.type ===
                                          "restore"

                                            ? (
                                                <>
                                                    Are you sure you want to restore{" "}
                                                    <strong>
                                                        {
                                                            getOrganizationName(
                                                                confirmDialog.organization
                                                            )
                                                        }
                                                    </strong>
                                                    ?
                                                </>
                                            )

                                            : (
                                                <>
                                                    Are you sure you want to delete{" "}
                                                    <strong>
                                                        {
                                                            getOrganizationName(
                                                                confirmDialog.organization
                                                            )
                                                        }
                                                    </strong>
                                                    ? The organization will be
                                                    soft deleted and can be restored later.
                                                </>
                                            )
                        }

                    </DialogContentText>

                </DialogContent>


                <DialogActions
                    sx={{
                        px: 3,
                        pb: 2
                    }}
                >

                    <Button
                        onClick={
                            handleCloseDialog
                        }
                        disabled={
                            actionLoading
                        }
                    >
                        Cancel
                    </Button>


                    <Button
                        variant="contained"
                        color={
                            confirmDialog.type ===
                            "restore" ||
                            confirmDialog.type ===
                            "activate"
                                ? "success"
                                : confirmDialog.type ===
                                  "suspend"
                                    ? "warning"
                                    : "error"
                        }
                        onClick={
                            handleConfirmAction
                        }
                        disabled={
                            actionLoading
                        }
                        startIcon={
                            actionLoading
                                ? (
                                    <CircularProgress
                                        size={18}
                                        color="inherit"
                                    />
                                )
                                : null
                        }
                    >

                        {
                            actionLoading

                                ? "Processing..."

                                : confirmDialog.type ===
                                  "activate"

                                    ? "Activate"

                                    : confirmDialog.type ===
                                      "suspend"

                                        ? "Suspend"

                                        : confirmDialog.type ===
                                          "deactivate"

                                            ? "Deactivate"

                                            : confirmDialog.type ===
                                              "restore"

                                                ? "Restore"

                                                : "Delete"
                        }

                    </Button>

                </DialogActions>

            </Dialog>

        </>
    );

};


export default OrganizationTable;