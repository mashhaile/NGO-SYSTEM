import {
    useEffect,
    useState
} from "react";


import {
    Box,
    Typography,
    Paper,
    Grid,
    Divider,
    Chip,
    Button,
    Dialog,
    DialogTitle,
    DialogContent,
    DialogActions,
    TextField,
    MenuItem,
    Alert,
    CircularProgress
} from "@mui/material";


import {
    getAllPlansService,
    createPlanService,
    updatePlanService
} from "../services/planService";


// =====================================================
// EMPTY FORM
// =====================================================

const EMPTY_FORM = {

    name: "",

    description: "",

    code: "",

    price: 0,

    currency: "USD",

    billingCycle: "yearly",

    trialDays: 30,

    isActive: true,

    isPublic: true,

    sortOrder: 1,

    limits: {

        users: 0,

        beneficiaries: 0,

        donors: 0,

        donations: 0,

        programs: 0,

        projects: 0,

        activities: 0,

        activityRuns: 0,

        enrollments: 0,

        serviceDeliveries: 0,

        attendanceRecords: 0,

        customFields: 0,

        storageMB: 0,

        enterprises: 0

    },

    features: {

        dashboard: true,

        reports: true,

        apiAccess: false,

        customFields: false,

        notifications: true,

        aiReports: false,

        scheduledReports: false,

        automation: false,

        exports: {

            json: true,

            excel: false,

            csv: false,

            pdf: false

        }

    }

};


// =====================================================
// PAGE
// =====================================================

const PlanListPage = () => {

    const [
        plans,
        setPlans
    ] = useState([]);


    const [
        loading,
        setLoading
    ] = useState(true);


    const [
        saving,
        setSaving
    ] = useState(false);


    const [
        error,
        setError
    ] = useState("");


    const [
        open,
        setOpen
    ] = useState(false);


    const [
        editingPlan,
        setEditingPlan
    ] = useState(null);


    const [
        form,
        setForm
    ] = useState(EMPTY_FORM);


    // =================================================
    // LOAD PLANS
    // =================================================

    const loadPlans = async () => {

        try {

            setLoading(true);

            setError("");

            const response =
                await getAllPlansService();

            setPlans(
                response?.data || []
            );

        } catch (err) {

            setError(
                err?.response?.data?.message ||
                err?.message ||
                "Failed to load plans."
            );

        } finally {

            setLoading(false);

        }

    };


    useEffect(() => {

        loadPlans();

    }, []);


    // =================================================
    // OPEN CREATE
    // =================================================

    const handleCreate = () => {

        setEditingPlan(null);

        setForm({

            ...EMPTY_FORM,

            billingCycle: "yearly",

            trialDays: 30,

            limits: {
                ...EMPTY_FORM.limits
            },

            features: {

                ...EMPTY_FORM.features,

                exports: {
                    ...EMPTY_FORM.features.exports
                }

            }

        });

        setOpen(true);

    };


    // =================================================
    // OPEN EDIT
    // =================================================

    const handleEdit = (plan) => {

        setEditingPlan(plan);

        setForm({

            ...EMPTY_FORM,

            ...plan,

            billingCycle:
                plan.billingCycle === "lifetime"
                    ? "lifetime"
                    : "yearly",

            trialDays:
                plan.billingCycle === "lifetime"
                    ? 0
                    : 30,

            limits: {

                ...EMPTY_FORM.limits,

                ...(plan.limits || {})

            },

            features: {

                ...EMPTY_FORM.features,

                ...(plan.features || {}),

                exports: {

                    ...EMPTY_FORM.features.exports,

                    ...(plan.features?.exports || {})

                }

            }

        });

        setOpen(true);

    };


    // =================================================
    // CLOSE
    // =================================================

    const handleClose = () => {

        if (saving) return;

        setOpen(false);

        setEditingPlan(null);

    };


    // =================================================
    // SIMPLE FIELD
    // =================================================

    const handleChange = (
        field,
        value
    ) => {

        setForm(
            previous => ({

                ...previous,

                [field]:
                    value

            })
        );

    };


    // =================================================
    // LIMIT CHANGE
    // =================================================

    const handleLimitChange = (
        field,
        value
    ) => {

        setForm(
            previous => ({

                ...previous,

                limits: {

                    ...previous.limits,

                    [field]:
                        Number(value)

                }

            })
        );

    };


    // =================================================
    // FEATURE CHANGE
    // =================================================

    const handleFeatureChange = (
        field,
        value
    ) => {

        setForm(
            previous => ({

                ...previous,

                features: {

                    ...previous.features,

                    [field]:
                        value

                }

            })
        );

    };


    // =================================================
    // EXPORT FEATURE CHANGE
    // =================================================

    const handleExportChange = (
        field,
        value
    ) => {

        setForm(
            previous => ({

                ...previous,

                features: {

                    ...previous.features,

                    exports: {

                        ...previous.features.exports,

                        [field]:
                            value

                    }

                }

            })
        );

    };


    // =================================================
    // SAVE
    // =================================================

    const handleSubmit = async () => {

        try {

            setSaving(true);

            setError("");


            const isLifetime =
                form.billingCycle === "lifetime";


            const payload = {

                name:
                    form.name.trim(),

                description:
                    form.description.trim(),

                code:
                    form.code.trim().toUpperCase(),

                price:
                    Number(form.price),

                currency:
                    form.currency.trim().toUpperCase(),

                billingCycle:
                    form.billingCycle,

                // =====================================
                // ALL NON-LIFETIME PLANS = 30 DAYS
                // LIFETIME = 0 DAYS
                // =====================================

                trialDays:
                    isLifetime
                        ? 0
                        : 30,

                isActive:
                    Boolean(form.isActive),

                isPublic:
                    Boolean(form.isPublic),

                sortOrder:
                    Number(form.sortOrder),

                limits:
                    form.limits,

                features:
                    form.features

            };


            if (editingPlan) {

                await updatePlanService(

                    editingPlan._id,

                    payload

                );

            } else {

                await createPlanService(
                    payload
                );

            }


            setOpen(false);

            setEditingPlan(null);

            await loadPlans();

        } catch (err) {

            setError(
                err?.response?.data?.message ||
                err?.message ||
                "Failed to save plan."
            );

        } finally {

            setSaving(false);

        }

    };


    // =================================================
    // RENDER
    // =================================================

    return (

        <Box
            sx={{
                p: 3
            }}
        >

            {/* =========================================
                HEADER
            ========================================= */}

            <Box
                sx={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    mb: 3
                }}
            >

                <Box>

                    <Typography
                        variant="h4"
                        sx={{
                            fontWeight: 700
                        }}
                    >
                        Plans
                    </Typography>

                    <Typography
                        color="text.secondary"
                    >
                        Manage subscription plans, pricing,
                        trial periods, features and limits.
                    </Typography>

                </Box>


                <Button
                    variant="contained"
                    onClick={handleCreate}
                >
                    Create Plan
                </Button>

            </Box>


            {/* =========================================
                ERROR
            ========================================= */}

            {error && (

                <Alert
                    severity="error"
                    sx={{
                        mb: 3
                    }}
                >
                    {error}
                </Alert>

            )}


            {/* =========================================
                LOADING
            ========================================= */}

            {loading ? (

                <Box
                    sx={{
                        display: "flex",
                        justifyContent: "center",
                        py: 8
                    }}
                >

                    <CircularProgress />

                </Box>

            ) : (

                <Grid
                    container
                    spacing={3}
                >

                    {plans.map(
                        plan => (

                            <Grid
                                item
                                xs={12}
                                md={6}
                                lg={4}
                                key={plan._id}
                            >

                                <Paper
                                    sx={{
                                        p: 3,
                                        height: "100%"
                                    }}
                                >

                                    {/* PLAN HEADER */}

                                    <Box
                                        sx={{
                                            display: "flex",
                                            justifyContent: "space-between",
                                            alignItems: "flex-start",
                                            mb: 2
                                        }}
                                    >

                                        <Box>

                                            <Typography
                                                variant="h6"
                                                sx={{
                                                    fontWeight: 700
                                                }}
                                            >
                                                {plan.name}
                                            </Typography>

                                            <Typography
                                                variant="body2"
                                                color="text.secondary"
                                            >
                                                {plan.code}
                                            </Typography>

                                        </Box>


                                        <Chip

                                            label={
                                                plan.isActive
                                                    ? "Active"
                                                    : "Inactive"
                                            }

                                            color={
                                                plan.isActive
                                                    ? "success"
                                                    : "default"
                                            }

                                            size="small"

                                        />

                                    </Box>


                                    {/* PRICE */}

                                    <Typography
                                        variant="h4"
                                        sx={{
                                            fontWeight: 700,
                                            mb: 0.5
                                        }}
                                    >
                                        {plan.currency} {plan.price}
                                    </Typography>


                                    <Typography
                                        variant="body2"
                                        color="text.secondary"
                                        sx={{
                                            mb: 1
                                        }}
                                    >
                                        {plan.billingCycle}
                                    </Typography>


                                    <Chip
                                        size="small"
                                        variant="outlined"
                                        label={
                                            plan.billingCycle === "lifetime"
                                                ? "No trial"
                                                : "30-day trial"
                                        }
                                        sx={{
                                            mb: 2
                                        }}
                                    />


                                    <Typography
                                        variant="body2"
                                        sx={{
                                            mb: 2
                                        }}
                                    >
                                        {plan.description}
                                    </Typography>


                                    <Divider
                                        sx={{
                                            mb: 2
                                        }}
                                    />


                                    {/* LIMITS */}

                                    <Typography
                                        variant="subtitle2"
                                        sx={{
                                            fontWeight: 700,
                                            mb: 1
                                        }}
                                    >
                                        Limits
                                    </Typography>


                                    <Box
                                        sx={{
                                            display: "grid",
                                            gridTemplateColumns:
                                                "1fr 1fr",
                                            gap: 1,
                                            mb: 2
                                        }}
                                    >

                                        {Object.entries(
                                            plan.limits || {}
                                        ).map(
                                            ([key, value]) => (

                                                <Typography
                                                    key={key}
                                                    variant="body2"
                                                >
                                                    <strong>
                                                        {key}:
                                                    </strong>{" "}

                                                    {value === -1
                                                        ? "Unlimited"
                                                        : value
                                                    }

                                                </Typography>

                                            )
                                        )}

                                    </Box>


                                    <Divider
                                        sx={{
                                            mb: 2
                                        }}
                                    />


                                    {/* FEATURES */}

                                    <Typography
                                        variant="subtitle2"
                                        sx={{
                                            fontWeight: 700,
                                            mb: 1
                                        }}
                                    >
                                        Features
                                    </Typography>


                                    <Box
                                        sx={{
                                            display: "flex",
                                            flexWrap: "wrap",
                                            gap: 0.75,
                                            mb: 3
                                        }}
                                    >

                                        {Object.entries(
                                            plan.features || {}
                                        ).map(
                                            ([key, value]) => {

                                                if (
                                                    typeof value ===
                                                    "object"
                                                ) {

                                                    return null;

                                                }


                                                return (

                                                    <Chip
                                                        key={key}
                                                        label={`${key}: ${
                                                            value
                                                                ? "Yes"
                                                                : "No"
                                                        }`}
                                                        size="small"
                                                        variant="outlined"
                                                    />

                                                );

                                            }
                                        )}

                                    </Box>


                                    {/* ACTION */}

                                    <Button
                                        variant="outlined"
                                        fullWidth
                                        onClick={() =>
                                            handleEdit(plan)
                                        }
                                    >
                                        Edit Plan
                                    </Button>

                                </Paper>

                            </Grid>

                        )
                    )}

                </Grid>

            )}


            {/* =========================================
                CREATE / EDIT DIALOG
            ========================================= */}

            <Dialog
                open={open}
                onClose={handleClose}
                fullWidth
                maxWidth="md"
            >

                <DialogTitle>

                    {editingPlan
                        ? "Edit Plan"
                        : "Create Plan"
                    }

                </DialogTitle>


                <DialogContent>

                    <Grid
                        container
                        spacing={2}
                        sx={{
                            mt: 0.5
                        }}
                    >

                        {/* BASIC */}

                        <Grid
                            item
                            xs={12}
                            md={6}
                        >

                            <TextField
                                fullWidth
                                label="Plan Name"
                                value={form.name}
                                onChange={e =>
                                    handleChange(
                                        "name",
                                        e.target.value
                                    )
                                }
                            />

                        </Grid>


                        <Grid
                            item
                            xs={12}
                            md={6}
                        >

                            <TextField
                                fullWidth
                                label="Plan Code"
                                value={form.code}
                                onChange={e =>
                                    handleChange(
                                        "code",
                                        e.target.value
                                    )
                                }
                            />

                        </Grid>


                        <Grid
                            item
                            xs={12}
                        >

                            <TextField
                                fullWidth
                                multiline
                                minRows={2}
                                label="Description"
                                value={form.description}
                                onChange={e =>
                                    handleChange(
                                        "description",
                                        e.target.value
                                    )
                                }
                            />

                        </Grid>


                        {/* PRICE */}

                        <Grid
                            item
                            xs={12}
                            md={4}
                        >

                            <TextField
                                fullWidth
                                type="number"
                                label="Price"
                                value={form.price}
                                onChange={e =>
                                    handleChange(
                                        "price",
                                        Number(e.target.value)
                                    )
                                }
                            />

                        </Grid>


                        <Grid
                            item
                            xs={12}
                            md={4}
                        >

                            <TextField
                                fullWidth
                                label="Currency"
                                value={form.currency}
                                onChange={e =>
                                    handleChange(
                                        "currency",
                                        e.target.value
                                    )
                                }
                            />

                        </Grid>


                        <Grid
                            item
                            xs={12}
                            md={4}
                        >

                            <TextField
                                fullWidth
                                select
                                label="Billing Cycle"
                                value={form.billingCycle}
                                onChange={e =>
                                    handleChange(
                                        "billingCycle",
                                        e.target.value
                                    )
                                }
                            >

                                <MenuItem value="yearly">
                                    Yearly
                                </MenuItem>

                                <MenuItem value="lifetime">
                                    Lifetime
                                </MenuItem>

                            </TextField>

                        </Grid>


                        {/* TRIAL */}

                        <Grid
                            item
                            xs={12}
                            md={4}
                        >

                            <TextField
                                fullWidth
                                type="number"
                                label="Trial Days"
                                value={
                                    form.billingCycle === "lifetime"
                                        ? 0
                                        : 30
                                }
                                InputProps={{
                                    readOnly: true
                                }}
                                helperText={
                                    form.billingCycle === "lifetime"
                                        ? "Lifetime plans do not have a trial."
                                        : "All non-lifetime plans have a 30-day trial."
                                }
                            />

                        </Grid>


                        {/* SORT ORDER */}

                        <Grid
                            item
                            xs={12}
                            md={4}
                        >

                            <TextField
                                fullWidth
                                type="number"
                                label="Sort Order"
                                value={form.sortOrder}
                                onChange={e =>
                                    handleChange(
                                        "sortOrder",
                                        Number(e.target.value)
                                    )
                                }
                            />

                        </Grid>


                        {/* STATUS */}

                        <Grid
                            item
                            xs={12}
                            md={4}
                        >

                            <TextField
                                fullWidth
                                select
                                label="Status"
                                value={
                                    form.isActive
                                        ? "active"
                                        : "inactive"
                                }
                                onChange={e =>
                                    handleChange(
                                        "isActive",
                                        e.target.value ===
                                            "active"
                                    )
                                }
                            >

                                <MenuItem value="active">
                                    Active
                                </MenuItem>

                                <MenuItem value="inactive">
                                    Inactive
                                </MenuItem>

                            </TextField>

                        </Grid>


                        {/* LIMITS */}

                        <Grid
                            item
                            xs={12}
                        >

                            <Typography
                                variant="h6"
                                sx={{
                                    mt: 2,
                                    mb: 1
                                }}
                            >
                                Resource Limits
                            </Typography>

                        </Grid>


                        {Object.keys(
                            form.limits
                        ).map(
                            field => (

                                <Grid
                                    item
                                    xs={12}
                                    sm={6}
                                    md={3}
                                    key={field}
                                >

                                    <TextField
                                        fullWidth
                                        type="number"
                                        label={field}
                                        value={
                                            form.limits[field]
                                        }
                                        onChange={e =>
                                            handleLimitChange(
                                                field,
                                                e.target.value
                                            )
                                        }
                                        helperText="-1 = unlimited"
                                    />

                                </Grid>

                            )
                        )}


                        {/* FEATURES */}

                        <Grid
                            item
                            xs={12}
                        >

                            <Typography
                                variant="h6"
                                sx={{
                                    mt: 2,
                                    mb: 1
                                }}
                            >
                                Features
                            </Typography>

                        </Grid>


                        {Object.keys(
                            form.features
                        )
                            .filter(
                                key =>
                                    key !== "exports"
                            )
                            .map(
                                field => (

                                    <Grid
                                        item
                                        xs={12}
                                        sm={6}
                                        md={3}
                                        key={field}
                                    >

                                        <TextField
                                            fullWidth
                                            select
                                            label={field}
                                            value={
                                                form.features[field]
                                                    ? "yes"
                                                    : "no"
                                            }
                                            onChange={e =>
                                                handleFeatureChange(
                                                    field,
                                                    e.target.value ===
                                                        "yes"
                                                )
                                            }
                                        >

                                            <MenuItem value="yes">
                                                Yes
                                            </MenuItem>

                                            <MenuItem value="no">
                                                No
                                            </MenuItem>

                                        </TextField>

                                    </Grid>

                                )
                            )}


                        {/* EXPORTS */}

                        <Grid
                            item
                            xs={12}
                        >

                            <Typography
                                variant="subtitle1"
                                sx={{
                                    mt: 1,
                                    mb: 1,
                                    fontWeight: 700
                                }}
                            >
                                Export Features
                            </Typography>

                        </Grid>


                        {Object.keys(
                            form.features.exports
                        ).map(
                            field => (

                                <Grid
                                    item
                                    xs={12}
                                    sm={6}
                                    md={3}
                                    key={field}
                                >

                                    <TextField
                                        fullWidth
                                        select
                                        label={field}
                                        value={
                                            form.features.exports[field]
                                                ? "yes"
                                                : "no"
                                        }
                                        onChange={e =>
                                            handleExportChange(
                                                field,
                                                e.target.value ===
                                                    "yes"
                                            )
                                        }
                                    >

                                        <MenuItem value="yes">
                                            Yes
                                        </MenuItem>

                                        <MenuItem value="no">
                                            No
                                        </MenuItem>

                                    </TextField>

                                </Grid>

                            )
                        )}

                    </Grid>

                </DialogContent>


                <DialogActions
                    sx={{
                        p: 2
                    }}
                >

                    <Button
                        onClick={handleClose}
                        disabled={saving}
                    >
                        Cancel
                    </Button>


                    <Button
                        variant="contained"
                        onClick={handleSubmit}
                        disabled={
                            saving ||
                            !form.name.trim() ||
                            !form.code.trim()
                        }
                    >

                        {saving
                            ? "Saving..."
                            : editingPlan
                                ? "Update Plan"
                                : "Create Plan"
                        }

                    </Button>

                </DialogActions>

            </Dialog>

        </Box>

    );

};


export default PlanListPage;