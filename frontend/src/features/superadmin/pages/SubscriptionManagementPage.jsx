import {
    useEffect,
    useState
} from "react";


import {
    Box,
    Typography,
    Paper,
    Grid,
    TextField,
    MenuItem,
    Button,
    Alert,
    CircularProgress
} from "@mui/material";


import {
    getActivePlansService,
    assignSubscriptionService,
    changePlanService,
    renewSubscriptionService,
    cancelSubscriptionService,
    getOrganizationSubscriptionService,
    getOrganizationSubscriptionUsageService
} from "../services/subscriptionService";


import {
    getOrganizationsService
} from "../services/organizationService";

import SubscriptionDetails
    from "../components/SubscriptionDetails";


// =====================================================
// PAGE
// =====================================================

const SubscriptionManagementPage = () => {

    // =================================================
    // STATE
    // =================================================

    const [
        organizations,
        setOrganizations
    ] = useState([]);


    const [
        plans,
        setPlans
    ] = useState([]);


    const [
        selectedOrganization,
        setSelectedOrganization
    ] = useState("");


    const [
        subscription,
        setSubscription
    ] = useState(null);


    const [
        usage,
        setUsage
    ] = useState(null);


    const [
        loading,
        setLoading
    ] = useState(true);


    const [
        loadingSubscription,
        setLoadingSubscription
    ] = useState(false);


    const [
        saving,
        setSaving
    ] = useState(false);


    const [
        error,
        setError
    ] = useState("");


    const [
        success,
        setSuccess
    ] = useState("");


    const [
        selectedPlan,
        setSelectedPlan
    ] = useState("");


    const [
        cancelReason,
        setCancelReason
    ] = useState("");


    // =================================================
    // LOAD ORGANIZATIONS + PLANS
    // =================================================

    useEffect(() => {

        const loadData = async () => {

            try {

                setLoading(true);

                setError("");


                const [
                    organizationsResponse,
                    plansResponse
                ] = await Promise.all([

                    getOrganizationsService(),

                    getActivePlansService()

                ]);


                // -----------------------------------------
                // ORGANIZATIONS
                // -----------------------------------------

                const organizationData =
                    organizationsResponse?.data;


                const organizationList =
                    Array.isArray(
                        organizationData
                    )

                        ? organizationData

                        : Array.isArray(
                            organizationData?.organizations
                        )

                            ? organizationData.organizations

                            : Array.isArray(
                                organizationsResponse?.organizations
                            )

                                ? organizationsResponse.organizations

                                : [];


                setOrganizations(
                    organizationList
                );


                // -----------------------------------------
                // PLANS
                // -----------------------------------------

                const planData =
                    plansResponse?.data;


                const planList =
                    Array.isArray(
                        planData
                    )

                        ? planData

                        : Array.isArray(
                            planData?.plans
                        )

                            ? planData.plans

                            : Array.isArray(
                                plansResponse?.plans
                            )

                                ? plansResponse.plans

                                : [];


                setPlans(
                    planList
                );

            }

            catch (err) {

                setError(
                    err?.response?.data?.message ||
                    err?.message ||
                    "Failed to load organizations and plans."
                );

                setOrganizations([]);

                setPlans([]);

            }

            finally {

                setLoading(false);

            }

        };


        loadData();

    }, []);


    // =================================================
    // LOAD SUBSCRIPTION + USAGE
    // =================================================

    const loadSubscription = async (
        organizationId
    ) => {

        if (!organizationId) {

            setSubscription(null);

            setUsage(null);

            return;

        }


        try {

            setLoadingSubscription(true);

            setError("");

            setSubscription(null);

            setUsage(null);


            const [
                subscriptionResponse,
                usageResponse
            ] = await Promise.all([

                getOrganizationSubscriptionService(
                    organizationId
                ),

                getOrganizationSubscriptionUsageService(
                    organizationId
                )

            ]);


            setSubscription(
                subscriptionResponse?.data || null
            );


            setUsage(
                usageResponse?.data || null
            );

        }

        catch (err) {

            console.error(
                "LOAD ORGANIZATION SUBSCRIPTION ERROR:",
                err
            );


            setSubscription(null);

            setUsage(null);


            setError(
                err?.response?.data?.message ||
                err?.message ||
                "Failed to load organization subscription."
            );

        }

        finally {

            setLoadingSubscription(false);

        }

    };


    // =================================================
    // ORGANIZATION CHANGE
    // =================================================

    const handleOrganizationChange = async (
        event
    ) => {

        const organizationId =
            event.target.value;


        setSelectedOrganization(
            organizationId
        );


        setSelectedPlan("");

        setCancelReason("");

        setError("");

        setSuccess("");


        await loadSubscription(
            organizationId
        );

    };


    // =================================================
    // FIND ORGANIZATION
    // =================================================

    const organization =
        organizations.find(
            item =>
                item._id ===
                selectedOrganization
        );


    // =================================================
    // ASSIGN / CHANGE PLAN
    // =================================================

    const handlePlanSubmit = async () => {

        if (
            !selectedOrganization ||
            !selectedPlan
        ) {

            setError(
                "Please select an organization and plan."
            );

            return;

        }


        try {

            setSaving(true);

            setError("");

            setSuccess("");


            if (subscription) {

                await changePlanService(

                    selectedOrganization,

                    {
                        planId:
                            selectedPlan
                    }

                );


                setSuccess(
                    "Subscription plan changed successfully."
                );

            }

            else {

                await assignSubscriptionService({

                    organizationId:
                        selectedOrganization,

                    planId:
                        selectedPlan

                });


                setSuccess(
                    "Subscription assigned successfully."
                );

            }


            await loadSubscription(
                selectedOrganization
            );

        }

        catch (err) {

            setError(
                err?.response?.data?.message ||
                err?.message ||
                "Failed to update subscription."
            );

        }

        finally {

            setSaving(false);

        }

    };


    // =================================================
    // RENEW
    // =================================================

    const handleRenew = async () => {

        if (!selectedOrganization) {

            return;

        }


        try {

            setSaving(true);

            setError("");

            setSuccess("");


            await renewSubscriptionService(
                selectedOrganization
            );


            setSuccess(
                "Subscription renewed successfully."
            );


            await loadSubscription(
                selectedOrganization
            );

        }

        catch (err) {

            setError(
                err?.response?.data?.message ||
                err?.message ||
                "Failed to renew subscription."
            );

        }

        finally {

            setSaving(false);

        }

    };


    // =================================================
    // CANCEL
    // =================================================

    const handleCancel = async () => {

        if (!selectedOrganization) {

            return;

        }


        try {

            setSaving(true);

            setError("");

            setSuccess("");


            await cancelSubscriptionService(

                selectedOrganization,

                {
                    reason:
                        cancelReason
                }

            );


            setSuccess(
                "Subscription cancelled successfully."
            );


            await loadSubscription(
                selectedOrganization
            );

        }

        catch (err) {

            setError(
                err?.response?.data?.message ||
                err?.message ||
                "Failed to cancel subscription."
            );

        }

        finally {

            setSaving(false);

        }

    };


    // =================================================
    // LOADING
    // =================================================

    if (loading) {

        return (

            <Box
                sx={{
                    p: 3,
                    display: "flex",
                    justifyContent: "center",
                    py: 8
                }}
            >

                <CircularProgress />

            </Box>

        );

    }


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
                    mb: 3
                }}
            >

                <Typography
                    variant="h4"
                    sx={{
                        fontWeight: 700
                    }}
                >
                    Subscription Management
                </Typography>


                <Typography
                    sx={{
                        color: "text.secondary"
                    }}
                >
                    Manage organization subscriptions,
                    plans and resource usage.
                </Typography>

            </Box>

            {/* =========================================
                ALERTS
            ========================================= */}

            {error && (

                <Alert
                    severity="error"
                    sx={{
                        mb: 2
                    }}
                    onClose={() =>
                        setError("")
                    }
                >
                    {error}
                </Alert>

            )}

            {success && (

                <Alert
                    severity="success"
                    sx={{
                        mb: 2
                    }}
                    onClose={() =>
                        setSuccess("")
                    }
                >
                    {success}
                </Alert>

            )}

            {/* =========================================
                ORGANIZATION
            ========================================= */}

            <Paper
                sx={{
                    p: 3,
                    mb: 3
                }}
            >

                <Typography
                    variant="h6"
                    sx={{
                        fontWeight: 700,
                        mb: 2
                    }}
                >
                    Organization
                </Typography>


                <TextField
                    select
                    fullWidth
                    label="Select Organization"
                    value={
                        selectedOrganization
                    }
                    onChange={
                        handleOrganizationChange
                    }
                >

                    <MenuItem value="">
                        Select organization
                    </MenuItem>


                    {organizations.map(
                        item => (

                            <MenuItem
                                key={item._id}
                                value={item._id}
                            >
                                {
                                    item.name ||
                                    item.organizationName ||
                                    item._id
                                }
                            </MenuItem>

                        )
                    )}

                </TextField>


                {organization && (

                    <Box
                        sx={{
                            mt: 2
                        }}
                    >

                        <Typography
                            variant="body2"
                            sx={{
                                color: "text.secondary"
                            }}
                        >
                            Organization ID
                        </Typography>


                        <Typography>
                            {organization._id}
                        </Typography>

                    </Box>

                )}

            </Paper>

            {/* =========================================
                LOADING SUBSCRIPTION
            ========================================= */}

            {selectedOrganization &&
                loadingSubscription && (

                    <Paper
                        sx={{
                            p: 3,
                            mb: 3,
                            display: "flex",
                            alignItems: "center",
                            gap: 2
                        }}
                    >

                        <CircularProgress
                            size={24}
                        />

                        <Typography>
                            Loading subscription...
                        </Typography>

                    </Paper>

                )}

            {/* =========================================
                PLAN MANAGEMENT
            ========================================= */}

            {selectedOrganization &&
                !loadingSubscription && (

                    <Paper
                        sx={{
                            p: 3,
                            mb: 3
                        }}
                    >

                        <Typography
                            variant="h6"
                            sx={{
                                fontWeight: 700,
                                mb: 2
                            }}
                        >
                            Plan Management
                        </Typography>


                        <Grid
                            container
                            spacing={2}
                        >

                            <Grid
                                size={{ xs: 12, md: 8 }}
                            >

                                <TextField
                                    select
                                    fullWidth
                                    label="Plan"
                                    value={
                                        selectedPlan
                                    }
                                    onChange={
                                        e =>
                                            setSelectedPlan(
                                                e.target.value
                                            )
                                    }
                                >

                                    <MenuItem value="">
                                        Select plan
                                    </MenuItem>


                                    {plans.map(
                                        plan => (

                                            <MenuItem
                                                key={
                                                    plan._id
                                                }
                                                value={
                                                    plan._id
                                                }
                                            >

                                                {plan.name}
                                                {" — "}
                                                {plan.currency}
                                                {" "}
                                                {plan.price}
                                                {" / "}
                                                {plan.billingCycle}

                                            </MenuItem>

                                        )
                                    )}

                                </TextField>

                            </Grid>


                            <Grid
                                size={{ xs: 12, md: 4 }}
                            >

                                <Button
                                    fullWidth
                                    variant="contained"
                                    sx={{
                                        height: "56px"
                                    }}
                                    disabled={
                                        saving ||
                                        !selectedPlan
                                    }
                                    onClick={
                                        handlePlanSubmit
                                    }
                                >

                                    {saving

                                        ? "Saving..."

                                        : subscription
                                            ? "Change Plan"
                                            : "Assign Plan"

                                    }

                                </Button>

                            </Grid>

                        </Grid>

                    </Paper>

                )}

            {/* =========================================
                SUBSCRIPTION DETAILS
            ========================================= */}

            {selectedOrganization &&
                !loadingSubscription && (

                    <SubscriptionDetails
                        subscription={
                            subscription
                        }
                        usage={
                            usage
                        }
                    />

                )}

            {/* =========================================
                SUBSCRIPTION ACTIONS
            ========================================= */}

            {selectedOrganization &&
                !loadingSubscription &&
                subscription && (

                    <Paper
                        sx={{
                            p: 3
                        }}
                    >

                        <Typography
                            variant="h6"
                            sx={{
                                fontWeight: 700,
                                mb: 2
                            }}
                        >
                            Subscription Actions
                        </Typography>


                        <Box
                            sx={{
                                display: "flex",
                                gap: 2,
                                flexWrap: "wrap",
                                alignItems: "center"
                            }}
                        >

                            <Button
                                variant="outlined"
                                disabled={
                                    saving
                                }
                                onClick={
                                    handleRenew
                                }
                            >
                                Renew
                            </Button>


                            <TextField
                                size="small"
                                label="Cancellation reason"
                                value={
                                    cancelReason
                                }
                                onChange={
                                    e =>
                                        setCancelReason(
                                            e.target.value
                                        )
                                }
                                sx={{
                                    minWidth: 260
                                }}
                            />


                            <Button
                                variant="outlined"
                                color="error"
                                disabled={
                                    saving
                                }
                                onClick={
                                    handleCancel
                                }
                            >
                                Cancel Subscription
                            </Button>

                        </Box>

                    </Paper>

                )}

        </Box>
    );

};


export default SubscriptionManagementPage;
