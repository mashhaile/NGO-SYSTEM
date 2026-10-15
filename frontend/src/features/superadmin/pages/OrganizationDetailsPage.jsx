import {
    useEffect,
    useState
} from "react";


import {
    useDispatch,
    useSelector
} from "react-redux";


import {
    useNavigate,
    useParams
} from "react-router-dom";


import {
    Box,
    Typography,
    CircularProgress,
    Alert,
    Button,
    Grid,
    Chip,
    Paper,
    Divider,
    LinearProgress,
    FormControl,
    InputLabel,
    Select,
    MenuItem
} from "@mui/material";


import {
    ArrowBack,
    Edit,
    Add,
    SwapHoriz,
    Autorenew,
    Cancel
} from "@mui/icons-material";


import {
    getOrganizationByIdThunk
} from "../store/organizationThunks";

import {
    setOrganizationContext
} from "../store/organizationContextSlice";


import {
    selectOrganization,
    selectOrganizationSubscription,
    selectOrganizationPlan,
    selectOrganizationUsage,
    selectOrganizationLimits,
    selectOrganizationUsagePercentage,
    selectOrganizationLoading,
    selectOrganizationError
} from "../store/organizationSlice";


import PageContainer
    from "../../../components/ui/PageContainer";


import PageHeader
    from "../../../components/ui/PageHeader";


import {
    getActivePlansApi,
    assignSubscriptionApi,
    changePlanApi,
    renewSubscriptionApi,
    cancelSubscriptionApi
} from "../api/planApi";


// =====================================================
// PAGE
// SUPER ADMIN ORGANIZATION DETAILS
// =====================================================

const OrganizationDetailsPage = () => {

    const {
        id
    } = useParams();


    const dispatch =
        useDispatch();


    const navigate =
        useNavigate();


    // =================================================
    // LOCAL STATE
    // =================================================

    const [
        plans,
        setPlans
    ] = useState([]);


    const [
        selectedPlanId,
        setSelectedPlanId
    ] = useState("");


    const [
        subscriptionActionLoading,
        setSubscriptionActionLoading
    ] = useState(false);


    const [
        subscriptionActionError,
        setSubscriptionActionError
    ] = useState("");


    const [
        subscriptionActionSuccess,
        setSubscriptionActionSuccess
    ] = useState("");


    // =================================================
    // REDUX
    // =================================================

    const organization =
        useSelector(
            selectOrganization
        );


    const subscription =
        useSelector(
            selectOrganizationSubscription
        );


    const plan =
        useSelector(
            selectOrganizationPlan
        );


    const usage =
        useSelector(
            selectOrganizationUsage
        );


    const limits =
        useSelector(
            selectOrganizationLimits
        );


    const usagePercentage =
        useSelector(
            selectOrganizationUsagePercentage
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
    // LOAD ORGANIZATION
    // =================================================

    useEffect(() => {

        if (!id) {
            return;
        }


        dispatch(
            getOrganizationByIdThunk(
                id
            )
        );

    }, [
        dispatch,
        id
    ]);


    // =================================================
    // LOAD AVAILABLE PLANS
    // =================================================

    useEffect(() => {

        let mounted = true;


        const loadPlans = async () => {

            try {

                const response =
                    await getActivePlansApi();


                if (
                    !mounted
                ) {
                    return;
                }


                if (
                    response?.success
                ) {

                    const data =
                        response?.data;


                    const availablePlans =
                        Array.isArray(data)
                            ? data
                            : Array.isArray(data?.plans)
                                ? data.plans
                                : [];


                    setPlans(
                        availablePlans
                    );

                }

                else {

                    setPlans([]);

                }

            }

            catch (error) {

                if (
                    mounted
                ) {

                    console.error(
                        "Failed to load subscription plans:",
                        error
                    );


                    setPlans([]);

                }

            }

        };


        loadPlans();


        return () => {

            mounted = false;

        };

    }, []);


    // =================================================
    // HELPERS
    // =================================================

    const organizationName =
        organization?.organization?.name ||
        organization?.name ||
        organization?.organizationName ||
        "Unnamed Organization";


    const organizationCode =
        organization?.organization?.organizationCode ||
        organization?.organization?.code ||
        organization?.organizationCode ||
        organization?.code ||
        "—";


    const organizationId =
        organization?.organization?._id ||
        organization?.organization?.id ||
        organization?._id ||
        organization?.id ||
        id ||
        "—";


    const organizationData =
        organization?.organization ||
        organization;

     // =====================================================
// SET GLOBAL ORGANIZATION CONTEXT
// =====================================================

useEffect(() => {

    if (!organizationData) {
        return;
    }

    dispatch(
        setOrganizationContext(
            organizationData
        )
    );

}, [
    dispatch,
    organizationData
]);
    const email =
        organizationData?.email ||
        organizationData?.contactEmail ||
        "—";


    const phone =
        organizationData?.phone ||
        organizationData?.contactPhone ||
        "—";


    const website =
        organizationData?.website ||
        "—";


    const country =
        organizationData?.country ||
        "—";


    const address =
        organizationData?.address ||
        organizationData?.location ||
        "—";


    const status =
        organizationData?.status ||
        (
            organizationData?.isActive
                ? "active"
                : "inactive"
        );


    const isDeleted =
        Boolean(
            organizationData?.isDeleted
        );


    const hasSubscription =
        Boolean(
            subscription
        );


    const subscriptionStatus =
        String(
            subscription?.status ||
            ""
        ).toLowerCase();
const isTrialing =
    subscriptionStatus === "trialing";

    const canManageSubscription =
        !isDeleted &&
        organizationId &&
        organizationId !== "—";


    // =================================================
    // STATUS HELPERS
    // =================================================

    const formatStatus = (
        value
    ) => {

        const text =
            String(
                value ||
                "inactive"
            );


        return (
            text.charAt(0).toUpperCase() +
            text.slice(1)
        );

    };


    const getStatusColor = (
        value
    ) => {

        switch (
            String(value)
                .toLowerCase()
        ) {

            case "active":
                return "success";

             case "trial":
            case "trialing":
            return "info";

            case "suspended":
                return "warning";

            case "inactive":
                return "default";

            case "cancelled":
                return "error";

            case "expired":
                return "error";

            default:
                return "default";

        }

    };


    // =================================================
    // DATE
    // =================================================

    const formatDate = (
        value
    ) => {

        if (!value) {

            return "—";

        }


        const date =
            new Date(value);


        if (
            Number.isNaN(
                date.getTime()
            )
        ) {

            return "—";

        }


        return date.toLocaleDateString(
            undefined,
            {
                year: "numeric",
                month: "short",
                day: "numeric"
            }
        );

    };


    // =================================================
    // SUBSCRIPTION END DATE
    // =================================================

  const formatSubscriptionEndDate = () => {

    if (isTrialing) {

        return formatDate(
            subscription?.trialEndDate
        );

    }


    if (!subscription?.endDate) {

        return "Lifetime";

    }


    return formatDate(
        subscription.endDate
    );

};


    // =================================================
    // NUMBER
    // =================================================

    const formatNumber = (
        value
    ) => {

        if (
            value === null ||
            value === undefined ||
            Number.isNaN(
                Number(value)
            )
        ) {

            return "0";

        }


        return Number(
            value
        ).toLocaleString();

    };


    // =================================================
    // LIMIT
    // =================================================

    const formatLimit = (
        value
    ) => {

        if (
            value === -1
        ) {

            return "Unlimited";

        }


        if (
            value === null ||
            value === undefined
        ) {

            return "—";

        }


        return formatNumber(
            value
        );

    };


    // =================================================
    // RESOURCE NAME
    // =================================================

    const formatResourceName = (
        resource
    ) => {

        return String(
            resource
        )
            .replace(
                /([a-z])([A-Z])/g,
                "$1 $2"
            )
            .replace(
                /_/g,
                " "
            )
            .replace(
                /\b\w/g,
                letter =>
                    letter.toUpperCase()
            );

    };


    // =================================================
    // USAGE RESOURCES
    // =================================================

    const resourceKeys = [

        "users",

        "beneficiaries",

        "enterprises",

        "donors",

        "donations",

        "programs",

        "projects",

        "activities",

        "activityRuns",

        "enrollments",

        "serviceDeliveries",

        "attendanceRecords",

        "customFields"

    ];


    // =================================================
    // REFRESH ORGANIZATION
    // =================================================

    const refreshOrganization =
        async () => {

            if (!id) {
                return;
            }


            await dispatch(
                getOrganizationByIdThunk(
                    id
                )
            );

        };


    // =================================================
    // CLEAR SUBSCRIPTION MESSAGES
    // =================================================

    const clearSubscriptionMessages =
        () => {

            setSubscriptionActionError("");

            setSubscriptionActionSuccess("");

        };


    // =================================================
    // ASSIGN SUBSCRIPTION
    // =================================================

    const handleAssignSubscription =
        async () => {

            if (!canManageSubscription) {

                return;

            }


            if (!selectedPlanId) {

                setSubscriptionActionError(
                    "Please select a subscription plan."
                );

                return;

            }


            try {

                setSubscriptionActionLoading(
                    true
                );

                setSubscriptionActionError("");

                setSubscriptionActionSuccess("");


                const response =
                    await assignSubscriptionApi({

                        organizationId,

                        planId:
                            selectedPlanId

                    });


                if (
                    !response?.success
                ) {

                    throw new Error(
                        response?.message ||
                        "Failed to assign subscription."
                    );

                }


                setSubscriptionActionSuccess(
                    response?.message ||
                    "Subscription assigned successfully."
                );


                setSelectedPlanId("");


                await refreshOrganization();

            }

            catch (error) {

                setSubscriptionActionError(
                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to assign subscription."
                );

            }

            finally {

                setSubscriptionActionLoading(
                    false
                );

            }

        };


    // =================================================
    // CHANGE PLAN
    // =================================================

    const handleChangePlan =
        async () => {

            if (!canManageSubscription) {

                return;

            }


            if (!selectedPlanId) {

                setSubscriptionActionError(
                    "Please select a subscription plan."
                );

                return;

            }


            const currentPlanId =
                subscription?.plan?._id ||
                subscription?.plan?.id ||
                plan?._id ||
                plan?.id ||
                subscription?.planSnapshot?.planId;


            if (
                currentPlanId &&
                String(currentPlanId) ===
                String(selectedPlanId)
            ) {

                setSubscriptionActionError(
                    "The organization is already subscribed to this plan."
                );

                return;

            }


            try {

                setSubscriptionActionLoading(
                    true
                );

                setSubscriptionActionError("");

                setSubscriptionActionSuccess("");


                const response =
                    await changePlanApi(
                        organizationId,
                        {
                            planId:
                                selectedPlanId
                        }
                    );


                if (
                    !response?.success
                ) {

                    throw new Error(
                        response?.message ||
                        "Failed to change subscription plan."
                    );

                }


                setSubscriptionActionSuccess(
                    response?.message ||
                    "Subscription plan changed successfully."
                );


                setSelectedPlanId("");


                await refreshOrganization();

            }

            catch (error) {

                setSubscriptionActionError(
                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to change subscription plan."
                );

            }

            finally {

                setSubscriptionActionLoading(
                    false
                );

            }

        };


    // =================================================
    // RENEW SUBSCRIPTION
    // =================================================

    const handleRenewSubscription =
        async () => {

            if (!canManageSubscription) {

                return;

            }


            if (
                subscription?.planSnapshot?.billingCycle ===
                "lifetime"
            ) {

                setSubscriptionActionError(
                    "Lifetime subscriptions do not need renewal."
                );

                return;

            }


            if (
                !window.confirm(
                    "Are you sure you want to renew this subscription?"
                )
            ) {

                return;

            }


            try {

                setSubscriptionActionLoading(
                    true
                );

                setSubscriptionActionError("");

                setSubscriptionActionSuccess("");


                const response =
                    await renewSubscriptionApi(
                        organizationId
                    );


                if (
                    !response?.success
                ) {

                    throw new Error(
                        response?.message ||
                        "Failed to renew subscription."
                    );

                }


                setSubscriptionActionSuccess(
                    response?.message ||
                    "Subscription renewed successfully."
                );


                await refreshOrganization();

            }

            catch (error) {

                setSubscriptionActionError(
                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to renew subscription."
                );

            }

            finally {

                setSubscriptionActionLoading(
                    false
                );

            }

        };


    // =================================================
    // CANCEL SUBSCRIPTION
    // =================================================

    const handleCancelSubscription =
        async () => {

            if (!canManageSubscription) {

                return;

            }


            if (
                !window.confirm(
                    "Are you sure you want to cancel this subscription?"
                )
            ) {

                return;

            }


            try {

                setSubscriptionActionLoading(
                    true
                );

                setSubscriptionActionError("");

                setSubscriptionActionSuccess("");


                const response =
                    await cancelSubscriptionApi(
                        organizationId,
                        {
                            reason:
                                "Cancelled by Super Admin."
                        }
                    );


                if (
                    !response?.success
                ) {

                    throw new Error(
                        response?.message ||
                        "Failed to cancel subscription."
                    );

                }


                setSubscriptionActionSuccess(
                    response?.message ||
                    "Subscription cancelled successfully."
                );


                setSelectedPlanId("");


                await refreshOrganization();

            }

            catch (error) {

                setSubscriptionActionError(
                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to cancel subscription."
                );

            }

            finally {

                setSubscriptionActionLoading(
                    false
                );

            }

        };


    // =================================================
    // LOADING
    // =================================================

    if (
        loading &&
        !organization
    ) {

        return (

            <PageContainer>

                <Box
                    sx={{
                        minHeight: 320,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center"
                    }}
                >

                    <CircularProgress />

                </Box>

            </PageContainer>

        );

    }


    // =================================================
    // ERROR
    // =================================================

    if (error) {

        return (

            <PageContainer>

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
                                "Unable to load organization."
                            )
                    }

                </Alert>


                <Button
                    variant="outlined"
                    startIcon={
                        <ArrowBack />
                    }
                    onClick={() =>
                        navigate(
                            "/superadmin/organizations"
                        )
                    }
                >

                    Back to Organizations

                </Button>

            </PageContainer>

        );

    }


    // =================================================
    // NOT FOUND
    // =================================================

    if (!organization) {

        return (

            <PageContainer>

                <Alert
                    severity="warning"
                    sx={{
                        mb: 2
                    }}
                >

                    Organization not found.

                </Alert>


                <Button
                    variant="outlined"
                    startIcon={
                        <ArrowBack />
                    }
                    onClick={() =>
                        navigate(
                            "/superadmin/organizations"
                        )
                    }
                >

                    Back to Organizations

                </Button>

            </PageContainer>

        );

    }


    // =================================================
    // SECTION
    // =================================================

    const Section = ({
        title,
        subtitle,
        children
    }) => (

        <Paper
            elevation={0}
            sx={{
                p: {
                    xs: 2,
                    sm: 3
                },
                mb: 3,
                border: "1px solid",
                borderColor: "divider",
                borderRadius: 2
            }}
        >

            <Box
                sx={{
                    mb: 2.5
                }}
            >

                <Typography
                    variant="h6"
                    sx={{
                        fontWeight: 700
                    }}
                >

                    {title}

                </Typography>


                {
                    subtitle && (

                        <Typography
                            variant="body2"
                            color="text.secondary"
                            sx={{
                                mt: 0.5
                            }}
                        >

                            {subtitle}

                        </Typography>

                    )
                }

            </Box>


            <Divider
                sx={{
                    mb: 3
                }}
            />


            {children}

        </Paper>

    );


    // =================================================
    // FIELD
    // =================================================

    const Field = ({
        label,
        value,
        children
    }) => (

        <Box>

            <Typography
                variant="caption"
                color="text.secondary"
                sx={{
                    display: "block",
                    mb: 0.5,
                    fontWeight: 600
                }}
            >

                {label}

            </Typography>


            {
                children || (

                    <Typography
                        variant="body1"
                        sx={{
                            fontWeight: 500,
                            wordBreak: "break-word"
                        }}
                    >

                        {
                            value || "—"
                        }

                    </Typography>

                )
            }

        </Box>

    );


    // =================================================
    // PAGE
    // =================================================

    return (

        <PageContainer>

            {/* =================================================
                HEADER
            ================================================= */}

            <PageHeader
                title="Organization Details"
                subtitle={
                    `View platform information for ${organizationName}.`
                }

                action={() =>
                    navigate(
                        `/superadmin/organizations/${organizationId}/edit`
                    )
                }

                actionLabel="Edit"

                actionIcon={
                    <Edit />
                }

                secondaryAction={() =>
                    navigate(
                        "/superadmin/organizations"
                    )
                }

                secondaryActionLabel="Back"

                secondaryActionIcon={
                    <ArrowBack />
                }
            />


            {/* =================================================
                ORGANIZATION OVERVIEW
            ================================================= */}

            <Section
                title="Organization Overview"
                subtitle="Primary organization identity and platform status."
            >

                <Grid
                    container
                    spacing={3}
                >

                    <Grid
                        item
                        xs={12}
                        md={6}
                    >

                        <Field
                            label="Organization Name"
                            value={
                                organizationName
                            }
                        />

                    </Grid>


                    <Grid
                        item
                        xs={12}
                        md={6}
                    >

                        <Field
                            label="Organization Code"
                            value={
                                organizationCode
                            }
                        />

                    </Grid>


                    <Grid
                        item
                        xs={12}
                        md={6}
                    >

                        <Field
                            label="Status"
                        >

                            <Chip
                                size="small"
                                label={
                                    formatStatus(
                                        status
                                    )
                                }
                                color={
                                    getStatusColor(
                                        status
                                    )
                                }
                            />

                        </Field>

                    </Grid>


                    <Grid
                        item
                        xs={12}
                        md={6}
                    >

                        <Field
                            label="Organization ID"
                            value={
                                organizationId
                            }
                        />

                    </Grid>

                </Grid>

            </Section>


            {/* =================================================
                CONTACT
            ================================================= */}

            <Section
                title="Contact Information"
                subtitle="Official organization contact details."
            >

                <Grid
                    container
                    spacing={3}
                >

                    <Grid
                        item
                        xs={12}
                        md={6}
                    >

                        <Field
                            label="Email"
                            value={
                                email
                            }
                        />

                    </Grid>


                    <Grid
                        item
                        xs={12}
                        md={6}
                    >

                        <Field
                            label="Phone"
                            value={
                                phone
                            }
                        />

                    </Grid>


                    <Grid
                        item
                        xs={12}
                        md={6}
                    >

                        <Field
                            label="Website"
                            value={
                                website
                            }
                        />

                    </Grid>


                    <Grid
                        item
                        xs={12}
                        md={6}
                    >

                        <Field
                            label="Country"
                            value={
                                country
                            }
                        />

                    </Grid>

                </Grid>

            </Section>


            {/* =================================================
                ADDRESS
            ================================================= */}

            <Section
                title="Address"
                subtitle="Registered organization location."
            >

                <Typography
                    variant="body1"
                    sx={{
                        fontWeight: 500,
                        lineHeight: 1.7
                    }}
                >

                    {
                        address
                    }

                </Typography>

            </Section>


            {/* =================================================
                SUBSCRIPTION
            ================================================= */}

            <Section
                title="Current Subscription"
                subtitle="View and manage the subscription assigned to this organization."
            >

                {
                    subscriptionActionError && (

                        <Alert
                            severity="error"
                            sx={{
                                mb: 2
                            }}
                            onClose={() =>
                                setSubscriptionActionError("")
                            }
                        >

                            {
                                subscriptionActionError
                            }

                        </Alert>

                    )
                }


                {
                    subscriptionActionSuccess && (

                        <Alert
                            severity="success"
                            sx={{
                                mb: 2
                            }}
                            onClose={() =>
                                setSubscriptionActionSuccess("")
                            }
                        >

                            {
                                subscriptionActionSuccess
                            }

                        </Alert>

                    )
                }


                {
                    isDeleted && (

                        <Alert
                            severity="warning"
                            sx={{
                                mb: 2
                            }}
                        >

                            This organization is deleted. Subscription management
                            is disabled until the organization is restored.

                        </Alert>

                    )
                }


                {
                    hasSubscription ? (

                        <>

                            <Grid
                                container
                                spacing={3}
                            >

                                <Grid
                                    item
                                    xs={12}
                                    md={4}
                                >

                                    <Field
                                        label="Plan"
                                        value={
                                            subscription?.planSnapshot?.name ||
                                            plan?.name ||
                                            "—"
                                        }
                                    />

                                </Grid>


                                <Grid
                                    item
                                    xs={12}
                                    md={4}
                                >

                                    <Field
                                        label="Plan Code"
                                        value={
                                            subscription?.planSnapshot?.code ||
                                            plan?.code ||
                                            "—"
                                        }
                                    />

                                </Grid>


                                <Grid
                                    item
                                    xs={12}
                                    md={4}
                                >

                                    <Field
                                        label="Subscription Status"
                                    >

                                        <Chip
                                            size="small"
                                            label={
                                                formatStatus(
                                                    subscription?.status
                                                )
                                            }
                                            color={
                                                getStatusColor(
                                                    subscription?.status
                                                )
                                            }
                                        />

                                    </Field>

                                </Grid>


                                <Grid
                                    item
                                    xs={12}
                                    md={4}
                                >

                                    <Field
                                        label="Start Date"
                                        value={
                                            formatDate(
                                                subscription?.startDate
                                            )
                                        }
                                    />

                                </Grid>


                                <Grid
                                    item
                                    xs={12}
                                    md={4}
                                >

                                  <Field
    label={
        isTrialing
            ? "Trial End Date"
            : "End Date"
    }
    value={
        formatSubscriptionEndDate()
    }
/>
                                </Grid>


                                <Grid
                                    item
                                    xs={12}
                                    md={4}
                                >

                                    <Field
                                        label="Auto Renew"
                                        value={
                                            subscription?.autoRenew
                                                ? "Yes"
                                                : "No"
                                        }
                                    />

                                </Grid>

                            </Grid>


                            <Divider
                                sx={{
                                    my: 3
                                }}
                            />


                            <Typography
                                variant="subtitle1"
                                sx={{
                                    fontWeight: 700,
                                    mb: 1
                                }}
                            >

                                Subscription Management

                            </Typography>


                            <Typography
                                variant="body2"
                                color="text.secondary"
                                sx={{
                                    mb: 2
                                }}
                            >

                                Change the organization's plan or manage its
                                current subscription lifecycle.

                            </Typography>


                            <Grid
                                container
                                spacing={2}
                                alignItems="center"
                            >

                                <Grid
                                    item
                                    xs={12}
                                    md={6}
                                >

                                    <FormControl
                                        fullWidth
                                        size="small"
                                        disabled={
                                            subscriptionActionLoading ||
                                            !canManageSubscription
                                        }
                                    >

                                        <InputLabel>
                                            Select New Plan
                                        </InputLabel>


                                        <Select
                                            value={
                                                selectedPlanId
                                            }
                                            label="Select New Plan"
                                            onChange={event => {

                                                setSelectedPlanId(
                                                    event.target.value
                                                );

                                                clearSubscriptionMessages();

                                            }}
                                        >

                                            <MenuItem value="">

                                                Select a plan

                                            </MenuItem>


                                            {
                                                plans.map(
                                                    availablePlan => {

                                                        const planId =
                                                            availablePlan?._id ||
                                                            availablePlan?.id;


                                                        if (!planId) {
                                                            return null;
                                                        }


                                                        return (

                                                            <MenuItem
                                                                key={
                                                                    planId
                                                                }
                                                                value={
                                                                    planId
                                                                }
                                                            >

                                                                {
                                                                    availablePlan?.name ||
                                                                    availablePlan?.code ||
                                                                    "Unnamed Plan"
                                                                }

                                                                {
                                                                    availablePlan?.billingCycle
                                                                        ? ` (${formatStatus(availablePlan.billingCycle)})`
                                                                        : ""
                                                                }

                                                            </MenuItem>

                                                        );

                                                    }
                                                )
                                            }

                                        </Select>

                                    </FormControl>

                                </Grid>


                                <Grid
                                    item
                                    xs={12}
                                    md="auto"
                                >

                                    <Button
                                        variant="outlined"
                                        startIcon={
                                            <SwapHoriz />
                                        }
                                        onClick={
                                            handleChangePlan
                                        }
                                        disabled={
                                            subscriptionActionLoading ||
                                            !selectedPlanId ||
                                            !canManageSubscription
                                        }
                                    >

                                        Change Plan

                                    </Button>

                                </Grid>


                                <Grid
                                    item
                                    xs={12}
                                    md="auto"
                                >

                                    <Button
                                        variant="outlined"
                                        color="success"
                                        startIcon={
                                            <Autorenew />
                                        }
                                        onClick={
                                            handleRenewSubscription
                                        }
                                        disabled={
                                            subscriptionActionLoading ||
                                            !canManageSubscription ||
                                            subscriptionStatus === "cancelled" ||
                                            subscriptionStatus === "active" &&
                                            subscription?.planSnapshot?.billingCycle === "lifetime"
                                        }
                                    >

                                        Renew

                                    </Button>

                                </Grid>


                                <Grid
                                    item
                                    xs={12}
                                    md="auto"
                                >

                                    <Button
                                        variant="outlined"
                                        color="error"
                                        startIcon={
                                            <Cancel />
                                        }
                                        onClick={
                                            handleCancelSubscription
                                        }
                                        disabled={
                                            subscriptionActionLoading ||
                                            !canManageSubscription ||
                                            subscriptionStatus !== "active"
                                        }
                                    >

                                        Cancel

                                    </Button>

                                </Grid>

                            </Grid>


                            {
                                subscriptionActionLoading && (

                                    <Box
                                        sx={{
                                            mt: 2
                                        }}
                                    >

                                        <LinearProgress />

                                    </Box>

                                )
                            }

                        </>

                    ) : (

                        <>

                            <Alert
                                severity="info"
                                sx={{
                                    mb: 3
                                }}
                            >

                                No subscription found. Assign a plan to this
                                organization to enable subscription-based
                                platform access.

                            </Alert>


                            <Grid
                                container
                                spacing={2}
                                alignItems="center"
                            >

                                <Grid
                                    item
                                    xs={12}
                                    md={7}
                                >

                                    <FormControl
                                        fullWidth
                                        size="small"
                                        disabled={
                                            subscriptionActionLoading ||
                                            !canManageSubscription
                                        }
                                    >

                                        <InputLabel>
                                            Subscription Plan
                                        </InputLabel>


                                        <Select
                                            value={
                                                selectedPlanId
                                            }
                                            label="Subscription Plan"
                                            onChange={event => {

                                                setSelectedPlanId(
                                                    event.target.value
                                                );

                                                clearSubscriptionMessages();

                                            }}
                                        >

                                            <MenuItem value="">

                                                Select a plan

                                            </MenuItem>


                                            {
                                                plans.map(
                                                    availablePlan => {

                                                        const planId =
                                                            availablePlan?._id ||
                                                            availablePlan?.id;


                                                        if (!planId) {
                                                            return null;
                                                        }


                                                        return (

                                                            <MenuItem
                                                                key={
                                                                    planId
                                                                }
                                                                value={
                                                                    planId
                                                                }
                                                            >

                                                                {
                                                                    availablePlan?.name ||
                                                                    availablePlan?.code ||
                                                                    "Unnamed Plan"
                                                                }

                                                                {
                                                                    availablePlan?.billingCycle
                                                                        ? ` (${formatStatus(availablePlan.billingCycle)})`
                                                                        : ""
                                                                }

                                                            </MenuItem>

                                                        );

                                                    }
                                                )
                                            }

                                        </Select>

                                    </FormControl>

                                </Grid>


                                <Grid
                                    item
                                    xs={12}
                                    md="auto"
                                >

                                    <Button
                                        variant="contained"
                                        startIcon={
                                            <Add />
                                        }
                                        onClick={
                                            handleAssignSubscription
                                        }
                                        disabled={
                                            subscriptionActionLoading ||
                                            !selectedPlanId ||
                                            !canManageSubscription
                                        }
                                    >

                                        Assign Plan

                                    </Button>

                                </Grid>

                            </Grid>


                            {
                                plans.length === 0 && (

                                    <Typography
                                        variant="body2"
                                        color="text.secondary"
                                        sx={{
                                            mt: 2
                                        }}
                                    >

                                        No available subscription plans were
                                        found.

                                    </Typography>

                                )
                            }


                            {
                                subscriptionActionLoading && (

                                    <Box
                                        sx={{
                                            mt: 2
                                        }}
                                    >

                                        <LinearProgress />

                                    </Box>

                                )
                            }

                        </>

                    )
                }

            </Section>


            {/* =================================================
                RESOURCE USAGE
            ================================================= */}

            <Section
                title="Resource Usage"
                subtitle="Current tenant usage compared with the organization's subscription limits."
            >

                {
                    Object.keys(
                        usage || {}
                    ).length > 0 ? (

                        <Grid
                            container
                            spacing={2}
                        >

                            {
                                resourceKeys.map(
                                    resource => {

                                        const used =
                                            Number(
                                                usage?.[resource] ||
                                                0
                                            );


                                        const limit =
                                            limits?.[resource];


                                        const percentageValue =
                                            usagePercentage?.[resource];


                                        let percentage =
                                            Number(
                                                percentageValue
                                            );


                                        if (
                                            !Number.isFinite(
                                                percentage
                                            )
                                        ) {

                                            if (
                                                limit === -1
                                            ) {

                                                percentage = 0;

                                            }

                                            else if (
                                                Number(
                                                    limit
                                                ) > 0
                                            ) {

                                                percentage =
                                                    (
                                                        used /
                                                        Number(limit)
                                                    ) *
                                                    100;

                                            }

                                            else {

                                                percentage = 0;

                                            }

                                        }


                                        percentage =
                                            Math.min(
                                                100,
                                                Math.max(
                                                    0,
                                                    percentage
                                                )
                                            );


                                        return (

                                            <Grid
                                                item
                                                xs={12}
                                                sm={6}
                                                md={4}
                                                key={
                                                    resource
                                                }
                                            >

                                                <Paper
                                                    variant="outlined"
                                                    sx={{
                                                        p: 2,
                                                        height: "100%"
                                                    }}
                                                >

                                                    <Typography
                                                        variant="subtitle2"
                                                        sx={{
                                                            fontWeight: 700
                                                        }}
                                                    >

                                                        {
                                                            formatResourceName(
                                                                resource
                                                            )
                                                        }

                                                    </Typography>


                                                    <Box
                                                        sx={{
                                                            display: "flex",
                                                            justifyContent: "space-between",
                                                            mt: 1,
                                                            mb: 0.75
                                                        }}
                                                    >

                                                        <Typography
                                                            variant="body2"
                                                            color="text.secondary"
                                                        >

                                                            Used:{" "}

                                                            {
                                                                formatNumber(
                                                                    used
                                                                )
                                                            }

                                                        </Typography>


                                                        <Typography
                                                            variant="body2"
                                                            color="text.secondary"
                                                        >

                                                            Limit:{" "}

                                                            {
                                                                formatLimit(
                                                                    limit
                                                                )
                                                            }

                                                        </Typography>

                                                    </Box>


                                                    {
                                                        limit === -1 ? (

                                                            <Chip
                                                                size="small"
                                                                label="Unlimited"
                                                                color="success"
                                                                variant="outlined"
                                                            />

                                                        ) : (

                                                            <LinearProgress
                                                                variant="determinate"
                                                                value={
                                                                    percentage
                                                                }
                                                                sx={{
                                                                    height: 7,
                                                                    borderRadius: 5
                                                                }}
                                                            />

                                                        )
                                                    }

                                                </Paper>

                                            </Grid>

                                        );

                                    }
                                )
                            }

                        </Grid>

                    ) : (

                        <Typography
                            variant="body2"
                            color="text.secondary"
                        >

                            Usage information is not available.

                        </Typography>

                    )
                }

            </Section>


            {/* =================================================
                PLAN LIMITS
            ================================================= */}

            {
                Object.keys(
                    limits || {}
                ).length > 0 && (

                    <Section
                        title="Plan Limits"
                        subtitle="Resource limits defined by the current subscription plan."
                    >

                        <Grid
                            container
                            spacing={2}
                        >

                            {
                                Object.entries(
                                    limits || {}
                                ).map(
                                    (
                                        [
                                            resource,
                                            limit
                                        ]
                                    ) => (

                                        <Grid
                                            item
                                            xs={12}
                                            sm={6}
                                            md={4}
                                            key={
                                                resource
                                            }
                                        >

                                            <Paper
                                                variant="outlined"
                                                sx={{
                                                    p: 2
                                                }}
                                            >

                                                <Typography
                                                    variant="body2"
                                                    color="text.secondary"
                                                >

                                                    {
                                                        formatResourceName(
                                                            resource
                                                        )
                                                    }

                                                </Typography>


                                                <Typography
                                                    variant="h6"
                                                    sx={{
                                                        fontWeight: 700,
                                                        mt: 0.5
                                                    }}
                                                >

                                                    {
                                                        formatLimit(
                                                            limit
                                                        )
                                                    }

                                                </Typography>

                                            </Paper>

                                        </Grid>

                                    )
                                )
                            }

                        </Grid>

                    </Section>

                )
            }


            {/* =================================================
                LIFECYCLE
            ================================================= */}

            <Section
                title="Organization Lifecycle"
                subtitle="Platform-level organization record information."
            >

                <Grid
                    container
                    spacing={3}
                >

                    <Grid
                        item
                        xs={12}
                        md={4}
                    >

                        <Field
                            label="Created"
                            value={
                                formatDate(
                                    organizationData?.createdAt
                                )
                            }
                        />

                    </Grid>


                    <Grid
                        item
                        xs={12}
                        md={4}
                    >

                        <Field
                            label="Last Updated"
                            value={
                                formatDate(
                                    organizationData?.updatedAt
                                )
                            }
                        />

                    </Grid>


                    <Grid
                        item
                        xs={12}
                        md={4}
                    >

                        <Field
                            label="Record Status"
                        >

                            <Chip
                                size="small"
                                label={
                                    organizationData?.isDeleted
                                        ? "Deleted"
                                        : "Active Record"
                                }
                                color={
                                    organizationData?.isDeleted
                                        ? "error"
                                        : "success"
                                }
                            />

                        </Field>

                    </Grid>


                    {
                        organizationData?.isDeleted && (

                            <Grid
                                item
                                xs={12}
                                md={4}
                            >

                                <Field
                                    label="Deleted At"
                                    value={
                                        formatDate(
                                            organizationData?.deletedAt
                                        )
                                    }
                                />

                            </Grid>

                        )
                    }

                </Grid>

            </Section>


            {/* =================================================
                PLATFORM NOTE
            ================================================= */}

            <Alert
                severity="info"
                sx={{
                    mb: 3
                }}
            >

                Subscription, resource usage, plan limits,
                audit activity and other tenant-level platform
                controls are managed by the Super Admin.

            </Alert>

        </PageContainer>

    );

};


export default OrganizationDetailsPage;
