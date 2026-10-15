import {
    useEffect,
    useMemo,
    useState
} from "react";

import {
    Link,
    useNavigate,
    useParams
} from "react-router-dom";

import {
    Alert,
    Box,
    Button,
    Card,
    CardContent,
    Chip,
    CircularProgress,
    Divider,
    IconButton,
    Stack,
    Switch,
    TextField,
    Typography,
    FormControl,
    InputLabel,
    MenuItem,
    Select
} from "@mui/material";

import {
    Add,
    ArrowBack,
    Delete,
    Edit,
    Save,
    Cancel
} from "@mui/icons-material";


// ==========================================================
// SERVICES
// ==========================================================

import {
    getLookupsByModuleAndCategoryService,
    normalizeModule,
    normalizeCategory,
    createLookupService,
    updateLookupService,
    deleteLookupService
} from "../services/lookupService";


// ==========================================================
// UI
// ==========================================================

import {
    PageContainer,
    PageHeader
} from "../../../components/ui";


// ==========================================================
// MODULE LABELS
// ==========================================================

const MODULE_LABELS = {

    beneficiaries: "Beneficiaries",
    enterprises: "Enterprises",
    "enterprise-members": "Enterprise Members",
    programs: "Programs",
    projects: "Projects",
    activities: "Activities",
    "activity-runs": "Activity Runs",
    attendance: "Attendance",
    enrollments: "Enrollments",
    "service-delivery": "Service Delivery",
    users: "Users",
    donors: "Donors",
    donations: "Donations"

};


// ==========================================================
// ALLOCATION BEHAVIORS
// ==========================================================

const ALLOCATION_BEHAVIORS = [

    {
        value: "CONSUMPTION",
        label: "Consumption",
        description:
            "Delivered quantity is a shared pool that beneficiary allocations consume."
    },

    {
        value: "PARTICIPATION",
        label: "Participation",
        description:
            "Beneficiaries can each participate in the delivered quantity independently."
    }

];


// ==========================================================
// RESPONSE ARRAY HELPER
// ==========================================================

const extractArray = response => {

    if (Array.isArray(response)) {
        return response;
    }

    if (Array.isArray(response?.data)) {
        return response.data;
    }

    if (Array.isArray(response?.data?.data)) {
        return response.data.data;
    }

    return [];

};


// ==========================================================
// ID HELPER
// ==========================================================

const getLookupId = value => {

    if (!value) {
        return "";
    }

    if (
        typeof value === "object" &&
        value !== null
    ) {

        return String(
            value?._id ||
            value?.id ||
            ""
        ).trim();

    }

    return String(
        value
    ).trim();

};


// ==========================================================
// LABEL HELPER
// ==========================================================

const getLookupLabel = value => {

    if (!value) {
        return "";
    }

    if (
        typeof value === "object" &&
        value !== null
    ) {

        return String(
            value?.value ||
            value?.label ||
            value?.name ||
            ""
        ).trim();

    }

    return String(
        value
    ).trim();

};


// ==========================================================
// NORMALIZE ID ARRAY
// ==========================================================

const normalizeIdArray = values => {

    if (!Array.isArray(values)) {
        return [];
    }

    const result = [];
    const seen = new Set();

    values.forEach(value => {

        const id =
            getLookupId(
                value
            );

        if (
            !id ||
            seen.has(id)
        ) {
            return;
        }

        seen.add(id);

        result.push(
            id
        );

    });

    return result;

};


// ==========================================================
// NORMALIZE ALLOCATION BEHAVIOR
// ==========================================================

const normalizeAllocationBehavior =
    value => {

        const normalized =
            String(
                value || ""
            )
                .trim()
                .toUpperCase();


        if (
            normalized ===
            "PARTICIPATION"
        ) {

            return "PARTICIPATION";

        }


        return "CONSUMPTION";

    };


// ==========================================================
// EMPTY FORM
// ==========================================================

const createEmptyForm = () => ({

    value: "",
    code: "",
    active: true,
    parentLookup: "",
    allowedUnits: [],
    allocationBehavior: "CONSUMPTION"

});


// ==========================================================
// CATEGORY PAGE
// ==========================================================

const LookupCategoryPage = () => {

    const navigate =
        useNavigate();


    const {
        module: routeModule,
        category: routeCategory
    } = useParams();


    // ======================================================
    // NORMALIZED MODULE
    // ======================================================

    const module =
        useMemo(() => {

            const raw =
                String(
                    routeModule || ""
                ).trim();


            if (!raw) {
                return "";
            }


            return normalizeModule(
                decodeURIComponent(raw)
            );

        }, [
            routeModule
        ]);


    // ======================================================
    // NORMALIZED CATEGORY
    // ======================================================

    const category =
        useMemo(() => {

            const raw =
                String(
                    routeCategory || ""
                ).trim();


            if (!raw) {
                return "";
            }


            return normalizeCategory(
                decodeURIComponent(raw)
            );

        }, [
            routeCategory
        ]);


    // ======================================================
    // MODULE LABEL
    // ======================================================

    const moduleLabel =
        useMemo(() => {

            if (!module) {
                return "Unknown Module";
            }


            return (
                MODULE_LABELS[module] ||
                module
            );

        }, [
            module
        ]);


    // ======================================================
    // SERVICE TYPE
    // ======================================================

    const isServiceType =
        category === "ServiceType";


    // ======================================================
    // STATE
    // ======================================================

    const [
        lookups,
        setLookups
    ] = useState([]);


    const [
        parentCategories,
        setParentCategories
    ] = useState([]);


    const [
        allowedUnitOptions,
        setAllowedUnitOptions
    ] = useState([]);


    const [
        loading,
        setLoading
    ] = useState(false);


    const [
        loadingParentCategories,
        setLoadingParentCategories
    ] = useState(false);


    const [
        loadingAllowedUnits,
        setLoadingAllowedUnits
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
        editingId,
        setEditingId
    ] = useState(null);


    const [
        editForm,
        setEditForm
    ] = useState(
        createEmptyForm()
    );


    const [
        newValue,
        setNewValue
    ] = useState(
        createEmptyForm()
    );


    const [
        showAddForm,
        setShowAddForm
    ] = useState(false);


    // ======================================================
    // LOAD LOOKUPS
    // ======================================================

    useEffect(() => {

        let cancelled = false;


        const loadLookups =
            async () => {

                if (
                    !module ||
                    !category
                ) {

                    if (!cancelled) {

                        setLookups([]);

                        setLoading(false);

                    }

                    return;

                }


                try {

                    setLoading(true);

                    setError("");


                    const response =
                        await getLookupsByModuleAndCategoryService(
                            module,
                            category
                        );


                    const rows =
                        extractArray(
                            response
                        );


                    if (!cancelled) {

                        setLookups(
                            rows
                        );

                    }

                }
                catch (loadError) {

                    console.error(
                        "Failed loading lookup values:",
                        loadError
                    );


                    if (!cancelled) {

                        setLookups([]);

                        setError(
                            loadError
                                ?.response
                                ?.data
                                ?.message ||
                            loadError?.message ||
                            "Failed to load lookup values."
                        );

                    }

                }
                finally {

                    if (!cancelled) {

                        setLoading(false);

                    }

                }

            };


        loadLookups();


        return () => {

            cancelled = true;

        };

    }, [
        module,
        category
    ]);


    // ======================================================
    // LOAD SERVICE CATEGORIES
    // ======================================================

    useEffect(() => {

        let cancelled = false;


        const loadParentCategories =
            async () => {

                if (!isServiceType) {

                    setParentCategories([]);

                    return;

                }


                try {

                    setLoadingParentCategories(true);


                    const response =
                        await getLookupsByModuleAndCategoryService(
                            "ServiceDelivery",
                            "ServiceCategory"
                        );


                    const rows =
                        extractArray(
                            response
                        );


                    if (!cancelled) {

                        setParentCategories(
                            rows
                        );

                    }

                }
                catch (parentError) {

                    console.error(
                        "Failed loading service categories:",
                        parentError
                    );


                    if (!cancelled) {

                        setParentCategories([]);

                        setError(
                            parentError
                                ?.response
                                ?.data
                                ?.message ||
                            parentError?.message ||
                            "Failed to load service categories."
                        );

                    }

                }
                finally {

                    if (!cancelled) {

                        setLoadingParentCategories(
                            false
                        );

                    }

                }

            };


        loadParentCategories();


        return () => {

            cancelled = true;

        };

    }, [
        isServiceType
    ]);


    // ======================================================
    // LOAD ALLOWED UNITS
    // ======================================================

    useEffect(() => {

        let cancelled = false;


        const loadAllowedUnits =
            async () => {

                if (!isServiceType) {

                    setAllowedUnitOptions([]);

                    return;

                }


                try {

                    setLoadingAllowedUnits(true);


                    const response =
                        await getLookupsByModuleAndCategoryService(
                            "ServiceDelivery",
                            "Unit"
                        );


                    const rows =
                        extractArray(
                            response
                        );


                    const activeUnits =
                        rows.filter(
                            item =>
                                item?.active !== false &&
                                Boolean(
                                    getLookupId(
                                        item
                                    )
                                )
                        );


                    if (!cancelled) {

                        setAllowedUnitOptions(
                            activeUnits
                        );

                    }

                }
                catch (unitError) {

                    console.error(
                        "Failed loading service delivery units:",
                        unitError
                    );


                    if (!cancelled) {

                        setAllowedUnitOptions([]);

                        setError(
                            unitError
                                ?.response
                                ?.data
                                ?.message ||
                            unitError?.message ||
                            "Failed to load service delivery units."
                        );

                    }

                }
                finally {

                    if (!cancelled) {

                        setLoadingAllowedUnits(
                            false
                        );

                    }

                }

            };


        loadAllowedUnits();


        return () => {

            cancelled = true;

        };

    }, [
        isServiceType
    ]);


    // ======================================================
    // START EDIT
    // ======================================================

    const handleEdit =
        lookup => {

            if (!lookup?._id) {
                return;
            }


            const existingAllowedUnits =
                normalizeIdArray(
                    lookup?.allowedUnits
                );


            setEditingId(
                lookup._id
            );


            setEditForm({

                value:
                    lookup?.value || "",

                code:
                    lookup?.code || "",

                active:
                    lookup?.active !== false,

                parentLookup:
                    String(
                        lookup?.parentLookup?._id ||
                        lookup?.parentLookup ||
                        ""
                    ).trim(),

                allowedUnits:
                    existingAllowedUnits,

                allocationBehavior:
                    normalizeAllocationBehavior(
                        lookup?.allocationBehavior
                    )

            });


            setError("");

        };


    // ======================================================
    // CANCEL EDIT
    // ======================================================

    const handleCancelEdit =
        () => {

            setEditingId(null);

            setEditForm(
                createEmptyForm()
            );

            setError("");

        };


    // ======================================================
    // EDIT FORM CHANGE
    // ======================================================

    const handleEditChange =
        (
            field,
            value
        ) => {

            setEditForm(
                previous => {

                    const next =
                        Object.assign(
                            {},
                            previous
                        );

                    next[field] =
                        value;

                    return next;

                }
            );


            setError("");

        };


    // ======================================================
    // SERVICE TYPE ALLOWED UNIT CHANGE
    // ======================================================

    const handleEditAllowedUnitsChange =
        event => {

            const values =
                Array.isArray(
                    event.target.value
                )
                    ? event.target.value
                    : [];


            const normalized =
                normalizeIdArray(
                    values
                );


            handleEditChange(
                "allowedUnits",
                normalized
            );

        };


    // ======================================================
    // NEW FORM CHANGE
    // ======================================================

    const handleNewValueChange =
        (
            field,
            value
        ) => {

            setNewValue(
                previous => {

                    const next =
                        Object.assign(
                            {},
                            previous
                        );

                    next[field] =
                        value;

                    return next;

                }
            );


            setError("");

        };


    // ======================================================
    // NEW ALLOWED UNIT CHANGE
    // ======================================================

    const handleNewAllowedUnitsChange =
        event => {

            const values =
                Array.isArray(
                    event.target.value
                )
                    ? event.target.value
                    : [];


            const normalized =
                normalizeIdArray(
                    values
                );


            handleNewValueChange(
                "allowedUnits",
                normalized
            );

        };


    // ======================================================
    // SAVE EDIT
    // ======================================================

    const handleSaveEdit =
        async lookup => {

            if (!lookup?._id) {

                setError(
                    "Lookup ID is missing."
                );

                return;

            }


            const cleanValue =
                String(
                    editForm.value || ""
                ).trim();


            const cleanCode =
                String(
                    editForm.code || ""
                ).trim();


            const cleanParentLookup =
                String(
                    editForm.parentLookup || ""
                ).trim();


            const cleanAllowedUnits =
                normalizeIdArray(
                    editForm.allowedUnits
                );


            const cleanAllocationBehavior =
                isServiceType
                    ? normalizeAllocationBehavior(
                        editForm.allocationBehavior
                    )
                    : null;


            if (!cleanValue) {

                setError(
                    "Value is required."
                );

                return;

            }


            if (
                !module ||
                !category
            ) {

                setError(
                    "Lookup module or category is missing."
                );

                return;

            }


            if (
                isServiceType &&
                !cleanParentLookup
            ) {

                setError(
                    "Service Type must belong to a Service Category."
                );

                return;

            }


            if (
                isServiceType &&
                cleanAllowedUnits.length === 0
            ) {

                setError(
                    "Service Type must have at least one allowed unit."
                );

                return;

            }


            if (
                isServiceType &&
                !ALLOCATION_BEHAVIORS.some(
                    item =>
                        item.value ===
                        cleanAllocationBehavior
                )
            ) {

                setError(
                    "Service Type allocation behavior must be Consumption or Participation."
                );

                return;

            }


            const duplicate =
                lookups.some(item => {

                    if (
                        item?._id ===
                        lookup?._id
                    ) {

                        return false;

                    }


                    return (
                        String(
                            item?.value || ""
                        )
                            .trim()
                            .toLowerCase() ===
                        cleanValue.toLowerCase()
                    );

                });


            if (duplicate) {

                setError(
                    `"${cleanValue}" already exists.`
                );

                return;

            }


            try {

                setSaving(true);

                setError("");


                const updateData = {

                    module,

                    category,

                    value:
                        cleanValue,

                    code:
                        cleanCode,

                    active:
                        editForm.active

                };


                if (isServiceType) {

                    updateData.parentLookup =
                        cleanParentLookup;

                    updateData.allowedUnits =
                        cleanAllowedUnits;

                    updateData.allocationBehavior =
                        cleanAllocationBehavior;

                }
                else {

                    updateData.parentLookup =
                        null;

                    updateData.allowedUnits =
                        [];

                }


                const response =
                    await updateLookupService(

                        lookup._id,

                        updateData

                    );


                const updated =
                    response?.data?.data ||
                    response?.data ||
                    response;


                setLookups(
                    previous =>
                        previous.map(item => {

                            if (
                                item?._id !==
                                lookup?._id
                            ) {

                                return item;

                            }


                            const next =
                                Object.assign(
                                    {},
                                    item
                                );


                            if (
                                updated &&
                                typeof updated === "object"
                            ) {

                                Object.assign(
                                    next,
                                    updated
                                );

                            }


                            next.module =
                                module;

                            next.category =
                                category;

                            next.value =
                                cleanValue;

                            next.code =
                                cleanCode;

                            next.active =
                                editForm.active;

                            next.parentLookup =
                                isServiceType
                                    ? cleanParentLookup
                                    : null;

                            next.allowedUnits =
                                isServiceType
                                    ? cleanAllowedUnits
                                    : [];

                            if (isServiceType) {

                                next.allocationBehavior =
                                    cleanAllocationBehavior;

                            }


                            return next;

                        })
                );


                handleCancelEdit();

            }
            catch (saveError) {

                console.error(
                    "Failed updating lookup:",
                    saveError
                );


                setError(
                    saveError
                        ?.response
                        ?.data
                        ?.message ||
                    saveError?.message ||
                    "Failed to update lookup."
                );

            }
            finally {

                setSaving(false);

            }

        };


    // ======================================================
    // DEACTIVATE LOOKUP
    // ======================================================

    const handleDelete =
        async lookup => {

            if (!lookup?._id) {
                return;
            }


            const confirmed =
                window.confirm(
                    `Deactivate "${lookup.value}"?`
                );


            if (!confirmed) {
                return;
            }


            try {

                setSaving(true);

                setError("");


                await deleteLookupService(
                    lookup._id
                );


                setLookups(
                    previous =>
                        previous.map(item => {

                            if (
                                item?._id !==
                                lookup?._id
                            ) {

                                return item;

                            }


                            const next =
                                Object.assign(
                                    {},
                                    item
                                );

                            next.active =
                                false;

                            return next;

                        })
                );


                if (
                    editingId ===
                    lookup?._id
                ) {

                    handleCancelEdit();

                }

            }
            catch (deleteError) {

                console.error(
                    "Failed deactivating lookup:",
                    deleteError
                );


                setError(
                    deleteError
                        ?.response
                        ?.data
                        ?.message ||
                    deleteError?.message ||
                    "Failed to deactivate lookup."
                );

            }
            finally {

                setSaving(false);

            }

        };


    // ======================================================
    // CREATE VALUE
    // ======================================================

    const handleCreate =
        async () => {

            const cleanValue =
                String(
                    newValue.value || ""
                ).trim();


            const cleanCode =
                String(
                    newValue.code || ""
                ).trim();


            const cleanParentLookup =
                String(
                    newValue.parentLookup || ""
                ).trim();


            const cleanAllowedUnits =
                normalizeIdArray(
                    newValue.allowedUnits
                );


            const cleanAllocationBehavior =
                isServiceType
                    ? normalizeAllocationBehavior(
                        newValue.allocationBehavior
                    )
                    : null;


            if (!cleanValue) {

                setError(
                    "Value is required."
                );

                return;

            }


            if (
                !module ||
                !category
            ) {

                setError(
                    "Lookup module or category is missing."
                );

                return;

            }


            // ==================================================
            // SERVICE TYPE PARENT
            // ==================================================

            if (
                isServiceType &&
                !cleanParentLookup
            ) {

                setError(
                    "Service Type must belong to a Service Category."
                );

                return;

            }


            // ==================================================
            // SERVICE TYPE ALLOWED UNITS
            // ==================================================

            if (
                isServiceType &&
                cleanAllowedUnits.length === 0
            ) {

                setError(
                    "Service Type must have at least one allowed unit."
                );

                return;

            }


            // ==================================================
            // SERVICE TYPE ALLOCATION BEHAVIOR
            // ==================================================

            if (
                isServiceType &&
                !ALLOCATION_BEHAVIORS.some(
                    item =>
                        item.value ===
                        cleanAllocationBehavior
                )
            ) {

                setError(
                    "Service Type allocation behavior must be Consumption or Participation."
                );

                return;

            }


            const duplicate =
                lookups.some(
                    lookup =>
                        String(
                            lookup?.value || ""
                        )
                            .trim()
                            .toLowerCase() ===
                        cleanValue.toLowerCase()
                );


            if (duplicate) {

                setError(
                    `"${cleanValue}" already exists.`
                );

                return;

            }


            try {

                setSaving(true);

                setError("");


                const createData = {

                    module,

                    category,

                    value:
                        cleanValue,

                    code:
                        cleanCode,

                    active:
                        newValue.active

                };


                if (isServiceType) {

                    createData.parentLookup =
                        cleanParentLookup;

                    createData.allowedUnits =
                        cleanAllowedUnits;

                    createData.allocationBehavior =
                        cleanAllocationBehavior;

                }


                const response =
                    await createLookupService(
                        createData
                    );


                const created =
                    response?.data?.data ||
                    response?.data ||
                    response;


                if (
                    created &&
                    typeof created === "object" &&
                    (
                        created._id ||
                        created.value
                    )
                ) {

                    setLookups(
                        previous => {

                            return previous.concat(
                                [
                                    created
                                ]
                            );

                        }
                    );

                }
                else {

                    const refreshed =
                        await getLookupsByModuleAndCategoryService(
                            module,
                            category
                        );


                    setLookups(
                        extractArray(
                            refreshed
                        )
                    );

                }


                setNewValue(
                    createEmptyForm()
                );


                setShowAddForm(
                    false
                );

            }
            catch (createError) {

                console.error(
                    "Failed creating lookup:",
                    createError
                );


                setError(
                    createError
                        ?.response
                        ?.data
                        ?.message ||
                    createError?.message ||
                    "Failed to create lookup."
                );

            }
            finally {

                setSaving(false);

            }

        };


    // ======================================================
    // BACK
    // ======================================================

    const handleBack =
        () => {

            navigate(
                "/lookups"
            );

        };


    // ======================================================
    // MISSING ROUTE DATA
    // ======================================================

    if (
        !module ||
        !category
    ) {

        return (

            <PageContainer>

                <PageHeader
                    title="Lookup Category"
                    subtitle="Manage system lookup values"
                />


                <Card>

                    <CardContent>

                        <Alert
                            severity="error"
                            sx={{
                                mb: 2
                            }}
                        >
                            Missing lookup module or category.
                        </Alert>


                        <Typography
                            variant="body2"
                            sx={{
                                mb: 2
                            }}
                        >
                            /lookups/module/:module/category/:category
                        </Typography>


                        <Button
                            component={Link}
                            to="/lookups"
                            startIcon={
                                <ArrowBack />
                            }
                        >
                            Back to Lookups
                        </Button>

                    </CardContent>

                </Card>

            </PageContainer>

        );

    }


    // ======================================================
    // RENDER
    // ======================================================

    return (

        <PageContainer>

            <PageHeader
                title={
                    `${moduleLabel} — ${category}`
                }
                subtitle={
                    `Manage ${category} lookup values`
                }
            />


            <Box
                sx={{
                    mb: 2
                }}
            >

                <Button
                    startIcon={
                        <ArrowBack />
                    }
                    onClick={
                        handleBack
                    }
                    disabled={
                        saving
                    }
                >
                    Back to Lookups
                </Button>

            </Box>


            {/* ==================================================
                INFORMATION
            ================================================== */}

            <Card
                sx={{
                    mb: 3
                }}
            >

                <CardContent>

                    <Stack
                        spacing={2}
                    >

                        <Box>

                            <Typography
                                variant="body2"
                                color="text.secondary"
                            >
                                Module
                            </Typography>


                            <Typography
                                variant="h6"
                                fontWeight={700}
                            >
                                {moduleLabel}
                            </Typography>

                        </Box>


                        <Box>

                            <Typography
                                variant="body2"
                                color="text.secondary"
                            >
                                Category
                            </Typography>


                            <Typography
                                variant="h6"
                                fontWeight={700}
                            >
                                {category}
                            </Typography>

                        </Box>


                        <Stack
                            direction="row"
                            spacing={1}
                            flexWrap="wrap"
                        >

                            <Chip
                                label={
                                    `${lookups.length} ${
                                        lookups.length === 1
                                            ? "value"
                                            : "values"
                                    }`
                                }
                            />


                            <Chip
                                size="small"
                                label={module}
                            />

                        </Stack>

                    </Stack>

                </CardContent>

            </Card>


            {/* ==================================================
                ERROR
            ================================================== */}

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


            {/* ==================================================
                VALUES
            ================================================== */}

            <Card>

                <CardContent>

                    <Stack
                        spacing={3}
                    >

                        {/* HEADER */}

                        <Stack
                            direction={{
                                xs: "column",
                                sm: "row"
                            }}
                            justifyContent="space-between"
                            alignItems={{
                                xs: "flex-start",
                                sm: "center"
                            }}
                            spacing={2}
                        >

                            <Box>

                                <Typography
                                    variant="h6"
                                    fontWeight={700}
                                >
                                    Lookup Values
                                </Typography>


                                <Typography
                                    variant="body2"
                                    color="text.secondary"
                                >
                                    Values available for{" "}
                                    <strong>
                                        {category}
                                    </strong>
                                </Typography>

                            </Box>


                            <Button
                                variant="contained"
                                startIcon={
                                    <Add />
                                }
                                onClick={() =>
                                    setShowAddForm(
                                        previous =>
                                            !previous
                                    )
                                }
                                disabled={
                                    saving
                                }
                            >
                                {
                                    showAddForm
                                        ? "Close"
                                        : "Add Value"
                                }
                            </Button>

                        </Stack>


                        <Divider />


                        {/* ==================================================
                            ADD FORM
                        ================================================== */}

                        {showAddForm && (

                            <Card
                                variant="outlined"
                            >

                                <CardContent>

                                    <Stack
                                        spacing={2}
                                    >

                                        <Typography
                                            fontWeight={700}
                                        >
                                            Add New Value
                                        </Typography>


                                        {/* ==================================================
                                            SERVICE CATEGORY
                                        ================================================== */}

                                        {isServiceType && (

                                            <FormControl
                                                fullWidth
                                                required
                                                disabled={
                                                    loadingParentCategories ||
                                                    saving
                                                }
                                            >

                                                <InputLabel>
                                                    Service Category
                                                </InputLabel>


                                                <Select
                                                    value={
                                                        newValue.parentLookup
                                                    }
                                                    label="Service Category"
                                                    onChange={
                                                        event =>
                                                            handleNewValueChange(
                                                                "parentLookup",
                                                                event.target.value
                                                            )
                                                    }
                                                >

                                                    <MenuItem value="">
                                                        <em>
                                                            {
                                                                loadingParentCategories
                                                                    ? "Loading service categories..."
                                                                    : "Select Service Category"
                                                            }
                                                        </em>
                                                    </MenuItem>


                                                    {parentCategories.map(
                                                        item => {

                                                            const parentId =
                                                                getLookupId(
                                                                    item
                                                                );


                                                            const parentLabel =
                                                                getLookupLabel(
                                                                    item
                                                                );


                                                            if (!parentId) {
                                                                return null;
                                                            }


                                                            return (

                                                                <MenuItem
                                                                    key={
                                                                        parentId
                                                                    }
                                                                    value={
                                                                        parentId
                                                                    }
                                                                >
                                                                    {
                                                                        parentLabel ||
                                                                        parentId
                                                                    }
                                                                </MenuItem>

                                                            );

                                                        }
                                                    )}

                                                </Select>

                                            </FormControl>

                                        )}


                                        {/* ==================================================
                                            ALLOCATION BEHAVIOR
                                        ================================================== */}

                                        {isServiceType && (

                                            <FormControl
                                                fullWidth
                                                required
                                                disabled={
                                                    saving
                                                }
                                            >

                                                <InputLabel>
                                                    Allocation Behavior
                                                </InputLabel>


                                                <Select
                                                    value={
                                                        newValue.allocationBehavior
                                                    }
                                                    label="Allocation Behavior"
                                                    onChange={
                                                        event =>
                                                            handleNewValueChange(
                                                                "allocationBehavior",
                                                                event.target.value
                                                            )
                                                    }
                                                >

                                                    {ALLOCATION_BEHAVIORS.map(
                                                        behavior => (

                                                            <MenuItem
                                                                key={
                                                                    behavior.value
                                                                }
                                                                value={
                                                                    behavior.value
                                                                }
                                                            >
                                                                {
                                                                    behavior.label
                                                                }
                                                            </MenuItem>

                                                        )
                                                    )}

                                                </Select>


                                                <Typography
                                                    variant="caption"
                                                    color="text.secondary"
                                                    sx={{
                                                        mt: 0.75,
                                                        display: "block"
                                                    }}
                                                >
                                                    Consumption uses the delivered quantity as a shared pool. Participation allows each beneficiary to participate independently in the delivered quantity.
                                                </Typography>

                                            </FormControl>

                                        )}


                                        {/* ==================================================
                                            ALLOWED UNITS
                                        ================================================== */}

                                        {isServiceType && (

                                            <FormControl
                                                fullWidth
                                                required
                                                disabled={
                                                    loadingAllowedUnits ||
                                                    saving
                                                }
                                            >

                                                <InputLabel>
                                                    Allowed Units
                                                </InputLabel>


                                                <Select
                                                    multiple
                                                    value={
                                                        newValue.allowedUnits
                                                    }
                                                    label="Allowed Units"
                                                    onChange={
                                                        handleNewAllowedUnitsChange
                                                    }
                                                    renderValue={
                                                        selected => {

                                                            const selectedIds =
                                                                normalizeIdArray(
                                                                    selected
                                                                );


                                                            const selectedLabels =
                                                                allowedUnitOptions
                                                                    .filter(
                                                                        unit =>
                                                                            selectedIds.includes(
                                                                                getLookupId(
                                                                                    unit
                                                                                )
                                                                            )
                                                                    )
                                                                    .map(
                                                                        unit =>
                                                                            getLookupLabel(
                                                                                unit
                                                                            )
                                                                    )
                                                                    .filter(
                                                                        Boolean
                                                                    );


                                                            return (

                                                                <Box
                                                                    sx={{
                                                                        display: "flex",
                                                                        flexWrap: "wrap",
                                                                        gap: 0.5
                                                                    }}
                                                                >

                                                                    {selectedLabels.map(
                                                                        label => (

                                                                            <Chip
                                                                                key={
                                                                                    label
                                                                                }
                                                                                size="small"
                                                                                label={
                                                                                    label
                                                                                }
                                                                            />

                                                                        )
                                                                    )}

                                                                </Box>

                                                            );

                                                        }
                                                    }
                                                >

                                                    {loadingAllowedUnits && (

                                                        <MenuItem
                                                            disabled
                                                        >
                                                            Loading units...
                                                        </MenuItem>

                                                    )}


                                                    {!loadingAllowedUnits &&
                                                        allowedUnitOptions.length === 0 && (

                                                            <MenuItem
                                                                disabled
                                                            >
                                                                No active units found.
                                                            </MenuItem>

                                                        )}


                                                    {!loadingAllowedUnits &&
                                                        allowedUnitOptions.map(
                                                            unit => {

                                                                const unitId =
                                                                    getLookupId(
                                                                        unit
                                                                    );


                                                                const unitLabel =
                                                                    getLookupLabel(
                                                                        unit
                                                                    );


                                                                if (!unitId) {
                                                                    return null;
                                                                }


                                                                return (

                                                                    <MenuItem
                                                                        key={
                                                                            unitId
                                                                        }
                                                                        value={
                                                                            unitId
                                                                        }
                                                                    >
                                                                        {
                                                                            unitLabel ||
                                                                            unitId
                                                                        }
                                                                    </MenuItem>

                                                                );

                                                            }
                                                        )}

                                                </Select>


                                                <Typography
                                                    variant="caption"
                                                    color="text.secondary"
                                                    sx={{
                                                        mt: 0.75,
                                                        display: "block"
                                                    }}
                                                >
                                                    Select the units that this Service Type is allowed to use. There is no default unit.
                                                </Typography>

                                            </FormControl>

                                        )}


                                        <TextField
                                            label="Value"
                                            value={
                                                newValue.value
                                            }
                                            onChange={
                                                event =>
                                                    handleNewValueChange(
                                                        "value",
                                                        event.target.value
                                                    )
                                            }
                                            required
                                            fullWidth
                                            disabled={
                                                saving
                                            }
                                            placeholder="Example: Medical Consultation"
                                        />


                                        <TextField
                                            label="Code"
                                            value={
                                                newValue.code
                                            }
                                            onChange={
                                                event =>
                                                    handleNewValueChange(
                                                        "code",
                                                        event.target.value
                                                    )
                                            }
                                            fullWidth
                                            disabled={
                                                saving
                                            }
                                            placeholder="Example: MED_CONSULT"
                                            helperText="Optional"
                                        />


                                        <Stack
                                            direction="row"
                                            alignItems="center"
                                            spacing={1}
                                        >

                                            <Switch
                                                checked={
                                                    newValue.active
                                                }
                                                onChange={
                                                    event =>
                                                        handleNewValueChange(
                                                            "active",
                                                            event.target.checked
                                                        )
                                                }
                                                disabled={
                                                    saving
                                                }
                                            />


                                            <Typography>
                                                {
                                                    newValue.active
                                                        ? "Active"
                                                        : "Inactive"
                                                }
                                            </Typography>

                                        </Stack>


                                        <Stack
                                            direction={{
                                                xs: "column",
                                                sm: "row"
                                            }}
                                            spacing={2}
                                        >

                                            <Button
                                                variant="contained"
                                                startIcon={
                                                    <Save />
                                                }
                                                onClick={
                                                    handleCreate
                                                }
                                                disabled={
                                                    saving ||
                                                    !String(
                                                        newValue.value || ""
                                                    ).trim() ||
                                                    (
                                                        isServiceType &&
                                                        (
                                                            !newValue.parentLookup ||
                                                            !Array.isArray(
                                                                newValue.allowedUnits
                                                            ) ||
                                                            newValue.allowedUnits.length === 0 ||
                                                            !newValue.allocationBehavior
                                                        )
                                                    )
                                                }
                                            >
                                                {
                                                    saving
                                                        ? "Saving..."
                                                        : "Save Value"
                                                }
                                            </Button>


                                            <Button
                                                variant="outlined"
                                                startIcon={
                                                    <Cancel />
                                                }
                                                onClick={() => {

                                                    setShowAddForm(
                                                        false
                                                    );

                                                    setNewValue(
                                                        createEmptyForm()
                                                    );

                                                    setError("");

                                                }}
                                                disabled={
                                                    saving
                                                }
                                            >
                                                Cancel
                                            </Button>

                                        </Stack>

                                    </Stack>

                                </CardContent>

                            </Card>

                        )}


                        {/* ==================================================
                            LOADING
                        ================================================== */}

                        {loading && (

                            <Stack
                                alignItems="center"
                                py={6}
                            >

                                <CircularProgress />


                                <Typography
                                    variant="body2"
                                    color="text.secondary"
                                    sx={{
                                        mt: 2
                                    }}
                                >
                                    Loading lookup values...
                                </Typography>

                            </Stack>

                        )}


                        {/* ==================================================
                            EMPTY
                        ================================================== */}

                        {!loading &&
                            lookups.length === 0 && (

                                <Card
                                    variant="outlined"
                                >

                                    <CardContent>

                                        <Typography
                                            align="center"
                                            color="text.secondary"
                                            py={4}
                                        >
                                            No values found for{" "}
                                            <strong>
                                                {category}
                                            </strong>.
                                        </Typography>

                                    </CardContent>

                                </Card>

                            )}


                        {/* ==================================================
                            VALUE LIST
                        ================================================== */}

                        {!loading &&
                            lookups.length > 0 && (

                                <Stack
                                    spacing={2}
                                >

                                    {lookups.map(
                                        (
                                            lookup,
                                            index
                                        ) => {

                                            const isEditing =
                                                editingId ===
                                                lookup?._id;


                                            const lookupAllowedUnits =
                                                normalizeIdArray(
                                                    lookup?.allowedUnits
                                                );


                                            const lookupAllocationBehavior =
                                                isServiceType
                                                    ? normalizeAllocationBehavior(
                                                        lookup?.allocationBehavior
                                                    )
                                                    : null;


                                            const allocationBehaviorLabel =
                                                ALLOCATION_BEHAVIORS.find(
                                                    item =>
                                                        item.value ===
                                                        lookupAllocationBehavior
                                                )?.label ||
                                                "Consumption";


                                            return (

                                                <Card
                                                    key={
                                                        lookup?._id ||
                                                        index
                                                    }
                                                    variant="outlined"
                                                >

                                                    <CardContent>

                                                        {isEditing ? (

                                                            <Stack
                                                                spacing={2}
                                                            >

                                                                <Typography
                                                                    fontWeight={700}
                                                                >
                                                                    Edit Lookup Value
                                                                </Typography>


                                                                {/* ==================================================
                                                                    SERVICE CATEGORY
                                                                ================================================== */}

                                                                {isServiceType && (

                                                                    <FormControl
                                                                        fullWidth
                                                                        required
                                                                        disabled={
                                                                            loadingParentCategories ||
                                                                            saving
                                                                        }
                                                                    >

                                                                        <InputLabel>
                                                                            Service Category
                                                                        </InputLabel>


                                                                        <Select
                                                                            value={
                                                                                editForm.parentLookup
                                                                            }
                                                                            label="Service Category"
                                                                            onChange={
                                                                                event =>
                                                                                    handleEditChange(
                                                                                        "parentLookup",
                                                                                        event.target.value
                                                                                    )
                                                                            }
                                                                        >

                                                                            <MenuItem value="">
                                                                                <em>
                                                                                    {
                                                                                        loadingParentCategories
                                                                                            ? "Loading service categories..."
                                                                                            : "Select Service Category"
                                                                                    }
                                                                                </em>
                                                                            </MenuItem>


                                                                            {parentCategories.map(
                                                                                item => {

                                                                                    const parentId =
                                                                                        getLookupId(
                                                                                            item
                                                                                        );


                                                                                    const parentLabel =
                                                                                        getLookupLabel(
                                                                                            item
                                                                                        );


                                                                                    if (!parentId) {
                                                                                        return null;
                                                                                    }


                                                                                    return (

                                                                                        <MenuItem
                                                                                            key={
                                                                                                parentId
                                                                                            }
                                                                                            value={
                                                                                                parentId
                                                                                            }
                                                                                        >
                                                                                            {
                                                                                                parentLabel ||
                                                                                                parentId
                                                                                            }
                                                                                        </MenuItem>

                                                                                    );

                                                                                }
                                                                            )}

                                                                        </Select>

                                                                    </FormControl>

                                                                )}


                                                                {/* ==================================================
                                                                    ALLOCATION BEHAVIOR
                                                                ================================================== */}

                                                                {isServiceType && (

                                                                    <FormControl
                                                                        fullWidth
                                                                        required
                                                                        disabled={
                                                                            saving
                                                                        }
                                                                    >

                                                                        <InputLabel>
                                                                            Allocation Behavior
                                                                        </InputLabel>


                                                                        <Select
                                                                            value={
                                                                                editForm.allocationBehavior
                                                                            }
                                                                            label="Allocation Behavior"
                                                                            onChange={
                                                                                event =>
                                                                                    handleEditChange(
                                                                                        "allocationBehavior",
                                                                                        event.target.value
                                                                                    )
                                                                            }
                                                                        >

                                                                            {ALLOCATION_BEHAVIORS.map(
                                                                                behavior => (

                                                                                    <MenuItem
                                                                                        key={
                                                                                            behavior.value
                                                                                        }
                                                                                        value={
                                                                                            behavior.value
                                                                                        }
                                                                                    >
                                                                                        {
                                                                                            behavior.label
                                                                                        }
                                                                                    </MenuItem>

                                                                                )
                                                                            )}

                                                                        </Select>


                                                                        <Typography
                                                                            variant="caption"
                                                                            color="text.secondary"
                                                                            sx={{
                                                                                mt: 0.75,
                                                                                display: "block"
                                                                            }}
                                                                        >
                                                                            Consumption uses the delivered quantity as a shared pool. Participation allows each beneficiary to participate independently in the delivered quantity.
                                                                        </Typography>

                                                                    </FormControl>

                                                                )}


                                                                {/* ==================================================
                                                                    ALLOWED UNITS
                                                                ================================================== */}

                                                                {isServiceType && (

                                                                    <FormControl
                                                                        fullWidth
                                                                        required
                                                                        disabled={
                                                                            loadingAllowedUnits ||
                                                                            saving
                                                                        }
                                                                    >

                                                                        <InputLabel>
                                                                            Allowed Units
                                                                        </InputLabel>


                                                                        <Select
                                                                            multiple
                                                                            value={
                                                                                editForm.allowedUnits
                                                                            }
                                                                            label="Allowed Units"
                                                                            onChange={
                                                                                handleEditAllowedUnitsChange
                                                                            }
                                                                            renderValue={
                                                                                selected => {

                                                                                    const selectedIds =
                                                                                        normalizeIdArray(
                                                                                            selected
                                                                                        );


                                                                                    const selectedLabels =
                                                                                        allowedUnitOptions
                                                                                            .filter(
                                                                                                unit =>
                                                                                                    selectedIds.includes(
                                                                                                        getLookupId(
                                                                                                            unit
                                                                                                        )
                                                                                                    )
                                                                                            )
                                                                                            .map(
                                                                                                unit =>
                                                                                                    getLookupLabel(
                                                                                                        unit
                                                                                                    )
                                                                                            )
                                                                                            .filter(
                                                                                                Boolean
                                                                                            );


                                                                                    return (

                                                                                        <Box
                                                                                            sx={{
                                                                                                display: "flex",
                                                                                                flexWrap: "wrap",
                                                                                                gap: 0.5
                                                                                            }}
                                                                                        >

                                                                                            {selectedLabels.map(
                                                                                                label => (

                                                                                                    <Chip
                                                                                                        key={
                                                                                                            label
                                                                                                        }
                                                                                                        size="small"
                                                                                                        label={
                                                                                                            label
                                                                                                        }
                                                                                                    />

                                                                                                )
                                                                                            )}

                                                                                        </Box>

                                                                                    );

                                                                                }
                                                                            }
                                                                        >

                                                                            {loadingAllowedUnits && (

                                                                                <MenuItem
                                                                                    disabled
                                                                                >
                                                                                    Loading units...
                                                                                </MenuItem>

                                                                            )}


                                                                            {!loadingAllowedUnits &&
                                                                                allowedUnitOptions.length === 0 && (

                                                                                    <MenuItem
                                                                                        disabled
                                                                                    >
                                                                                        No active units found.
                                                                                    </MenuItem>

                                                                                )}


                                                                            {!loadingAllowedUnits &&
                                                                                allowedUnitOptions.map(
                                                                                    unit => {

                                                                                        const unitId =
                                                                                            getLookupId(
                                                                                                unit
                                                                                            );


                                                                                        const unitLabel =
                                                                                            getLookupLabel(
                                                                                                unit
                                                                                            );


                                                                                        if (!unitId) {
                                                                                            return null;
                                                                                        }


                                                                                        return (

                                                                                            <MenuItem
                                                                                                key={
                                                                                                    unitId
                                                                                                }
                                                                                                value={
                                                                                                    unitId
                                                                                                }
                                                                                            >
                                                                                                {
                                                                                                    unitLabel ||
                                                                                                    unitId
                                                                                                }
                                                                                            </MenuItem>

                                                                                        );

                                                                                    }
                                                                                )}

                                                                        </Select>


                                                                        <Typography
                                                                            variant="caption"
                                                                            color="text.secondary"
                                                                            sx={{
                                                                                mt: 0.75,
                                                                                display: "block"
                                                                            }}
                                                                        >
                                                                            These are the only units that this Service Type may use. No default unit is assigned.
                                                                        </Typography>

                                                                    </FormControl>

                                                                )}


                                                                <TextField
                                                                    label="Value"
                                                                    value={
                                                                        editForm.value
                                                                    }
                                                                    onChange={
                                                                        event =>
                                                                            handleEditChange(
                                                                                "value",
                                                                                event.target.value
                                                                            )
                                                                    }
                                                                    fullWidth
                                                                    required
                                                                    disabled={
                                                                        saving
                                                                    }
                                                                />


                                                                <TextField
                                                                    label="Code"
                                                                    value={
                                                                        editForm.code
                                                                    }
                                                                    onChange={
                                                                        event =>
                                                                            handleEditChange(
                                                                                "code",
                                                                                event.target.value
                                                                            )
                                                                    }
                                                                    fullWidth
                                                                    disabled={
                                                                        saving
                                                                    }
                                                                />


                                                                <Stack
                                                                    direction="row"
                                                                    alignItems="center"
                                                                    spacing={1}
                                                                >

                                                                    <Switch
                                                                        checked={
                                                                            editForm.active
                                                                        }
                                                                        onChange={
                                                                            event =>
                                                                                handleEditChange(
                                                                                    "active",
                                                                                    event.target.checked
                                                                                )
                                                                        }
                                                                        disabled={
                                                                            saving
                                                                        }
                                                                    />


                                                                    <Typography>
                                                                        {
                                                                            editForm.active
                                                                                ? "Active"
                                                                                : "Inactive"
                                                                        }
                                                                    </Typography>

                                                                </Stack>


                                                                <Stack
                                                                    direction={{
                                                                        xs: "column",
                                                                        sm: "row"
                                                                    }}
                                                                    spacing={2}
                                                                >

                                                                    <Button
                                                                        variant="contained"
                                                                        startIcon={
                                                                            <Save />
                                                                        }
                                                                        onClick={() =>
                                                                            handleSaveEdit(
                                                                                lookup
                                                                            )
                                                                        }
                                                                        disabled={
                                                                            saving ||
                                                                            !String(
                                                                                editForm.value || ""
                                                                            ).trim() ||
                                                                            (
                                                                                isServiceType &&
                                                                                (
                                                                                    !editForm.parentLookup ||
                                                                                    !Array.isArray(
                                                                                        editForm.allowedUnits
                                                                                    ) ||
                                                                                    editForm.allowedUnits.length === 0 ||
                                                                                    !editForm.allocationBehavior
                                                                                )
                                                                            )
                                                                        }
                                                                    >
                                                                        {
                                                                            saving
                                                                                ? "Saving..."
                                                                                : "Save Changes"
                                                                        }
                                                                    </Button>


                                                                    <Button
                                                                        variant="outlined"
                                                                        startIcon={
                                                                            <Cancel />
                                                                        }
                                                                        onClick={
                                                                            handleCancelEdit
                                                                        }
                                                                        disabled={
                                                                            saving
                                                                        }
                                                                    >
                                                                        Cancel
                                                                    </Button>

                                                                </Stack>

                                                            </Stack>

                                                        ) : (

                                                            <Stack
                                                                spacing={2}
                                                            >

                                                                <Stack
                                                                    direction={{
                                                                        xs: "column",
                                                                        sm: "row"
                                                                    }}
                                                                    justifyContent="space-between"
                                                                    alignItems={{
                                                                        xs: "flex-start",
                                                                        sm: "center"
                                                                    }}
                                                                    spacing={2}
                                                                >

                                                                    <Box>

                                                                        <Typography
                                                                            variant="h6"
                                                                            fontWeight={700}
                                                                        >
                                                                            {
                                                                                lookup?.value ||
                                                                                "Unnamed Value"
                                                                            }
                                                                        </Typography>


                                                                        {lookup?.code && (

                                                                            <Typography
                                                                                variant="body2"
                                                                                color="text.secondary"
                                                                            >
                                                                                Code:{" "}
                                                                                {lookup.code}
                                                                            </Typography>

                                                                        )}


                                                                        {isServiceType &&
                                                                            lookup?.parentLookup && (

                                                                                <Typography
                                                                                    variant="body2"
                                                                                    color="text.secondary"
                                                                                >
                                                                                    Service Category:{" "}
                                                                                    {
                                                                                        lookup?.parentLookup?.value ||
                                                                                        lookup?.parentLookup?.label ||
                                                                                        "Assigned"
                                                                                    }
                                                                                </Typography>

                                                                            )}


                                                                        {/* ==================================================
                                                                            ALLOCATION BEHAVIOR DISPLAY
                                                                        ================================================== */}

                                                                        {isServiceType && (

                                                                            <Box
                                                                                sx={{
                                                                                    mt: 1
                                                                                }}
                                                                            >

                                                                                <Typography
                                                                                    variant="body2"
                                                                                    color="text.secondary"
                                                                                >
                                                                                    Allocation Behavior:
                                                                                </Typography>


                                                                                <Chip
                                                                                    size="small"
                                                                                    sx={{
                                                                                        mt: 0.5
                                                                                    }}
                                                                                    label={
                                                                                        allocationBehaviorLabel
                                                                                    }
                                                                                />

                                                                            </Box>

                                                                        )}


                                                                        {isServiceType && (

                                                                            <Box
                                                                                sx={{
                                                                                    mt: 1
                                                                                }}
                                                                            >

                                                                                <Typography
                                                                                    variant="body2"
                                                                                    color="text.secondary"
                                                                                    sx={{
                                                                                        mb: 0.75
                                                                                    }}
                                                                                >
                                                                                    Allowed Units:
                                                                                </Typography>


                                                                                <Stack
                                                                                    direction="row"
                                                                                    spacing={0.75}
                                                                                    flexWrap="wrap"
                                                                                    useFlexGap
                                                                                >

                                                                                    {lookupAllowedUnits.length === 0 ? (

                                                                                        <Chip
                                                                                            size="small"
                                                                                            color="warning"
                                                                                            label="No units configured"
                                                                                        />

                                                                                    ) : (

                                                                                        lookupAllowedUnits.map(
                                                                                            unitId => {

                                                                                                const unit =
                                                                                                    allowedUnitOptions.find(
                                                                                                        item =>
                                                                                                            getLookupId(
                                                                                                                item
                                                                                                            ) ===
                                                                                                            unitId
                                                                                                    );


                                                                                                return (

                                                                                                    <Chip
                                                                                                        key={
                                                                                                            unitId
                                                                                                        }
                                                                                                        size="small"
                                                                                                        label={
                                                                                                            getLookupLabel(
                                                                                                                unit
                                                                                                            ) ||
                                                                                                            unitId
                                                                                                        }
                                                                                                    />

                                                                                                );

                                                                                            }
                                                                                        )

                                                                                    )}

                                                                                </Stack>

                                                                            </Box>

                                                                        )}

                                                                    </Box>


                                                                    <Chip
                                                                        size="small"
                                                                        label={
                                                                            lookup?.active !== false
                                                                                ? "Active"
                                                                                : "Inactive"
                                                                        }
                                                                    />

                                                                </Stack>


                                                                <Divider />


                                                                <Stack
                                                                    direction={{
                                                                        xs: "column",
                                                                        sm: "row"
                                                                    }}
                                                                    justifyContent="space-between"
                                                                    alignItems={{
                                                                        xs: "stretch",
                                                                        sm: "center"
                                                                    }}
                                                                    spacing={2}
                                                                >

                                                                    <Typography
                                                                        variant="body2"
                                                                        color="text.secondary"
                                                                    >
                                                                        {
                                                                            lookup?.category ||
                                                                            category
                                                                        }
                                                                    </Typography>


                                                                    <Stack
                                                                        direction="row"
                                                                        spacing={1}
                                                                    >

                                                                        <Button
                                                                            size="small"
                                                                            variant="outlined"
                                                                            startIcon={
                                                                                <Edit />
                                                                            }
                                                                            onClick={() =>
                                                                                handleEdit(
                                                                                    lookup
                                                                                )
                                                                            }
                                                                            disabled={
                                                                                saving
                                                                            }
                                                                        >
                                                                            Edit
                                                                        </Button>


                                                                        {lookup?.active !== false && (

                                                                            <IconButton
                                                                                color="error"
                                                                                onClick={() =>
                                                                                    handleDelete(
                                                                                        lookup
                                                                                    )
                                                                                }
                                                                                disabled={
                                                                                    saving
                                                                                }
                                                                                title="Deactivate"
                                                                            >
                                                                                <Delete />
                                                                            </IconButton>

                                                                        )}

                                                                    </Stack>

                                                                </Stack>

                                                            </Stack>

                                                        )}

                                                    </CardContent>

                                                </Card>

                                            );

                                        }
                                    )}

                                </Stack>

                            )}

                    </Stack>

                </CardContent>

            </Card>

        </PageContainer>

    );

};


export default LookupCategoryPage;
