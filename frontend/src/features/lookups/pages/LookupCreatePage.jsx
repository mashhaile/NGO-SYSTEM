import {
    useEffect,
    useMemo,
    useState
} from "react";

import {
    useNavigate
} from "react-router-dom";

import {
    Box,
    Button,
    Card,
    CardContent,
    Chip,
    CircularProgress,
    Divider,
    FormControl,
    FormControlLabel,
    IconButton,
    InputLabel,
    MenuItem,
    Select,
    Stack,
    Switch,
    TextField,
    Typography
} from "@mui/material";

import {
    Add,
    ArrowBack,
    Delete
} from "@mui/icons-material";

import {
    createLookupsBulkService,
    getLookupCategoriesByModuleService,
    getLookupsByModuleAndCategoryService,
    getLookupsService
} from "../services/lookupService";

import {
    PageContainer,
    PageHeader
} from "../../../components/ui";


// ==========================================================
// MODULE OPTIONS
// ==========================================================

const MODULE_OPTIONS = [

    {
        value: "beneficiaries",
        label: "Beneficiaries"
    },

    {
        value: "enterprises",
        label: "Enterprises"
    },

    {
        value: "programs",
        label: "Programs"
    },

    {
        value: "projects",
        label: "Projects"
    },

    {
        value: "activities",
        label: "Activities"
    },

    {
        value: "activity-runs",
        label: "Activity Runs"
    },

    {
        value: "attendance",
        label: "Attendance"
    },

    {
        value: "enrollments",
        label: "Enrollments"
    },

    {
        value: "service-delivery",
        label: "Service Delivery"
    },

    {
        value: "users",
        label: "Users"
    },

    {
        value: "donors",
        label: "Donors"
    },

    {
        value: "donations",
        label: "Donations"
    }

];


// ==========================================================
// EMPTY VALUE
// ==========================================================

const createEmptyValue = () => ({

    value: "",

    code: ""

});


// ==========================================================
// RESPONSE NORMALIZER
// ==========================================================

const extractArray = (
    response
) => {

    if (
        Array.isArray(response)
    ) {

        return response;

    }


    if (
        Array.isArray(
            response?.data
        )
    ) {

        return response.data;

    }


    if (
        Array.isArray(
            response?.data?.data
        )
    ) {

        return response.data.data;

    }


    return [];

};


// ==========================================================
// ID HELPER
// ==========================================================

const getLookupId = (
    item
) => {

    if (
        typeof item === "string" ||
        typeof item === "number"
    ) {

        return String(item);

    }


    return String(
        item?._id ??
        item?.id ??
        ""
    );

};


// ==========================================================
// LABEL HELPER
// ==========================================================
//
// IMPORTANT:
//
// Lookup APIs may return:
//
//     value  = ObjectId
//     label  = human-readable lookup value
//
// or:
//
//     value  = human-readable lookup value
//
// The UI must prefer the human-readable fields.
//
// ==========================================================

const getLookupLabel = (
    item
) => {

    if (
        typeof item === "string" ||
        typeof item === "number"
    ) {

        return String(item);

    }


    if (!item) {

        return "";

    }


    const labelCandidates = [

        item?.label,

        item?.name,

        item?.displayValue,

        item?.displayName,

        item?.title,

        item?.value

    ];


    for (
        const candidate
        of labelCandidates
    ) {

        if (
            candidate !== undefined &&
            candidate !== null
        ) {

            const normalized =
                String(candidate).trim();


            if (
                normalized
            ) {

                return normalized;

            }

        }

    }


    return "";

};


// ==========================================================
// CREATE PAGE
// ==========================================================

const LookupCreatePage = () => {

    const navigate =
        useNavigate();


    // ======================================================
    // STATE
    // ======================================================

    const [
        module,
        setModule
    ] = useState("");


    const [
        category,
        setCategory
    ] = useState("");


    const [
        categories,
        setCategories
    ] = useState([]);


    const [
        parentCategories,
        setParentCategories
    ] = useState([]);


    const [
        parentLookup,
        setParentLookup
    ] = useState("");


    const [
        allowedUnits,
        setAllowedUnits
    ] = useState([]);


    const [
        unitOptions,
        setUnitOptions
    ] = useState([]);


    const [
        values,
        setValues
    ] = useState([
        createEmptyValue()
    ]);


    const [
        active,
        setActive
    ] = useState(true);


    const [
        loadingCategories,
        setLoadingCategories
    ] = useState(false);


    const [
        loadingParentCategories,
        setLoadingParentCategories
    ] = useState(false);


    const [
        loadingUnits,
        setLoadingUnits
    ] = useState(false);


    const [
        loadingLookups,
        setLoadingLookups
    ] = useState(false);


    const [
        loading,
        setLoading
    ] = useState(false);


    const [
        error,
        setError
    ] = useState("");


    const [
        existingLookups,
        setExistingLookups
    ] = useState([]);


    // ======================================================
    // MODULE LABEL
    // ======================================================

    const moduleLabel =
        useMemo(() => {

            return (
                MODULE_OPTIONS.find(
                    item =>
                        item.value ===
                        module
                )?.label ||
                module ||
                "Unknown"
            );

        }, [
            module
        ]);


    // ======================================================
    // IS SERVICE TYPE
    // ======================================================

    const isServiceType =
        category ===
        "ServiceType";


    // ======================================================
    // SELECTED CATEGORY
    // ======================================================

    const selectedCategory =
        useMemo(() => {

            if (!category) {

                return null;

            }


            const normalized =
                category
                    .trim()
                    .toLowerCase();


            return (
                categories.find(
                    item => {

                        const itemCategory =
                            String(
                                item?.category ||
                                item?.key ||
                                ""
                            )
                                .trim()
                                .toLowerCase();


                        return (
                            itemCategory ===
                            normalized
                        );

                    }
                ) ||
                null
            );

        }, [
            categories,
            category
        ]);


    // ======================================================
    // EXISTING VALUES
    // ======================================================

    const existingValues =
        useMemo(() => {

            if (
                !category ||
                !module
            ) {

                return [];

            }


            const normalizedCategory =
                category
                    .trim()
                    .toLowerCase();


            const normalizedModule =
                module
                    .trim()
                    .toLowerCase();


            return existingLookups
                .filter(
                    lookup => {

                        const lookupCategory =
                            String(
                                lookup?.category ||
                                ""
                            )
                                .trim()
                                .toLowerCase();


                        const lookupModule =
                            String(
                                lookup?.module ||
                                ""
                            )
                                .trim()
                                .toLowerCase();


                        return (
                            lookupCategory ===
                            normalizedCategory &&
                            lookupModule ===
                            normalizedModule
                        );

                    }
                )
                .map(
                    lookup =>
                        String(
                            lookup?.value ||
                            ""
                        )
                            .trim()
                            .toLowerCase()
                )
                .filter(Boolean);

        }, [
            existingLookups,
            category,
            module
        ]);


    // ======================================================
    // SELECTED UNIT LABELS
    // ======================================================

    const selectedUnitLabels =
        useMemo(() => {

            return allowedUnits.map(
                unitId => {

                    const option =
                        unitOptions.find(
                            item =>
                                String(
                                    getLookupId(item)
                                ) ===
                                String(unitId)
                        );


                    return (
                        getLookupLabel(option) ||
                        String(unitId)
                    );

                }
            );

        }, [
            allowedUnits,
            unitOptions
        ]);


    // ======================================================
    // LOAD MODULE DATA
    // ======================================================

    useEffect(() => {

        let cancelled = false;


        const loadData = async () => {

            if (!module) {

                setCategories([]);

                setParentCategories([]);

                setExistingLookups([]);

                setCategory("");

                setParentLookup("");

                setAllowedUnits([]);

                setUnitOptions([]);

                setError("");

                return;

            }


            try {

                setLoadingCategories(true);

                setLoadingLookups(true);

                setError("");

                setCategory("");

                setParentLookup("");

                setAllowedUnits([]);

                setParentCategories([]);

                setUnitOptions([]);

                setCategories([]);

                setExistingLookups([]);


                // ==========================================
                // SYSTEM CATEGORIES
                // ==========================================

                const categoryResponse =
                    await getLookupCategoriesByModuleService(
                        module
                    );


                const categoryRows =
                    extractArray(
                        categoryResponse
                    );


                if (!cancelled) {

                    setCategories(
                        categoryRows
                    );

                }


                // ==========================================
                // EXISTING LOOKUPS
                // ==========================================

                try {

                    const lookupResponse =
                        await getLookupsService({
                            module
                        });


                    const lookupRows =
                        extractArray(
                            lookupResponse
                        );


                    if (!cancelled) {

                        setExistingLookups(
                            lookupRows
                        );

                    }

                }
                catch (lookupError) {

                    console.error(
                        "Failed loading existing lookups:",
                        lookupError
                    );


                    if (!cancelled) {

                        setExistingLookups([]);

                    }

                }

            }
            catch (categoryError) {

                console.error(
                    "Failed loading categories:",
                    categoryError
                );


                if (!cancelled) {

                    setCategories([]);

                    setParentCategories([]);

                    setExistingLookups([]);

                    setError(
                        categoryError
                            ?.response
                            ?.data
                            ?.message ||
                        categoryError?.message ||
                        "Failed to load lookup categories."
                    );

                }

            }
            finally {

                if (!cancelled) {

                    setLoadingCategories(false);

                    setLoadingLookups(false);

                }

            }

        };


        loadData();


        return () => {

            cancelled = true;

        };

    }, [
        module
    ]);


    // ======================================================
    // LOAD SERVICE CATEGORIES
    // ======================================================

    useEffect(() => {

        let cancelled = false;


        const loadParentCategories = async () => {

            if (
                !module ||
                category !== "ServiceType"
            ) {

                setParentCategories([]);

                setParentLookup("");

                return;

            }


            try {

                setLoadingParentCategories(true);

                setError("");


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

                    setParentLookup("");

                    setError(
                        parentError
                            ?.response
                            ?.data
                            ?.message ||
                        parentError?.message ||
                        "Failed to load Service Categories."
                    );

                }

            }
            finally {

                if (!cancelled) {

                    setLoadingParentCategories(false);

                }

            }

        };


        loadParentCategories();


        return () => {

            cancelled = true;

        };

    }, [
        module,
        category
    ]);


    // ======================================================
    // LOAD SERVICE DELIVERY UNITS
    // ======================================================

    useEffect(() => {

        let cancelled = false;


        const loadUnits = async () => {

            if (
                module !== "service-delivery" ||
                category !== "ServiceType"
            ) {

                setUnitOptions([]);

                setAllowedUnits([]);

                return;

            }


            try {

                setLoadingUnits(true);

                setError("");


                const response =
                    await getLookupsByModuleAndCategoryService(
                        "ServiceDelivery",
                        "Unit"
                    );


                const rows =
                    extractArray(
                        response
                    );


                const normalizedRows =
                    rows
                        .map(
                            item => {

                                const id =
                                    getLookupId(
                                        item
                                    );


                                const label =
                                    getLookupLabel(
                                        item
                                    );


                                return {

                                    id,

                                    value:
                                        id,

                                    label,

                                    code:
                                        item?.code ||
                                        "",

                                    semanticType:
                                        item?.semanticType ||
                                        null,

                                    active:
                                        item?.active !== false,

                                    original:
                                        item

                                };

                            }
                        )
                        .filter(
                            item =>
                                Boolean(
                                    item.id
                                ) &&
                                Boolean(
                                    item.label
                                ) &&
                                item.active
                        )
                        .filter(
                            (
                                item,
                                index,
                                array
                            ) =>
                                array.findIndex(
                                    candidate =>
                                        String(
                                            candidate.id
                                        ) ===
                                        String(
                                            item.id
                                        )
                                ) ===
                                index
                        );


                if (!cancelled) {

                    setUnitOptions(
                        normalizedRows
                    );

                }

            }
            catch (unitError) {

                console.error(
                    "Failed loading Service Delivery Units:",
                    unitError
                );


                if (!cancelled) {

                    setUnitOptions([]);

                    setAllowedUnits([]);

                    setError(
                        unitError
                            ?.response
                            ?.data
                            ?.message ||
                        unitError?.message ||
                        "Failed to load Service Delivery Units."
                    );

                }

            }
            finally {

                if (!cancelled) {

                    setLoadingUnits(false);

                }

            }

        };


        loadUnits();


        return () => {

            cancelled = true;

        };

    }, [
        module,
        category
    ]);


    // ======================================================
    // MODULE CHANGE
    // ======================================================

    const handleModuleChange =
        event => {

            const selectedModule =
                event.target.value;


            setModule(
                selectedModule
            );

            setCategory("");

            setParentLookup("");

            setAllowedUnits([]);

            setParentCategories([]);

            setUnitOptions([]);

            setCategories([]);

            setExistingLookups([]);

            setError("");

            setValues([
                createEmptyValue()
            ]);

        };


    // ======================================================
    // CATEGORY CHANGE
    // ======================================================

    const handleCategoryChange =
        event => {

            const selectedCategory =
                event.target.value;


            setCategory(
                selectedCategory
            );

            setParentLookup("");

            setAllowedUnits([]);

            setError("");

            setValues([
                createEmptyValue()
            ]);

        };


    // ======================================================
    // PARENT CATEGORY CHANGE
    // ======================================================

    const handleParentLookupChange =
        event => {

            setParentLookup(
                event.target.value
            );

            setError("");

            setValues([
                createEmptyValue()
            ]);

        };


    // ======================================================
    // ALLOWED UNITS CHANGE
    // ======================================================

    const handleAllowedUnitsChange =
        event => {

            const value =
                event.target.value;


            const selected =
                Array.isArray(value)
                    ? value
                    : [];


            const normalized =
                selected
                    .map(
                        item =>
                            String(item)
                    )
                    .filter(Boolean)
                    .filter(
                        (
                            item,
                            index,
                            array
                        ) =>
                            array.indexOf(
                                item
                            ) ===
                            index
                    );


            setAllowedUnits(
                normalized
            );

            setError("");

        };


    // ======================================================
    // ADD VALUE
    // ======================================================

    const handleAddValue = () => {

        setValues(
            previous =>
                previous.concat([
                    createEmptyValue()
                ])
        );

    };


    // ======================================================
    // REMOVE VALUE
    // ======================================================

    const handleRemoveValue =
        index => {

            setValues(
                previous => {

                    if (
                        previous.length <= 1
                    ) {

                        return previous;

                    }


                    return previous.filter(
                        (
                            _,
                            currentIndex
                        ) =>
                            currentIndex !==
                            index
                    );

                }
            );

        };


    // ======================================================
    // VALUE CHANGE
    // ======================================================

    const handleValueChange = (
        index,
        field,
        newValue
    ) => {

        setValues(
            previous =>
                previous.map(
                    (
                        item,
                        currentIndex
                    ) => {

                        if (
                            currentIndex !==
                            index
                        ) {

                            return item;

                        }


                        return Object.assign(
                            {},
                            item,
                            {
                                [field]:
                                    newValue
                            }
                        );

                    }
                )
        );

    };


    // ======================================================
    // SUBMIT
    // ======================================================

    const handleSubmit =
        async event => {

            event.preventDefault();

            setError("");


            const cleanModule =
                String(
                    module || ""
                ).trim();


            const cleanCategory =
                String(
                    category || ""
                ).trim();


            const cleanParentLookup =
                String(
                    parentLookup || ""
                ).trim();


            const cleanAllowedUnits =
                allowedUnits
                    .map(
                        unitId =>
                            String(
                                unitId || ""
                            ).trim()
                    )
                    .filter(Boolean)
                    .filter(
                        (
                            unitId,
                            index,
                            array
                        ) =>
                            array.indexOf(
                                unitId
                            ) ===
                            index
                    );


            // ==============================================
            // BASIC VALIDATION
            // ==============================================

            if (!cleanModule) {

                setError(
                    "Module is required."
                );

                return;

            }


            if (!cleanCategory) {

                setError(
                    "Category is required."
                );

                return;

            }


            // ==============================================
            // CATEGORY VALIDATION
            // ==============================================

            const validCategory =
                categories.some(
                    item => {

                        const itemCategory =
                            String(
                                item?.category ||
                                item?.key ||
                                ""
                            )
                                .trim()
                                .toLowerCase();


                        return (
                            itemCategory ===
                            cleanCategory.toLowerCase()
                        );

                    }
                );


            if (!validCategory) {

                setError(
                    "The selected category is not available for this module."
                );

                return;

            }


            // ==============================================
            // SERVICE TYPE PARENT VALIDATION
            // ==============================================

            if (
                isServiceType &&
                !cleanParentLookup
            ) {

                setError(
                    "Service Category is required when creating a Service Type."
                );

                return;

            }


            // ==============================================
            // SERVICE TYPE ALLOWED UNIT VALIDATION
            // ==============================================

            if (
                isServiceType &&
                cleanAllowedUnits.length === 0
            ) {

                setError(
                    "At least one Allowed Unit is required when creating a Service Type."
                );

                return;

            }


            if (
                isServiceType &&
                cleanAllowedUnits.some(
                    unitId =>
                        !unitOptions.some(
                            option =>
                                String(
                                    getLookupId(
                                        option
                                    )
                                ) ===
                                String(
                                    unitId
                                )
                        )
                )
            ) {

                setError(
                    "One or more selected Allowed Units are no longer available."
                );

                return;

            }


            // ==============================================
            // VALUES
            // ==============================================

            const cleanValues =
                values.map(
                    item => ({

                        value:
                            String(
                                item?.value ||
                                ""
                            ).trim(),

                        code:
                            String(
                                item?.code ||
                                ""
                            ).trim()

                    })
                );


            if (
                cleanValues.some(
                    item =>
                        !item.value
                )
            ) {

                setError(
                    "Every lookup must have a value."
                );

                return;

            }


            // ==============================================
            // FORM DUPLICATES
            // ==============================================

            const normalizedValues =
                cleanValues.map(
                    item =>
                        item.value
                            .toLowerCase()
                );


            if (
                new Set(
                    normalizedValues
                ).size !==
                normalizedValues.length
            ) {

                setError(
                    "Duplicate values are not allowed in the same submission."
                );

                return;

            }


            // ==============================================
            // DATABASE DUPLICATE
            // ==============================================

            const duplicate =
                cleanValues.find(
                    item =>
                        existingValues.includes(
                            item.value.toLowerCase()
                        )
                );


            if (duplicate) {

                setError(
                    `"${duplicate.value}" already exists in the "${cleanCategory}" category.`
                );

                return;

            }


            // ==============================================
            // CREATE
            // ==============================================

            try {

                setLoading(true);


                const payloadValues =
                    cleanValues.map(
                        item => {

                            const payloadItem =
                                Object.assign(
                                    {},
                                    item
                                );


                            if (
                                isServiceType
                            ) {

                                payloadItem.parentLookup =
                                    cleanParentLookup;


                                payloadItem.allowedUnits =
                                    cleanAllowedUnits.slice();

                            }


                            return payloadItem;

                        }
                    );


                const payload = {

                    module:
                        cleanModule,

                    category:
                        cleanCategory,

                    values:
                        payloadValues,

                    active

                };


                console.log(
                    "CREATE LOOKUP PAYLOAD:",
                    payload
                );


                await createLookupsBulkService(
                    payload
                );


                navigate(
                    `/lookups/module/${encodeURIComponent(
                        cleanModule
                    )}/category/${encodeURIComponent(
                        cleanCategory
                    )}`
                );

            }
            catch (createError) {

                console.error(
                    "Failed to create lookups:",
                    createError
                );


                console.error(
                    "Backend response:",
                    createError?.response?.data
                );


                console.error(
                    "Backend status:",
                    createError?.response?.status
                );


                console.error(
                    "Submitted payload:",
                    {
                        module:
                            cleanModule,

                        category:
                            cleanCategory,

                        parentLookup:
                            cleanParentLookup,

                        allowedUnits:
                            cleanAllowedUnits,

                        values:
                            cleanValues,

                        active
                    }
                );


                setError(
                    createError
                        ?.response
                        ?.data
                        ?.message ||
                    createError?.message ||
                    "Failed to create lookups."
                );

            }
            finally {

                setLoading(false);

            }

        };


    // ======================================================
    // RENDER
    // ======================================================

    return (

        <PageContainer>

            <PageHeader
                title="Create Lookups"
                subtitle="Add lookup values to a system-defined category"
            />


            <Box sx={{ mb: 2 }}>

                <Button
                    startIcon={
                        <ArrowBack />
                    }
                    onClick={() =>
                        navigate("/lookups")
                    }
                    disabled={loading}
                >
                    Back to Lookups
                </Button>

            </Box>


            <Card>

                <CardContent>

                    <Box
                        component="form"
                        onSubmit={
                            handleSubmit
                        }
                    >

                        <Stack spacing={3}>

                            {/* ==================================================
                                MODULE
                            ================================================== */}

                            <FormControl
                                fullWidth
                                required
                            >

                                <InputLabel>
                                    Module
                                </InputLabel>

                                <Select
                                    value={
                                        module
                                    }
                                    label="Module"
                                    onChange={
                                        handleModuleChange
                                    }
                                    disabled={
                                        loading
                                    }
                                >

                                    <MenuItem value="">
                                        <em>
                                            Select Module
                                        </em>
                                    </MenuItem>


                                    {
                                        MODULE_OPTIONS.map(
                                            item => (

                                                <MenuItem
                                                    key={
                                                        item.value
                                                    }
                                                    value={
                                                        item.value
                                                    }
                                                >
                                                    {
                                                        item.label
                                                    }
                                                </MenuItem>

                                            )
                                        )
                                    }

                                </Select>

                            </FormControl>


                            {/* ==================================================
                                CATEGORY
                            ================================================== */}

                            <FormControl
                                fullWidth
                                required
                                disabled={
                                    !module ||
                                    loadingCategories ||
                                    loading
                                }
                            >

                                <InputLabel>
                                    Category
                                </InputLabel>

                                <Select
                                    value={
                                        category
                                    }
                                    label="Category"
                                    onChange={
                                        handleCategoryChange
                                    }
                                >

                                    <MenuItem value="">
                                        <em>
                                            {
                                                loadingCategories
                                                    ? "Loading categories..."
                                                    : categories.length
                                                        ? "Select Category"
                                                        : "No categories available"
                                            }
                                        </em>
                                    </MenuItem>


                                    {
                                        categories.map(
                                            item => {

                                                const itemCategory =
                                                    String(
                                                        item?.category ||
                                                        item?.key ||
                                                        ""
                                                    ).trim();


                                                if (
                                                    !itemCategory
                                                ) {

                                                    return null;

                                                }


                                                return (

                                                    <MenuItem
                                                        key={
                                                            itemCategory
                                                        }
                                                        value={
                                                            itemCategory
                                                        }
                                                    >

                                                        {
                                                            getLookupLabel(
                                                                item
                                                            ) ||
                                                            itemCategory
                                                        }

                                                    </MenuItem>

                                                );

                                            }
                                        )
                                    }

                                </Select>

                            </FormControl>


                            {/* ==================================================
                                SERVICE CATEGORY PARENT
                            ================================================== */}

                            {
                                isServiceType && (

                                    <FormControl
                                        fullWidth
                                        required
                                        disabled={
                                            loading ||
                                            loadingParentCategories ||
                                            !category
                                        }
                                    >

                                        <InputLabel>
                                            Service Category
                                        </InputLabel>

                                        <Select
                                            value={
                                                parentLookup
                                            }
                                            label="Service Category"
                                            onChange={
                                                handleParentLookupChange
                                            }
                                        >

                                            <MenuItem value="">
                                                <em>
                                                    {
                                                        loadingParentCategories
                                                            ? "Loading Service Categories..."
                                                            : parentCategories.length
                                                                ? "Select Service Category"
                                                                : "No Service Categories available"
                                                    }
                                                </em>
                                            </MenuItem>


                                            {
                                                parentCategories.map(
                                                    item => {

                                                        const id =
                                                            item?._id ??
                                                            item?.id ??
                                                            "";


                                                        const label =
                                                            getLookupLabel(
                                                                item
                                                            );


                                                        if (
                                                            !id ||
                                                            !label
                                                        ) {

                                                            return null;

                                                        }


                                                        return (

                                                            <MenuItem
                                                                key={
                                                                    String(id)
                                                                }
                                                                value={
                                                                    String(id)
                                                                }
                                                            >
                                                                {
                                                                    label
                                                                }
                                                            </MenuItem>

                                                        );

                                                    }
                                                )
                                            }

                                        </Select>

                                    </FormControl>

                                )
                            }


                            {/* ==================================================
                                ALLOWED UNITS
                            ================================================== */}

                            {
                                isServiceType && (

                                    <FormControl
                                        fullWidth
                                        required
                                        disabled={
                                            loading ||
                                            loadingUnits ||
                                            !parentLookup
                                        }
                                    >

                                        <InputLabel>
                                            Allowed Units
                                        </InputLabel>

                                        <Select
                                            multiple
                                            value={
                                                allowedUnits
                                            }
                                            label="Allowed Units"
                                            onChange={
                                                handleAllowedUnitsChange
                                            }
                                            renderValue={
                                                selected => {

                                                    if (
                                                        !Array.isArray(
                                                            selected
                                                        ) ||
                                                        selected.length === 0
                                                    ) {

                                                        return "Select Allowed Units";

                                                    }


                                                    return (

                                                        <Box
                                                            sx={{
                                                                display:
                                                                    "flex",
                                                                flexWrap:
                                                                    "wrap",
                                                                gap:
                                                                    0.5
                                                            }}
                                                        >

                                                            {
                                                                selected.map(
                                                                    unitId => {

                                                                        const option =
                                                                            unitOptions.find(
                                                                                item =>
                                                                                    String(
                                                                                        getLookupId(
                                                                                            item
                                                                                        )
                                                                                    ) ===
                                                                                    String(
                                                                                        unitId
                                                                                    )
                                                                            );


                                                                        return (

                                                                            <Chip
                                                                                key={
                                                                                    String(
                                                                                        unitId
                                                                                    )
                                                                                }
                                                                                size="small"
                                                                                label={
                                                                                    getLookupLabel(
                                                                                        option
                                                                                    ) ||
                                                                                    String(
                                                                                        unitId
                                                                                    )
                                                                                }
                                                                            />

                                                                        );

                                                                    }
                                                                )
                                                            }

                                                        </Box>

                                                    );

                                                }
                                            }
                                        >

                                            {
                                                loadingUnits && (

                                                    <MenuItem disabled>

                                                        <Stack
                                                            direction="row"
                                                            spacing={1}
                                                            alignItems="center"
                                                        >

                                                            <CircularProgress
                                                                size={18}
                                                            />

                                                            <Typography>
                                                                Loading Units...
                                                            </Typography>

                                                        </Stack>

                                                    </MenuItem>

                                                )
                                            }


                                            {
                                                !loadingUnits &&
                                                unitOptions.length === 0 && (

                                                    <MenuItem disabled>

                                                        No active Units available

                                                    </MenuItem>

                                                )
                                            }


                                            {
                                                unitOptions.map(
                                                    item => (

                                                        <MenuItem
                                                            key={
                                                                String(
                                                                    item.id
                                                                )
                                                            }
                                                            value={
                                                                String(
                                                                    item.id
                                                                )
                                                            }
                                                        >

                                                         <MenuItem
    key={String(item.id)}
    value={String(item.id)}
>
    {item.label}
</MenuItem>

                                                        </MenuItem>

                                                    )
                                                )
                                            }

                                        </Select>


                                        <Typography
                                            variant="caption"
                                            color="text.secondary"
                                            sx={{
                                                mt:
                                                    0.75,
                                                px:
                                                    1.5
                                            }}
                                        >
                                            Select one or more units that this Service Type is allowed to use. There is no default unit.
                                        </Typography>

                                    </FormControl>

                                )
                            }


                            {/* ==================================================
                                CATEGORY INFO
                            ================================================== */}

                            {
                                selectedCategory && (

                                    <Card
                                        variant="outlined"
                                    >

                                        <CardContent>

                                            <Stack spacing={1}>

                                                <Typography
                                                    variant="body2"
                                                    color="text.secondary"
                                                >
                                                    Module
                                                </Typography>

                                                <Typography
                                                    fontWeight={700}
                                                >
                                                    {
                                                        moduleLabel
                                                    }
                                                </Typography>


                                                <Typography
                                                    variant="body2"
                                                    color="text.secondary"
                                                    sx={{
                                                        mt: 1
                                                    }}
                                                >
                                                    Category
                                                </Typography>

                                                <Typography
                                                    fontWeight={700}
                                                >
                                                    {
                                                        getLookupLabel(
                                                            selectedCategory
                                                        ) ||
                                                        selectedCategory?.category ||
                                                        selectedCategory?.key
                                                    }
                                                </Typography>


                                                {
                                                    isServiceType &&
                                                    parentLookup && (

                                                        <>

                                                            <Typography
                                                                variant="body2"
                                                                color="text.secondary"
                                                                sx={{
                                                                    mt: 1
                                                                }}
                                                            >
                                                                Service Category
                                                            </Typography>

                                                            <Typography
                                                                fontWeight={700}
                                                            >
                                                                {
                                                                    getLookupLabel(
                                                                        parentCategories.find(
                                                                            item =>
                                                                                String(
                                                                                    item?._id ??
                                                                                    item?.id ??
                                                                                    ""
                                                                                ) ===
                                                                                String(
                                                                                    parentLookup
                                                                                )
                                                                        )
                                                                    ) ||
                                                                    "Selected Service Category"
                                                                }
                                                            </Typography>

                                                        </>

                                                    )
                                                }


                                                {
                                                    isServiceType &&
                                                    selectedUnitLabels.length > 0 && (

                                                        <>

                                                            <Typography
                                                                variant="body2"
                                                                color="text.secondary"
                                                                sx={{
                                                                    mt: 1
                                                                }}
                                                            >
                                                                Allowed Units
                                                            </Typography>

                                                            <Stack
                                                                direction="row"
                                                                spacing={0.75}
                                                                flexWrap="wrap"
                                                                useFlexGap
                                                            >

                                                                {
                                                                    selectedUnitLabels.map(
                                                                        (
                                                                            label,
                                                                            index
                                                                        ) => (

                                                                            <Chip
                                                                                key={
                                                                                    `${label}-${index}`
                                                                                }
                                                                                size="small"
                                                                                label={
                                                                                    label
                                                                                }
                                                                            />

                                                                        )
                                                                    )
                                                                }

                                                            </Stack>

                                                        </>

                                                    )
                                                }


                                                <Chip
                                                    size="small"
                                                    label={`${Number(
                                                        selectedCategory.lookupCount || 0
                                                    )} existing value${
                                                        Number(
                                                            selectedCategory.lookupCount || 0
                                                        ) === 1
                                                            ? ""
                                                            : "s"
                                                    }`}
                                                    sx={{
                                                        width:
                                                            "fit-content",
                                                        mt:
                                                            1
                                                    }}
                                                />

                                            </Stack>

                                        </CardContent>

                                    </Card>

                                )
                            }


                            <Divider />


                            {/* ==================================================
                                VALUES HEADER
                            ================================================== */}

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
                                        Add one or more values to the selected category.
                                    </Typography>

                                </Box>


                                <Chip
                                    label={`${values.length} ${
                                        values.length === 1
                                            ? "value"
                                            : "values"
                                    }`}
                                />

                            </Stack>


                            {/* ==================================================
                                VALUES
                            ================================================== */}

                            <Stack spacing={2}>

                                {
                                    values.map(
                                        (
                                            item,
                                            index
                                        ) => (

                                            <Stack
                                                key={
                                                    index
                                                }
                                                direction={{
                                                    xs: "column",
                                                    md: "row"
                                                }}
                                                spacing={2}
                                                alignItems={{
                                                    xs: "stretch",
                                                    md: "center"
                                                }}
                                            >

                                                <TextField
                                                    label={`Value ${
                                                        index + 1
                                                    }`}
                                                    value={
                                                        item.value
                                                    }
                                                    onChange={
                                                        event =>
                                                            handleValueChange(
                                                                index,
                                                                "value",
                                                                event.target.value
                                                            )
                                                    }
                                                    required
                                                    fullWidth
                                                    disabled={
                                                        loading
                                                    }
                                                    placeholder={
                                                        isServiceType
                                                            ? "Example: Medical Consultation"
                                                            : "Example: Single"
                                                    }
                                                />


                                                <TextField
                                                    label="Code"
                                                    value={
                                                        item.code
                                                    }
                                                    onChange={
                                                        event =>
                                                            handleValueChange(
                                                                index,
                                                                "code",
                                                                event.target.value
                                                            )
                                                    }
                                                    fullWidth
                                                    disabled={
                                                        loading
                                                    }
                                                    placeholder={
                                                        isServiceType
                                                            ? "Example: MEDICAL_CONSULTATION"
                                                            : "Example: SINGLE"
                                                    }
                                                    helperText="Optional"
                                                />


                                                <IconButton
                                                    color="error"
                                                    disabled={
                                                        values.length === 1 ||
                                                        loading
                                                    }
                                                    onClick={() =>
                                                        handleRemoveValue(
                                                            index
                                                        )
                                                    }
                                                >
                                                    <Delete />
                                                </IconButton>

                                            </Stack>

                                        )
                                    )
                                }

                            </Stack>


                            {/* ==================================================
                                ADD
                            ================================================== */}

                            <Box>

                                <Button
                                    type="button"
                                    variant="outlined"
                                    startIcon={
                                        <Add />
                                    }
                                    onClick={
                                        handleAddValue
                                    }
                                    disabled={
                                        loading ||
                                        !module ||
                                        !category ||
                                        (
                                            isServiceType &&
                                            (
                                                !parentLookup ||
                                                allowedUnits.length === 0
                                            )
                                        )
                                    }
                                >
                                    Add Value
                                </Button>

                            </Box>


                            <Divider />


                            {/* ==================================================
                                ACTIVE
                            ================================================== */}

                            <FormControlLabel
                                control={
                                    <Switch
                                        checked={
                                            active
                                        }
                                        onChange={
                                            event =>
                                                setActive(
                                                    event.target.checked
                                                )
                                        }
                                        disabled={
                                            loading
                                        }
                                    />
                                }
                                label={
                                    active
                                        ? "Active"
                                        : "Inactive"
                                }
                            />


                            {/* ==================================================
                                ERROR
                            ================================================== */}

                            {
                                error && (

                                    <Card
                                        variant="outlined"
                                        sx={{
                                            borderColor:
                                                "error.light"
                                        }}
                                    >

                                        <CardContent>

                                            <Typography
                                                color="error"
                                                fontWeight={600}
                                            >
                                                {
                                                    error
                                                }
                                            </Typography>

                                        </CardContent>

                                    </Card>

                                )
                            }


                            {/* ==================================================
                                ACTIONS
                            ================================================== */}

                            <Stack
                                direction={{
                                    xs: "column",
                                    sm: "row"
                                }}
                                spacing={2}
                            >

                                <Button
                                    type="submit"
                                    variant="contained"
                                    disabled={
                                        loading ||
                                        loadingCategories ||
                                        loadingLookups ||
                                        loadingParentCategories ||
                                        loadingUnits ||
                                        !module ||
                                        !category ||
                                        !selectedCategory ||
                                        (
                                            isServiceType &&
                                            (
                                                !parentLookup ||
                                                allowedUnits.length === 0
                                            )
                                        ) ||
                                        values.some(
                                            item =>
                                                !String(
                                                    item?.value ||
                                                    ""
                                                ).trim()
                                        )
                                    }
                                >
                                    {
                                        loading
                                            ? "Creating..."
                                            : "Create Lookups"
                                    }
                                </Button>


                                <Button
                                    type="button"
                                    variant="outlined"
                                    disabled={
                                        loading
                                    }
                                    onClick={() =>
                                        navigate(
                                            "/lookups"
                                        )
                                    }
                                >
                                    Cancel
                                </Button>

                            </Stack>

                        </Stack>

                    </Box>

                </CardContent>

            </Card>

        </PageContainer>

    );

};


export default LookupCreatePage;