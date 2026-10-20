import {
    useEffect,
    useState
} from "react";

import {
    Link,
    useNavigate,
    useParams
} from "react-router-dom";

import {
    Box,
    Button,
    Card,
    CardContent,
    CircularProgress,
    FormControl,
    FormControlLabel,
    InputLabel,
    MenuItem,
    Select,
    Stack,
    Switch,
    TextField,
    Typography
} from "@mui/material";

import {
    ArrowBack
} from "@mui/icons-material";

import {
    useLookupById,
    useUpdateLookup
} from "../hooks/useLookups";

import {
    getLookupCategoriesByModuleService,
    getLookupsByModuleAndCategoryService
} from "../services/lookupService";


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
// RESPONSE NORMALIZER
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
// EDIT PAGE
// ==========================================================

const LookupEditPage = () => {

    const {
        id
    } = useParams();


    const navigate =
        useNavigate();


    // ======================================================
    // LOOKUP
    // ======================================================

    const {
        data,
        isLoading,
        isError,
        error
    } = useLookupById(id);


    // ======================================================
    // UPDATE
    // ======================================================

    const updateMutation =
        useUpdateLookup();


    // ======================================================
    // FORM
    // ======================================================

    const [
        formData,
        setFormData
    ] = useState({

        module: "",

        category: "",

        value: "",

        code: "",

        active: true,

        parentLookup: ""

    });


    const [
        categories,
        setCategories
    ] = useState([]);


    const [
        parentCategories,
        setParentCategories
    ] = useState([]);


    const [
        loadingCategories,
        setLoadingCategories
    ] = useState(false);


    const [
        loadingParentCategories,
        setLoadingParentCategories
    ] = useState(false);


    const [
        formError,
        setFormError
    ] = useState("");


    // ======================================================
    // SERVICE TYPE
    // ======================================================

    const isServiceType =
        formData.category === "ServiceType";


    // ======================================================
    // LOAD LOOKUP
    // ======================================================

    useEffect(() => {

        if (!data) {
            return;
        }


        const lookup =
            data?.data || data;


        setFormData({

            module:
                String(
                    lookup?.module || ""
                ).trim(),

            category:
                String(
                    lookup?.category || ""
                ).trim(),

            value:
                String(
                    lookup?.value || ""
                ).trim(),

            code:
                String(
                    lookup?.code || ""
                ).trim(),

            active:
                lookup?.active !== false,

            parentLookup:
                String(
                    lookup?.parentLookup?._id ||
                    lookup?.parentLookup ||
                    ""
                ).trim()

        });

    }, [data]);


    // ======================================================
    // LOAD CATEGORIES
    // ======================================================

    useEffect(() => {

        let cancelled = false;


        const loadCategories = async () => {

            if (!formData.module) {

                setCategories([]);

                return;
            }


            try {

                setLoadingCategories(true);

                setFormError("");


                const response =
                    await getLookupCategoriesByModuleService(
                        formData.module
                    );


                const rows =
                    extractArray(response);


                if (!cancelled) {

                    setCategories(rows);

                }

            }
            catch (categoryError) {

                console.error(
                    "Failed loading lookup categories:",
                    categoryError
                );


                if (!cancelled) {

                    setCategories([]);

                    setFormError(
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

                }

            }

        };


        loadCategories();


        return () => {

            cancelled = true;

        };

    }, [
        formData.module
    ]);


    // ======================================================
    // LOAD SERVICE CATEGORIES
    // ======================================================

    useEffect(() => {

        let cancelled = false;


        const loadParentCategories = async () => {

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
                    extractArray(response);


                if (!cancelled) {

                    setParentCategories(rows);

                }

            }
            catch (parentError) {

                console.error(
                    "Failed loading service categories:",
                    parentError
                );


                if (!cancelled) {

                    setParentCategories([]);

                    setFormError(
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

                    setLoadingParentCategories(false);

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
    // HANDLE CHANGE
    // ======================================================

    const handleChange = event => {

        const {
            name,
            value,
            checked,
            type
        } = event.target;


        setFormData(previous => ({

            ...previous,

            [name]:
                type === "checkbox"
                    ? checked
                    : value,

            ...(name === "category" &&
                value !== "ServiceType"
                ? {
                    parentLookup: ""
                }
                : {})

        }));


        setFormError("");

    };


    // ======================================================
    // SUBMIT
    // ======================================================

    const handleSubmit = async event => {

        event.preventDefault();

        setFormError("");


        const cleanModule =
            String(
                formData.module || ""
            ).trim();


        const cleanCategory =
            String(
                formData.category || ""
            ).trim();


        const cleanValue =
            String(
                formData.value || ""
            ).trim();


        const cleanCode =
            String(
                formData.code || ""
            ).trim();


        const cleanParentLookup =
            String(
                formData.parentLookup || ""
            ).trim();


        // MODULE

        if (!cleanModule) {

            setFormError(
                "Module is required."
            );

            return;
        }


        // CATEGORY

        if (!cleanCategory) {

            setFormError(
                "Category is required."
            );

            return;
        }


        // CATEGORY VALIDATION

        const normalizedCategory =
            cleanCategory.toLowerCase();


        const validCategory =
            categories.some(item => {

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
                    normalizedCategory
                );

            });


        if (
            !loadingCategories &&
            categories.length > 0 &&
            !validCategory
        ) {

            setFormError(
                "The selected category is not available for this module."
            );

            return;
        }


        // SERVICE TYPE PARENT

        if (
            cleanCategory === "ServiceType" &&
            !cleanParentLookup
        ) {

            setFormError(
                "Service Type must belong to a Service Category."
            );

            return;
        }


        // SERVICE CATEGORY PARENT VALIDATION

        if (
            cleanCategory === "ServiceType" &&
            parentCategories.length > 0
        ) {

            const validParent =
                parentCategories.some(item => {

                    const parentId =
                        String(
                            item?._id ||
                            item?.id ||
                            ""
                        ).trim();

                    return (
                        parentId ===
                        cleanParentLookup
                    );

                });


            if (!validParent) {

                setFormError(
                    "The selected Service Category is not available."
                );

                return;
            }

        }


        // VALUE

        if (!cleanValue) {

            setFormError(
                "Value is required."
            );

            return;
        }


        // UPDATE

        try {

            const updateData = {

                module:
                    cleanModule,

                category:
                    cleanCategory,

                value:
                    cleanValue,

                code:
                    cleanCode,

                active:
                    formData.active

            };


            if (cleanCategory === "ServiceType") {

                updateData.parentLookup =
                    cleanParentLookup;

            }
            else {

                updateData.parentLookup = null;

            }


            await updateMutation.mutateAsync({

                id,

                data:
                    updateData

            });


            // RETURN TO CATEGORY

            navigate(
                `/lookups/module/${encodeURIComponent(
                    cleanModule
                )}/category/${encodeURIComponent(
                    cleanCategory
                )}`
            );

        }
        catch (updateError) {

            console.error(
                "Update lookup error:",
                updateError
            );


            setFormError(
                updateError
                    ?.response
                    ?.data
                    ?.message ||
                updateError?.message ||
                "Failed to update lookup."
            );

        }

    };


    // ======================================================
    // LOADING
    // ======================================================

    if (isLoading) {

        return (

            <Stack sx={{ alignItems: "center", justifyContent: "center", py: 8 }}
            >

                <CircularProgress />

                <Typography
                    variant="body2"
                    color="text.secondary"
                    sx={{ mt: 2 }}
                >
                    Loading lookup...
                </Typography>

            </Stack>

        );

    }


    // ======================================================
    // ERROR
    // ======================================================

    if (isError) {

        return (

            <Box>

                <Typography
                    variant="h5"
                    fontWeight={700}
                    mb={2}
                >
                    Edit Lookup
                </Typography>


                <Card>

                    <CardContent>

                        <Typography
                            color="error"
                            fontWeight={600}
                            mb={2}
                        >
                            {
                                error
                                    ?.response
                                    ?.data
                                    ?.message ||
                                error?.message ||
                                "Failed to load lookup."
                            }
                        </Typography>


                        <Button
                            component={Link}
                            to="/lookups"
                            startIcon={<ArrowBack />}
                        >
                            Back to Lookups
                        </Button>

                    </CardContent>

                </Card>

            </Box>

        );

    }


    // ======================================================
    // RENDER
    // ======================================================

    return (

        <Box>

            {/* HEADER */}

            <Stack sx={{ alignItems: {
                    xs: "flex-start",
                    sm: "center"
                }, mb: 3 }}
                direction={{
                    xs: "column",
                    sm: "row"
                }}
                spacing={2}
            >

                <Button
                    component={Link}
                    to="/lookups"
                    startIcon={<ArrowBack />}
                    disabled={
                        updateMutation.isPending
                    }
                >
                    Back to Lookups
                </Button>


                <Box>

                    <Typography
                        variant="h4"
                        fontWeight={700}
                    >
                        Edit Lookup
                    </Typography>


                    <Typography
                        variant="body2"
                        color="text.secondary"
                    >
                        Update the lookup value, code, category, or status.
                    </Typography>

                </Box>

            </Stack>


            {/* FORM */}

            <Card>

                <CardContent>

                    <Box
                        component="form"
                        onSubmit={handleSubmit}
                    >

                        <Stack spacing={3}>

                            {/* MODULE */}

                            <FormControl
                                fullWidth
                                required
                            >

                                <InputLabel>
                                    Module
                                </InputLabel>


                                <Select
                                    name="module"
                                    value={
                                        formData.module
                                    }
                                    label="Module"
                                    onChange={
                                        handleChange
                                    }
                                    disabled={
                                        updateMutation.isPending
                                    }
                                >

                                    <MenuItem value="">
                                        <em>
                                            Select Module
                                        </em>
                                    </MenuItem>


                                    {MODULE_OPTIONS.map(item => (

                                        <MenuItem
                                            key={item.value}
                                            value={item.value}
                                        >
                                            {item.label}
                                        </MenuItem>

                                    ))}

                                </Select>

                            </FormControl>


                            {/* CATEGORY */}

                            <FormControl
                                fullWidth
                                required
                                disabled={
                                    !formData.module ||
                                    loadingCategories ||
                                    updateMutation.isPending
                                }
                            >

                                <InputLabel>
                                    Category
                                </InputLabel>


                                <Select
                                    name="category"
                                    value={
                                        formData.category
                                    }
                                    label="Category"
                                    onChange={
                                        handleChange
                                    }
                                >

                                    <MenuItem value="">
                                        <em>
                                            {
                                                loadingCategories
                                                    ? "Loading categories..."
                                                    : "Select Category"
                                            }
                                        </em>
                                    </MenuItem>


                                    {categories.map(item => {

                                        const itemCategory =
                                            String(
                                                item?.category ||
                                                item?.key ||
                                                ""
                                            ).trim();


                                        if (!itemCategory) {
                                            return null;
                                        }


                                        return (

                                            <MenuItem
                                                key={itemCategory}
                                                value={itemCategory}
                                            >
                                                {
                                                    item?.label ||
                                                    itemCategory
                                                }
                                            </MenuItem>

                                        );

                                    })}

                                </Select>

                            </FormControl>


                            {/* SERVICE CATEGORY */}

                            {isServiceType && (

                                <FormControl
                                    fullWidth
                                    required
                                    disabled={
                                        loadingParentCategories ||
                                        updateMutation.isPending
                                    }
                                >

                                    <InputLabel>
                                        Service Category
                                    </InputLabel>


                                    <Select
                                        name="parentLookup"
                                        value={
                                            formData.parentLookup
                                        }
                                        label="Service Category"
                                        onChange={
                                            handleChange
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


                                        {parentCategories.map(item => {

                                            const parentId =
                                                String(
                                                    item?._id ||
                                                    item?.id ||
                                                    ""
                                                ).trim();


                                            const parentLabel =
                                                String(
                                                    item?.value ||
                                                    item?.label ||
                                                    item?.name ||
                                                    ""
                                                ).trim();


                                            if (!parentId) {
                                                return null;
                                            }


                                            return (

                                                <MenuItem
                                                    key={parentId}
                                                    value={parentId}
                                                >
                                                    {
                                                        parentLabel ||
                                                        parentId
                                                    }
                                                </MenuItem>

                                            );

                                        })}

                                    </Select>

                                </FormControl>

                            )}


                            {/* VALUE */}

                            <TextField
                                label="Value"
                                name="value"
                                value={
                                    formData.value
                                }
                                onChange={
                                    handleChange
                                }
                                required
                                fullWidth
                                disabled={
                                    updateMutation.isPending
                                }
                                placeholder="Example: Married"
                                helperText="The value displayed in dropdowns."
                            />


                            {/* CODE */}

                            <TextField
                                label="Code"
                                name="code"
                                value={
                                    formData.code
                                }
                                onChange={
                                    handleChange
                                }
                                fullWidth
                                disabled={
                                    updateMutation.isPending
                                }
                                placeholder="Example: MARRIED"
                                helperText="Optional internal code."
                            />


                            {/* ACTIVE */}

                            <FormControlLabel
                                control={
                                    <Switch
                                        name="active"
                                        checked={
                                            formData.active
                                        }
                                        onChange={
                                            handleChange
                                        }
                                        disabled={
                                            updateMutation.isPending
                                        }
                                    />
                                }
                                label={
                                    formData.active
                                        ? "Active"
                                        : "Inactive"
                                }
                            />


                            {/* ERROR */}

                            {formError && (

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
                                            {formError}
                                        </Typography>

                                    </CardContent>

                                </Card>

                            )}


                            {/* ACTIONS */}

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
                                        updateMutation.isPending ||
                                        loadingCategories ||
                                        loadingParentCategories ||
                                        (
                                            isServiceType &&
                                            !formData.parentLookup
                                        )
                                    }
                                >
                                    {
                                        updateMutation.isPending
                                            ? "Updating..."
                                            : "Update Lookup"
                                    }
                                </Button>


                                <Button
                                    component={Link}
                                    to={
                                        formData.module &&
                                        formData.category
                                            ? `/lookups/module/${encodeURIComponent(
                                                formData.module
                                            )}/category/${encodeURIComponent(
                                                formData.category
                                            )}`
                                            : "/lookups"
                                    }
                                    variant="outlined"
                                    disabled={
                                        updateMutation.isPending
                                    }
                                >
                                    Cancel
                                </Button>

                            </Stack>

                        </Stack>

                    </Box>

                </CardContent>

            </Card>

        </Box>

    );

};


export default LookupEditPage;