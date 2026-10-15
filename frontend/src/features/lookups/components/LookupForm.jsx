import {
    useEffect,
    useState
} from "react";

import {
    Box,
    Button,
    FormControl,
    FormControlLabel,
    InputLabel,
    MenuItem,
    Select,
    Stack,
    Switch,
    TextField
} from "@mui/material";

import {
    Save
} from "@mui/icons-material";

import {
    getLookupCategoriesByModuleService,
    normalizeModule
} from "../services/lookupService";


// ==========================================================
// MODULE OPTIONS
// ==========================================================

const MODULE_OPTIONS = [

    {
        value: "Beneficiary",
        label: "Beneficiaries"
    },

    {
        value: "Enterprise",
        label: "Enterprises"
    },

    {
        value: "EnterpriseMember",
        label: "Enterprise Members"
    },

    {
        value: "Program",
        label: "Programs"
    },

    {
        value: "Project",
        label: "Projects"
    },

    {
        value: "Activity",
        label: "Activities"
    },

    {
        value: "ActivityRun",
        label: "Activity Runs"
    },

    {
        value: "Attendance",
        label: "Attendance"
    },

    {
        value: "Enrollment",
        label: "Enrollments"
    },

    {
        value: "ServiceDelivery",
        label: "Service Delivery"
    },

    {
        value: "User",
        label: "Users"
    },

    {
        value: "Donor",
        label: "Donors"
    },

    {
        value: "Donation",
        label: "Donations"
    }

];


// ==========================================================
// DEFAULT FORM
// ==========================================================

const DEFAULT_FORM = {

    module: "",

    category: "",

    value: "",

    code: "",

    active: true

};


// ==========================================================
// CATEGORY HELPERS
// ==========================================================

const getCategoryValue = (
    category
) => {

    if (
        typeof category === "string"
    ) {

        return category;

    }

    return (
        category?.category ||
        category?.key ||
        category?.name ||
        ""
    );

};


const getCategoryLabel = (
    category
) => {

    if (
        typeof category === "string"
    ) {

        return category;

    }

    return (
        category?.label ||
        category?.name ||
        category?.category ||
        category?.key ||
        ""
    );

};


// ==========================================================
// COMPONENT
// ==========================================================

const LookupForm = ({
    initialData = null,
    onSubmit,
    loading = false
}) => {

    const [
        form,
        setForm
    ] = useState({
        ...DEFAULT_FORM
    });


    const [
        categories,
        setCategories
    ] = useState([]);


    const [
        categoriesLoading,
        setCategoriesLoading
    ] = useState(false);


    const [
        categoriesError,
        setCategoriesError
    ] = useState("");


    // ======================================================
    // INITIAL DATA
    // ======================================================

    useEffect(() => {

        if (!initialData) {

            setForm({
                ...DEFAULT_FORM
            });

            return;

        }


        setForm({

            module:
                normalizeModule(
                    initialData.module
                ),

            category:
                initialData.category ||
                "",

            value:
                initialData.value ||
                "",

            code:
                initialData.code ||
                "",

            active:
                initialData.active !== false

        });

    }, [
        initialData
    ]);


    // ======================================================
    // LOAD CATEGORIES
    // ======================================================

    useEffect(() => {

        if (!form.module) {

            setCategories([]);

            setCategoriesError("");

            return;

        }


        let cancelled = false;


        const loadCategories = async () => {

            try {

                setCategoriesLoading(true);

                setCategoriesError("");


                const module =
                    normalizeModule(
                        form.module
                    );


                const response =
                    await getLookupCategoriesByModuleService(
                        module
                    );


                if (
                    cancelled
                ) {

                    return;

                }


                const data =
                    response?.data ??
                    response ??
                    [];


                setCategories(
                    Array.isArray(data)
                        ? data
                        : []
                );

            }

            catch (error) {

                if (
                    cancelled
                ) {

                    return;

                }


                console.error(
                    "Failed to load lookup categories:",
                    error
                );


                setCategories([]);

                setCategoriesError(
                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to load categories."
                );

            }

            finally {

                if (
                    !cancelled
                ) {

                    setCategoriesLoading(false);

                }

            }

        };


        loadCategories();


        return () => {

            cancelled = true;

        };

    }, [
        form.module
    ]);


    // ======================================================
    // CHANGE
    // ======================================================

    const handleChange = (
        event
    ) => {

        const {
            name,
            value,
            checked,
            type
        } = event.target;


        if (
            name === "module"
        ) {

            const module =
                normalizeModule(
                    value
                );


            setForm(
                previous => ({

                    ...previous,

                    module,

                    category: ""

                })
            );

            return;

        }


        setForm(
            previous => ({

                ...previous,

                [name]:
                    type === "checkbox"
                        ? checked
                        : value

            })
        );

    };


    // ======================================================
    // SUBMIT
    // ======================================================

    const handleSubmit = (
        event
    ) => {

        event.preventDefault();


        const module =
            normalizeModule(
                form.module
            );


        const category =
            String(
                form.category || ""
            ).trim();


        const value =
            String(
                form.value || ""
            ).trim();


        const code =
            String(
                form.code || ""
            ).trim();


        if (!module) {

            return;

        }


        if (!category) {

            return;

        }


        if (!value) {

            return;

        }


        const payload = {

            module,

            category,

            value,

            code,

            active:
                form.active

        };


        onSubmit(
            payload
        );

    };


    // ======================================================
    // RENDER
    // ======================================================

    return (

        <Box
            component="form"
            onSubmit={
                handleSubmit
            }
        >

            <Stack spacing={2}>

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
                            form.module
                        }
                        label="Module"
                        onChange={
                            handleChange
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


                {/* CATEGORY */}

                <FormControl
                    fullWidth
                    required
                    disabled={
                        !form.module ||
                        categoriesLoading
                    }
                    error={
                        Boolean(
                            categoriesError
                        )
                    }
                >

                    <InputLabel>
                        Category
                    </InputLabel>


                    <Select
                        name="category"
                        value={
                            form.category
                        }
                        label="Category"
                        onChange={
                            handleChange
                        }
                    >

                        <MenuItem value="">
                            <em>
                                {
                                    categoriesLoading
                                        ? "Loading categories..."
                                        : "Select Category"
                                }
                            </em>
                        </MenuItem>


                        {
                            categories.map(
                                category => {

                                    const value =
                                        getCategoryValue(
                                            category
                                        );


                                    const label =
                                        getCategoryLabel(
                                            category
                                        );


                                    if (!value) {

                                        return null;

                                    }


                                    return (

                                        <MenuItem
                                            key={
                                                value
                                            }
                                            value={
                                                value
                                            }
                                        >
                                            {label}
                                        </MenuItem>

                                    );

                                }
                            )
                        }

                    </Select>


                    {
                        categoriesError && (

                            <Box
                                sx={{
                                    color:
                                        "error.main",
                                    fontSize: 12,
                                    mt: 0.5,
                                    px: 1
                                }}
                            >
                                {
                                    categoriesError
                                }
                            </Box>

                        )
                    }

                </FormControl>


                {/* VALUE */}

                <TextField
                    fullWidth
                    required
                    label="Value"
                    name="value"
                    value={
                        form.value
                    }
                    onChange={
                        handleChange
                    }
                    helperText={
                        "Example: Food"
                    }
                />


                {/* CODE */}

                <TextField
                    fullWidth
                    label="Code"
                    name="code"
                    value={
                        form.code
                    }
                    onChange={
                        handleChange
                    }
                    helperText={
                        "Optional internal code"
                    }
                />


                {/* ACTIVE */}

                <FormControlLabel
                    control={
                        <Switch
                            name="active"
                            checked={
                                form.active
                            }
                            onChange={
                                handleChange
                            }
                        />
                    }
                    label={
                        form.active
                            ? "Active"
                            : "Inactive"
                    }
                />


                {/* SAVE */}

                <Stack
                    direction="row"
                    justifyContent="flex-end"
                >

                    <Button
                        type="submit"
                        variant="contained"
                        startIcon={
                            <Save />
                        }
                        disabled={
                            loading ||
                            categoriesLoading ||
                            !form.module ||
                            !form.category ||
                            !form.value.trim()
                        }
                    >

                        {
                            loading
                                ? "Saving..."
                                : "Save Lookup"
                        }

                    </Button>

                </Stack>

            </Stack>

        </Box>

    );

};


export default LookupForm;