import {
    useEffect,
    useState
} from "react";

import {
    Link
} from "react-router-dom";

import {
    Box,
    Button,
    Card,
    CardContent,
    CircularProgress,
    Stack,
    Typography
} from "@mui/material";

import {
    Add
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
// RESPONSE HELPER
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
// CATEGORY HELPERS
// ==========================================================

const getCategoryName = (
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


const getCategoryCount = (
    category
) => {

    return Number(
        category?.lookupCount ??
        category?.count ??
        0
    );

};


// ==========================================================
// PAGE
// ==========================================================

const LookupManagementPage = () => {

    const [
        selectedModule,
        setSelectedModule
    ] = useState(
        "Beneficiary"
    );


    const [
        categories,
        setCategories
    ] = useState([]);


    const [
        loading,
        setLoading
    ] = useState(false);


    const [
        error,
        setError
    ] = useState("");


    // ======================================================
    // LOAD CATEGORIES
    // ======================================================

    useEffect(() => {

        let cancelled = false;


        const loadCategories = async () => {

            const module =
                normalizeModule(
                    selectedModule
                );


            if (!module) {

                setCategories([]);

                return;

            }


            try {

                setLoading(true);

                setError("");


                const response =
                    await getLookupCategoriesByModuleService(
                        module
                    );


                const rows =
                    extractArray(
                        response
                    );


                if (
                    !cancelled
                ) {

                    setCategories(
                        rows
                    );

                }

            }

            catch (err) {

                console.error(
                    "Failed to load lookup categories:",
                    err
                );


                if (
                    !cancelled
                ) {

                    setCategories([]);

                    setError(
                        err?.response?.data?.message ||
                        err?.message ||
                        "Failed to load lookup categories."
                    );

                }

            }

            finally {

                if (
                    !cancelled
                ) {

                    setLoading(false);

                }

            }

        };


        loadCategories();


        return () => {

            cancelled = true;

        };

    }, [
        selectedModule
    ]);


    // ======================================================
    // MODULE LABEL
    // ======================================================

    const moduleLabel =
        MODULE_OPTIONS.find(
            item =>
                item.value ===
                selectedModule
        )?.label ||
        selectedModule;


    // ======================================================
    // CATEGORY URL
    // ======================================================

    const getCategoryUrl = (
        category
    ) => {

        const module =
            normalizeModule(
                selectedModule
            );


        const categoryName =
            getCategoryName(
                category
            );


        return (
            `/lookups/module/${encodeURIComponent(module)}` +
            `/category/${encodeURIComponent(categoryName)}`
        );

    };


    // ======================================================
    // RENDER
    // ======================================================

    return (

        <Box>

            {/* ==================================================
                HEADER
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
                spacing={2}
                mb={3}
            >

                <Box>

                    <Typography
                        variant="h4"
                        fontWeight={700}
                    >
                        Lookup Management
                    </Typography>


                    <Typography
                        variant="body2"
                        color="text.secondary"
                    >
                        Manage reusable lookup values by module
                        and category.
                    </Typography>

                </Box>


                <Button
                    component={Link}
                    to="/lookups/create"
                    variant="contained"
                    startIcon={
                        <Add />
                    }
                >
                    Add Lookup
                </Button>

            </Stack>


            {/* ==================================================
                MODULE SELECTOR
            ================================================== */}

            <Card
                sx={{
                    mb: 3
                }}
            >

                <CardContent>

                    <Typography
                        variant="h6"
                        fontWeight={700}
                        mb={2}
                    >
                        Module
                    </Typography>


                    <Stack
                        direction="row"
                        spacing={1}
                        flexWrap="wrap"
                        useFlexGap
                    >

                        {
                            MODULE_OPTIONS.map(
                                module => (

                                    <Button
                                        key={
                                            module.value
                                        }
                                        variant={
                                            selectedModule ===
                                            module.value
                                                ? "contained"
                                                : "outlined"
                                        }
                                        onClick={() => {

                                            setSelectedModule(
                                                module.value
                                            );

                                        }}
                                    >
                                        {
                                            module.label
                                        }
                                    </Button>

                                )
                            )
                        }

                    </Stack>

                </CardContent>

            </Card>


            {/* ==================================================
                CATEGORY SECTION
            ================================================== */}

            <Card>

                <CardContent>

                    <Typography
                        variant="h6"
                        fontWeight={700}
                    >
                        {moduleLabel} Lookup Categories
                    </Typography>


                    <Typography
                        variant="body2"
                        color="text.secondary"
                        mb={3}
                    >
                        Select a category to manage its lookup
                        values.
                    </Typography>


                    {/* ==================================================
                        LOADING
                    ================================================== */}

                    {
                        loading && (

                            <Stack
                                alignItems="center"
                                py={6}
                            >

                                <CircularProgress />

                            </Stack>

                        )
                    }


                    {/* ==================================================
                        ERROR
                    ================================================== */}

                    {
                        !loading &&
                        error && (

                            <Typography
                                color="error"
                                fontWeight={600}
                            >
                                {error}
                            </Typography>

                        )
                    }


                    {/* ==================================================
                        EMPTY
                    ================================================== */}

                    {
                        !loading &&
                        !error &&
                        categories.length === 0 && (

                            <Stack
                                alignItems="center"
                                py={5}
                                spacing={1}
                            >

                                <Typography
                                    fontWeight={600}
                                >
                                    No lookup categories configured
                                </Typography>


                                <Typography
                                    variant="body2"
                                    color="text.secondary"
                                >
                                    There are currently no lookup
                                    categories available for this module.
                                </Typography>

                            </Stack>

                        )
                    }


                    {/* ==================================================
                        CATEGORY LIST
                    ================================================== */}

                    {
                        !loading &&
                        !error &&
                        categories.length > 0 && (

                            <Stack spacing={2}>

                                {
                                    categories.map(
                                        (
                                            category,
                                            index
                                        ) => {

                                            const name =
                                                getCategoryName(
                                                    category
                                                );


                                            const label =
                                                getCategoryLabel(
                                                    category
                                                );


                                            const count =
                                                getCategoryCount(
                                                    category
                                                );


                                            if (!name) {

                                                return null;

                                            }


                                            return (

                                                <Card
                                                    key={
                                                        `${selectedModule}-${name}-${index}`
                                                    }
                                                    variant="outlined"
                                                >

                                                    <CardContent>

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
                                                                    fontWeight={700}
                                                                >
                                                                    {label}
                                                                </Typography>


                                                                <Typography
                                                                    variant="body2"
                                                                    color="text.secondary"
                                                                >
                                                                    {count}{" "}
                                                                    {count === 1
                                                                        ? "value"
                                                                        : "values"}
                                                                </Typography>

                                                            </Box>


                                                            <Button
                                                                component={Link}
                                                                to={
                                                                    getCategoryUrl(
                                                                        category
                                                                    )
                                                                }
                                                                variant="outlined"
                                                            >
                                                                Manage
                                                            </Button>

                                                        </Stack>

                                                    </CardContent>

                                                </Card>

                                            );

                                        }
                                    )
                                }

                            </Stack>

                        )
                    }

                </CardContent>

            </Card>

        </Box>

    );

};


export default LookupManagementPage;