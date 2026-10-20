import {
    Link
} from "react-router-dom";

import {
    Box,
    Button,
    Card,
    CardContent,
    Chip,
    CircularProgress,
    Divider,
    Stack,
    Typography
} from "@mui/material";

import {
    Add,
    Settings
} from "@mui/icons-material";

import {
    useLookups
} from "../hooks/useLookups";


// ==========================================================
// LOOKUP LIST PAGE
// ==========================================================

const LookupListPage = () => {

    const {
        data,
        isLoading,
        isError,
        error
    } = useLookups();


    // ======================================================
    // NORMALIZE RESPONSE
    // ======================================================

    const lookups =
        Array.isArray(data?.data)
            ? data.data
            : Array.isArray(data)
                ? data
                : Array.isArray(data?.data?.data)
                    ? data.data.data
                    : [];


    // ======================================================
    // GROUP
    //
    // MODULE
    //   CATEGORY
    //      VALUES
    // ======================================================

    const modules =
        lookups.reduce(
            (result, lookup) => {

                const module =
                    String(
                        lookup?.module || "Other"
                    ).trim() || "Other";

                const category =
                    String(
                        lookup?.category || "Other"
                    ).trim() || "Other";


                if (!result[module]) {
                    result[module] = {};
                }


                if (!result[module][category]) {
                    result[module][category] = [];
                }


                result[module][category].push(
                    lookup
                );


                return result;

            },
            {}
        );


    const moduleList =
        Object.entries(modules);


    // ======================================================
    // SUMMARY
    // ======================================================

    const activeCount =
        lookups.filter(
            item =>
                item?.active !== false
        ).length;


    const inactiveCount =
        lookups.length -
        activeCount;


    const categoryCount =
        moduleList.reduce(
            (total, [, categories]) =>
                total +
                Object.keys(categories).length,
            0
        );


    // ======================================================
    // LOADING
    // ======================================================

    if (isLoading) {

        return (
            <Box>

                <Stack sx={{ alignItems: "center", justifyContent: "center", py: 8 }}
                >

                    <CircularProgress />

                    <Typography
                        variant="body2"
                        sx={{
                            color: "text.secondary",
                            mt: 2
                        }}>
                        Loading lookup values...
                    </Typography>

                </Stack>

            </Box>
        );

    }


    // ======================================================
    // ERROR
    // ======================================================

    if (isError) {

        return (
            <Box>

                <Stack sx={{ justifyContent: "space-between", alignItems: {
                        xs: "flex-start",
                        sm: "center"
                    }, mb: 3 }}
                    direction={{
                        xs: "column",
                        sm: "row"
                    }}
                    spacing={2}
                >

                    <Box>

                        <Typography
                            variant="h4"
                            sx={{
                                fontWeight: 700
                            }}
                        >
                            Lookup Management
                        </Typography>

                        <Typography
                            variant="body2"
                            sx={{
                                color: "text.secondary"
                            }}
                        >
                            Manage reusable lookup values by module and category.
                        </Typography>

                    </Box>


                    <Button
                        component={Link}
                        to="/lookups/create"
                        variant="contained"
                        startIcon={<Add />}
                    >
                        Add Lookup
                    </Button>

                </Stack>

                <Card>

                    <CardContent>

                        <Typography
                            color="error"
                            sx={{
                                fontWeight: 600
                            }}
                        >
                            Failed to load lookup values.
                        </Typography>


                        <Typography
                            variant="body2"
                            sx={{
                                color: "text.secondary",
                                mt: 1
                            }}>
                            {
                                error?.response?.data?.message ||
                                error?.message ||
                                "An unexpected error occurred."
                            }
                        </Typography>

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

            {/* ==================================================
                HEADER
            ================================================== */}

            <Stack sx={{ justifyContent: "space-between", alignItems: {
                    xs: "flex-start",
                    sm: "center"
                }, mb: 3 }}
                direction={{
                    xs: "column",
                    sm: "row"
                }}
                spacing={2}
            >

                <Box>

                    <Typography
                        variant="h4"
                        sx={{
                            fontWeight: 700
                        }}
                    >
                        Lookup Management
                    </Typography>


                    <Typography
                        variant="body2"
                        sx={{
                            color: "text.secondary"
                        }}
                    >
                        Manage reusable dropdown values by module and category.
                    </Typography>

                </Box>


                <Button
                    component={Link}
                    to="/lookups/create"
                    variant="contained"
                    startIcon={<Add />}
                >
                    Add Lookup
                </Button>

            </Stack>

            {/* ==================================================
                SUMMARY
            ================================================== */}

            <Stack sx={{ mb: 3 }}
                direction={{
                    xs: "column",
                    sm: "row"
                }}
                spacing={2}
            >

                <Card sx={{ flex: 1 }}>
                    <CardContent>

                        <Typography
                            variant="body2"
                            sx={{
                                color: "text.secondary"
                            }}
                        >
                            Modules
                        </Typography>

                        <Typography
                            variant="h4"
                            sx={{
                                fontWeight: 700
                            }}
                        >
                            {moduleList.length}
                        </Typography>

                    </CardContent>
                </Card>


                <Card sx={{ flex: 1 }}>
                    <CardContent>

                        <Typography
                            variant="body2"
                            sx={{
                                color: "text.secondary"
                            }}
                        >
                            Categories
                        </Typography>

                        <Typography
                            variant="h4"
                            sx={{
                                fontWeight: 700
                            }}
                        >
                            {categoryCount}
                        </Typography>

                    </CardContent>
                </Card>


                <Card sx={{ flex: 1 }}>
                    <CardContent>

                        <Typography
                            variant="body2"
                            sx={{
                                color: "text.secondary"
                            }}
                        >
                            Total Values
                        </Typography>

                        <Typography
                            variant="h4"
                            sx={{
                                fontWeight: 700
                            }}
                        >
                            {lookups.length}
                        </Typography>

                    </CardContent>
                </Card>


                <Card sx={{ flex: 1 }}>
                    <CardContent>

                        <Typography
                            variant="body2"
                            sx={{
                                color: "text.secondary"
                            }}
                        >
                            Active Values
                        </Typography>

                        <Typography
                            variant="h4"
                            sx={{
                                fontWeight: 700,
                                color: "success.main"
                            }}>
                            {activeCount}
                        </Typography>


                        {inactiveCount > 0 && (

                            <Typography
                                variant="body2"
                                sx={{
                                    color: "text.secondary"
                                }}
                            >
                                {inactiveCount} inactive
                            </Typography>

                        )}

                    </CardContent>
                </Card>

            </Stack>

            {/* ==================================================
                EMPTY
            ================================================== */}

            {moduleList.length === 0 ? (

                <Card>

                    <CardContent>

                        <Stack sx={{ alignItems: "center", py: 6 }}
                            spacing={1}
                        >

                            <Typography
                                variant="h6"
                                sx={{
                                    fontWeight: 600
                                }}
                            >
                                No lookup values found
                            </Typography>


                            <Typography
                                variant="body2"
                                sx={{
                                    color: "text.secondary"
                                }}
                            >
                                Create your first lookup value.
                            </Typography>


                            <Button
                                component={Link}
                                to="/lookups/create"
                                variant="contained"
                                startIcon={<Add />}
                                sx={{ mt: 2 }}
                            >
                                Create Lookup
                            </Button>

                        </Stack>

                    </CardContent>

                </Card>

            ) : (

                /* ==================================================
                   MODULES
                ================================================== */

                <Stack spacing={3}>

                    {moduleList.map(
                        ([module, categories]) => {

                            const categoryEntries =
                                Object.entries(categories);


                            const moduleValues =
                                categoryEntries.reduce(
                                    (total, [, values]) =>
                                        total + values.length,
                                    0
                                );


                            const moduleActive =
                                categoryEntries.reduce(
                                    (total, [, values]) =>
                                        total +
                                        values.filter(
                                            item =>
                                                item?.active !== false
                                        ).length,
                                    0
                                );


                            const moduleInactive =
                                moduleValues -
                                moduleActive;


                            return (
                                <Card
                                    key={module}
                                >

                                    {/* MODULE HEADER */}

                                    <CardContent>

                                        <Stack sx={{ justifyContent: "space-between", alignItems: {
                                                xs: "flex-start",
                                                sm: "center"
                                            } }}
                                            direction={{
                                                xs: "column",
                                                sm: "row"
                                            }}
                                            spacing={2}
                                        >

                                            <Box>

                                                <Typography
                                                    variant="h6"
                                                    sx={{
                                                        fontWeight: 700,

                                                        textTransform:
                                                            "capitalize"
                                                    }}>
                                                    {module}
                                                </Typography>


                                                <Typography
                                                    variant="body2"
                                                    sx={{
                                                        color: "text.secondary"
                                                    }}
                                                >
                                                    Lookup values used by the{" "}
                                                    {module} module.
                                                </Typography>

                                            </Box>


                                            <Stack sx={{ flexWrap: "wrap" }}
                                                direction="row"
                                                spacing={1}
                                                useFlexGap
                                            >

                                                <Chip
                                                    size="small"
                                                    label={`${categoryEntries.length} ${
                                                        categoryEntries.length === 1
                                                            ? "category"
                                                            : "categories"
                                                    }`}
                                                />


                                                <Chip
                                                    size="small"
                                                    color="success"
                                                    label={`${moduleActive} active`}
                                                />


                                                {moduleInactive > 0 && (

                                                    <Chip
                                                        size="small"
                                                        variant="outlined"
                                                        label={`${moduleInactive} inactive`}
                                                    />

                                                )}


                                                <Chip
                                                    size="small"
                                                    variant="outlined"
                                                    label={`${moduleValues} values`}
                                                />

                                            </Stack>

                                        </Stack>

                                    </CardContent>

                                    <Divider />

                                    {/* CATEGORY TABLE */}

                                    <CardContent>

                                        <Box
                                            sx={{
                                                width: "100%",
                                                overflowX: "auto"
                                            }}
                                        >

                                            <table
                                                style={{
                                                    width: "100%",
                                                    borderCollapse:
                                                        "collapse"
                                                }}
                                            >

                                                <thead>

                                                    <tr>

                                                        <th
                                                            style={{
                                                                textAlign:
                                                                    "left",
                                                                padding:
                                                                    "14px"
                                                            }}
                                                        >
                                                            Category
                                                        </th>


                                                        <th
                                                            style={{
                                                                textAlign:
                                                                    "left",
                                                                padding:
                                                                    "14px"
                                                            }}
                                                        >
                                                            Total
                                                        </th>


                                                        <th
                                                            style={{
                                                                textAlign:
                                                                    "left",
                                                                padding:
                                                                    "14px"
                                                            }}
                                                        >
                                                            Active
                                                        </th>


                                                        <th
                                                            style={{
                                                                textAlign:
                                                                    "right",
                                                                padding:
                                                                    "14px"
                                                            }}
                                                        >
                                                            Actions
                                                        </th>

                                                    </tr>

                                                </thead>


                                                <tbody>

                                                    {categoryEntries.map(
                                                        ([category, values]) => {

                                                            const active =
                                                                values.filter(
                                                                    item =>
                                                                        item?.active !== false
                                                                ).length;


                                                            const inactive =
                                                                values.length -
                                                                active;


                                                            return (

                                                                <tr
                                                                    key={`${module}-${category}`}
                                                                >

                                                                    <td
                                                                        style={{
                                                                            padding:
                                                                                "14px",
                                                                            fontWeight:
                                                                                600,
                                                                            borderTop:
                                                                                "1px solid #eee"
                                                                        }}
                                                                    >
                                                                        {category}
                                                                    </td>


                                                                    <td
                                                                        style={{
                                                                            padding:
                                                                                "14px",
                                                                            borderTop:
                                                                                "1px solid #eee"
                                                                        }}
                                                                    >
                                                                        {values.length}
                                                                    </td>


                                                                    <td
                                                                        style={{
                                                                            padding:
                                                                                "14px",
                                                                            borderTop:
                                                                                "1px solid #eee"
                                                                        }}
                                                                    >

                                                                        <Stack sx={{ alignItems: "center" }}
                                                                            direction="row"
                                                                            spacing={1}
                                                                        >

                                                                            <Chip
                                                                                size="small"
                                                                                color="success"
                                                                                label={active}
                                                                            />


                                                                            {inactive > 0 && (

                                                                                <Chip
                                                                                    size="small"
                                                                                    variant="outlined"
                                                                                    label={`${inactive} inactive`}
                                                                                />

                                                                            )}

                                                                        </Stack>

                                                                    </td>


                                                                    <td
                                                                        style={{
                                                                            padding:
                                                                                "14px",
                                                                            textAlign:
                                                                                "right",
                                                                            borderTop:
                                                                                "1px solid #eee"
                                                                        }}
                                                                    >

                                                                        <Button
                                                                            component={Link}
                                                                            to={`/lookups/module/${encodeURIComponent(
                                                                                module
                                                                            )}/category/${encodeURIComponent(
                                                                                category
                                                                            )}`}
                                                                            variant="outlined"
                                                                            size="small"
                                                                            startIcon={
                                                                                <Settings />
                                                                            }
                                                                        >
                                                                            Manage
                                                                        </Button>

                                                                    </td>

                                                                </tr>

                                                            );

                                                        }
                                                    )}

                                                </tbody>

                                            </table>

                                        </Box>

                                    </CardContent>

                                </Card>
                            );

                        }
                    )}

                </Stack>

            )}

        </Box>
    );

};


export default LookupListPage;