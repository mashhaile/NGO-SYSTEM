import {
    useEffect,
    useState
} from "react";

import {
    Box,
    Button,
    Card,
    CardContent,
    CircularProgress,
    FormControl,
    InputLabel,
    MenuItem,
    Select,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Typography
} from "@mui/material";

import {
    Add,
    Delete,
    Edit
} from "@mui/icons-material";

import {
    useNavigate
} from "react-router-dom";

import {
    toast
} from "react-toastify";


import {
    getCustomFieldsService,
    deleteCustomFieldService
} from "../services/customFieldService";

import {
    PageContainer,
    PageHeader
} from "../../../components/ui";


// ==========================================================
// MODULES
// ==========================================================

const modules = [
    "Beneficiary",
    "Donor",
    "Program",
    "ServiceDelivery",
    "User"
];


// ==========================================================
// PAGE
// ==========================================================

const CustomFieldListPage = () => {

    const navigate = useNavigate();


    const [module, setModule] =
        useState("Beneficiary");


    const [fields, setFields] =
        useState([]);


    const [loading, setLoading] =
        useState(false);


    // ======================================================
    // LOAD FIELDS
    // ======================================================

    const loadFields = async () => {

        try {

            setLoading(true);


            const response =
                await getCustomFieldsService(
                    module
                );


            setFields(
                response || []
            );

        }
        catch (error) {

            console.error(
                "Load custom fields error:",
                error
            );


            toast.error(
                error.response?.data?.message ||
                error.message ||
                "Failed to load custom fields"
            );


            setFields([]);

        }
        finally {

            setLoading(false);

        }

    };


    // ======================================================
    // INITIAL LOAD / MODULE CHANGE
    // ======================================================

    useEffect(() => {

        loadFields();

    }, [module]);


    const handleDelete = async (id) => {

    const confirmed =
        window.confirm(
            "Are you sure you want to delete this custom field?"
        );

    if (!confirmed) {
        return;
    }

    try {

        setLoading(true);

        const response =
            await deleteCustomFieldService(id);

        if (response.success) {

            toast.success(
                "Custom field deleted successfully"
            );

            await loadFields();

        } else {

            toast.error(
                response.message ||
                "Failed to delete custom field"
            );

        }

    }
    catch (error) {

        console.error(
            "Delete custom field error:",
            error
        );

        toast.error(
            error.response?.data?.message ||
            error.message ||
            "Failed to delete custom field"
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

            {/* ==================================================
                HEADER
            ================================================== */}

            <PageHeader
                title="Custom Fields"
                subtitle="Extra fields your organization adds to the standard forms."
                action={() =>
                    navigate("/settings/custom-fields/create")
                }
                actionLabel="Create Custom Field"
                actionIcon={<Add />}
            />

            {/* ==================================================
                FILTER
            ================================================== */}

            <Card
                sx={{
                    mb: 3
                }}
            >

                <CardContent>

                    <FormControl
                        sx={{
                            minWidth: 250
                        }}
                    >

                        <InputLabel>
                            Module
                        </InputLabel>

                        <Select
                            value={module}
                            label="Module"
                            onChange={(event) =>
                                setModule(
                                    event.target.value
                                )
                            }
                        >

                            {
                                modules.map(
                                    item => (

                                        <MenuItem
                                            key={item}
                                            value={item}
                                        >
                                            {item}
                                        </MenuItem>

                                    )
                                )
                            }

                        </Select>

                    </FormControl>

                </CardContent>

            </Card>

            {/* ==================================================
                TABLE
            ================================================== */}

            <Card>

                <TableContainer>

                    <Table>

                        <TableHead>

                            <TableRow>

                                <TableCell>
                                    Label
                                </TableCell>

                                <TableCell>
                                    Key
                                </TableCell>

                                <TableCell>
                                    Type
                                </TableCell>

                                <TableCell>
                                    Required
                                </TableCell>

                                <TableCell>
                                    Status
                                </TableCell>

                                <TableCell align="right">
                                    Actions
                                </TableCell>

                            </TableRow>

                        </TableHead>


                        <TableBody>

                            {
                                loading ? (

                                    <TableRow>

                                        <TableCell
                                            colSpan={6}
                                            align="center"
                                        >

                                            <Box
                                                sx={{
                                                    py: 4
                                                }}
                                            >

                                                <CircularProgress />

                                            </Box>

                                        </TableCell>

                                    </TableRow>

                                ) : fields.length === 0 ? (

                                    <TableRow>

                                        <TableCell
                                            colSpan={6}
                                            align="center"
                                        >

                                            <Typography
                                                sx={{
                                                    color: "text.secondary",
                                                    py: 4
                                                }}>
                                                No custom fields found
                                                for {module}.
                                            </Typography>

                                        </TableCell>

                                    </TableRow>

                                ) : (

                                    fields.map(
                                        field => (

                                            <TableRow
                                                key={field._id}
                                                hover
                                            >

                                                <TableCell>

                                                    <Typography
                                                        sx={{
                                                            fontWeight: 600
                                                        }}
                                                    >
                                                        {field.label}
                                                    </Typography>

                                                </TableCell>


                                                <TableCell>
                                                    {field.key}
                                                </TableCell>


                                                <TableCell>
                                                    {field.type}
                                                </TableCell>


                                                <TableCell>

                                                    {field.required
                                                        ? "Yes"
                                                        : "No"
                                                    }

                                                </TableCell>


                                                <TableCell>

                                                    {field.active
                                                        ? "Active"
                                                        : "Inactive"
                                                    }

                                                </TableCell>


                                                <TableCell align="right">

                                                    <Button
    size="small"
    startIcon={<Edit />}
    onClick={() =>
        navigate(
            `/settings/custom-fields/${field._id}/edit`
        )
    }
    sx={{
        mr: 1
    }}
>
    Edit
</Button>


                                                    <Button
                                                        size="small"
                                                        color="error"
                                                        startIcon={
                                                            <Delete />
                                                        }
                                                        onClick={() =>
                                                            handleDelete(
                                                                field._id
                                                            )
                                                        }
                                                    >
                                                        Delete
                                                    </Button>

                                                </TableCell>

                                            </TableRow>

                                        )
                                    )

                                )
                            }

                        </TableBody>

                    </Table>

                </TableContainer>

            </Card>

        </PageContainer>
    );

};


export default CustomFieldListPage;