import {
    useEffect,
    useState
} from "react";

import {
    Box,
    Button,
    Card,
    CardContent,
    Chip,
    CircularProgress,
    Divider,
    FormControl,
    IconButton,
    InputLabel,
    MenuItem,
    Select,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    TextField,
    Typography
} from "@mui/material";

import {
    Add,
    Delete,
    Edit
} from "@mui/icons-material";

import {
    toast
} from "react-toastify";

import {
    getCustomFieldsService,
    createCustomFieldService,
    updateCustomFieldService,
    deleteCustomFieldService
} from "../services/customFieldService";


// ==========================================
// AVAILABLE MODULES
// ==========================================

const MODULES = [

    {
        value: "Beneficiary",
        label: "Beneficiary"
    },

    {
        value: "Donor",
        label: "Donor"
    },

    {
        value: "Program",
        label: "Program"
    },

    {
        value: "ServiceDelivery",
        label: "Service Delivery"
    },

    {
        value: "User",
        label: "User"
    }

];


// ==========================================
// FIELD TYPES
// ==========================================

const FIELD_TYPES = [

    {
        value: "text",
        label: "Text"
    },

    {
        value: "number",
        label: "Number"
    },

    {
        value: "date",
        label: "Date"
    },

    {
        value: "select",
        label: "Select"
    },

    {
        value: "checkbox",
        label: "Checkbox"
    },

    {
        value: "textarea",
        label: "Textarea"
    }

];


// ==========================================
// INITIAL FORM
// ==========================================

const emptyForm = {

    label: "",

    key: "",

    type: "text",

    options: "",

    required: false

};


// ==========================================
// PAGE
// ==========================================

const CustomFieldManagementPage = () => {

    const [module, setModule] =
        useState("Beneficiary");

    const [fields, setFields] =
        useState([]);

    const [loading, setLoading] =
        useState(false);

    const [saving, setSaving] =
        useState(false);

    const [editingId, setEditingId] =
        useState(null);

    const [showForm, setShowForm] =
        useState(false);

    const [formData, setFormData] =
        useState(emptyForm);


    // ==========================================
    // LOAD FIELDS
    // ==========================================

    const loadFields = async () => {

        try {

            setLoading(true);

            const result =
                await getCustomFieldsService(
                    module
                );

            setFields(
                result || []
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

        }
        finally {

            setLoading(false);

        }

    };


    // ==========================================
    // LOAD WHEN MODULE CHANGES
    // ==========================================

    useEffect(() => {

        loadFields();

    }, [module]);


    // ==========================================
    // HANDLE FORM CHANGE
    // ==========================================

    const handleChange = (event) => {

        const {
            name,
            value
        } = event.target;

        setFormData(
            previous => ({

                ...previous,

                [name]: value

            })
        );

    };


    // ==========================================
    // RESET FORM
    // ==========================================

    const resetForm = () => {

        setFormData(
            emptyForm
        );

        setEditingId(null);

        setShowForm(false);

    };


    // ==========================================
    // START CREATE
    // ==========================================

    const handleAdd = () => {

        setEditingId(null);

        setFormData(
            emptyForm
        );

        setShowForm(true);

    };


    // ==========================================
    // START EDIT
    // ==========================================

    const handleEdit = (field) => {

        setEditingId(
            field._id
        );

        setFormData({

            label:
                field.label || "",

            key:
                field.key || "",

            type:
                field.type || "text",

            options:
                field.options?.join(", ") || "",

            required:
                field.required || false

        });

        setShowForm(true);

    };


    // ==========================================
    // SUBMIT
    // ==========================================

    const handleSubmit = async (event) => {

        event.preventDefault();


        if (!formData.label.trim()) {

            toast.error(
                "Field label is required"
            );

            return;

        }


        if (!formData.key.trim()) {

            toast.error(
                "Field key is required"
            );

            return;

        }


        if (
            formData.type === "select" &&
            !formData.options.trim()
        ) {

            toast.error(
                "Select fields require options"
            );

            return;

        }


        try {

            setSaving(true);


            const options =
                formData.options
                    .split(",")
                    .map(
                        item => item.trim()
                    )
                    .filter(Boolean);


            const data = {

                module,

                label:
                    formData.label.trim(),

                key:
                    formData.key
                        .trim()
                        .toLowerCase()
                        .replace(/\s+/g, "_"),

                type:
                    formData.type,

                required:
                    Boolean(
                        formData.required
                    )

            };


            if (
                formData.type === "select"
            ) {

                data.options =
                    options;

            }
            else {

                data.options = [];

            }


            // ==================================
            // CREATE
            // ==================================

            if (!editingId) {

                await createCustomFieldService(
                    data
                );

                toast.success(
                    "Custom field created successfully"
                );

            }


            // ==================================
            // UPDATE
            // ==================================

            else {

                await updateCustomFieldService(
                    editingId,
                    data
                );

                toast.success(
                    "Custom field updated successfully"
                );

            }


            resetForm();

            await loadFields();

        }
        catch (error) {

            console.error(
                "Save custom field error:",
                error
            );

            toast.error(
                error.response?.data?.message ||
                error.message ||
                "Failed to save custom field"
            );

        }
        finally {

            setSaving(false);

        }

    };


    // ==========================================
    // DELETE
    // ==========================================

    const handleDelete = async (id) => {

        const confirmed =
            window.confirm(
                "Are you sure you want to delete this custom field?"
            );


        if (!confirmed) {

            return;

        }


        try {

            await deleteCustomFieldService(
                id
            );

            toast.success(
                "Custom field deleted successfully"
            );

            await loadFields();

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

    };


    // ==========================================
    // PAGE
    // ==========================================

    return (

        <Box>

            {/* ==================================
                HEADER
            ================================== */}

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
                        variant="h5"
                        fontWeight={700}
                    >
                        Custom Fields
                    </Typography>

                    <Typography
                        variant="body2"
                        color="text.secondary"
                    >
                        Create and manage organization-specific fields.
                    </Typography>

                </Box>


                <Button
                    variant="contained"
                    startIcon={<Add />}
                    onClick={handleAdd}
                >
                    Add Custom Field
                </Button>

            </Box>


            {/* ==================================
                MODULE SELECTOR
            ================================== */}

            <Card
                sx={{
                    mb: 3
                }}
            >

                <CardContent>

                    <FormControl
                        fullWidth
                        sx={{
                            maxWidth: 400
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

                            {MODULES.map(
                                item => (

                                    <MenuItem
                                        key={item.value}
                                        value={item.value}
                                    >
                                        {item.label}
                                    </MenuItem>

                                )
                            )}

                        </Select>

                    </FormControl>

                </CardContent>

            </Card>


            {/* ==================================
                CREATE / EDIT FORM
            ================================== */}

            {showForm && (

                <Card
                    sx={{
                        mb: 3
                    }}
                >

                    <CardContent>

                        <Typography
                            variant="h6"
                            fontWeight={600}
                            mb={3}
                        >
                            {editingId
                                ? "Edit Custom Field"
                                : "Add Custom Field"
                            }
                        </Typography>


                        <Box
                            component="form"
                            onSubmit={handleSubmit}
                            sx={{
                                display: "flex",
                                flexDirection: "column",
                                gap: 3
                            }}
                        >

                            <TextField
                                label="Field Label"
                                name="label"
                                value={
                                    formData.label
                                }
                                onChange={
                                    handleChange
                                }
                                fullWidth
                                required
                            />


                            <TextField
                                label="Field Key"
                                name="key"
                                value={
                                    formData.key
                                }
                                onChange={
                                    handleChange
                                }
                                fullWidth
                                required
                                helperText="Example: phone_number"
                            />


                            <FormControl
                                fullWidth
                            >

                                <InputLabel>
                                    Field Type
                                </InputLabel>

                                <Select
                                    name="type"
                                    value={
                                        formData.type
                                    }
                                    label="Field Type"
                                    onChange={
                                        handleChange
                                    }
                                >

                                    {FIELD_TYPES.map(
                                        item => (

                                            <MenuItem
                                                key={item.value}
                                                value={item.value}
                                            >
                                                {item.label}
                                            </MenuItem>

                                        )
                                    )}

                                </Select>

                            </FormControl>


                            {formData.type === "select" && (

                                <TextField
                                    label="Options"
                                    name="options"
                                    value={
                                        formData.options
                                    }
                                    onChange={
                                        handleChange
                                    }
                                    fullWidth
                                    required
                                    helperText="Separate options with commas. Example: Male, Female, Other"
                                />

                            )}


                            <FormControl
                                fullWidth
                            >

                                <InputLabel>
                                    Required
                                </InputLabel>

                                <Select
                                    name="required"
                                    value={
                                        formData.required
                                            ? "true"
                                            : "false"
                                    }
                                    label="Required"
                                    onChange={(event) =>
                                        setFormData(
                                            previous => ({
                                                ...previous,
                                                required:
                                                    event.target.value === "true"
                                            })
                                        )
                                    }
                                >

                                    <MenuItem value="false">
                                        No
                                    </MenuItem>

                                    <MenuItem value="true">
                                        Yes
                                    </MenuItem>

                                </Select>

                            </FormControl>


                            <Box
                                sx={{
                                    display: "flex",
                                    justifyContent: "flex-end",
                                    gap: 2
                                }}
                            >

                                <Button
                                    variant="outlined"
                                    onClick={
                                        resetForm
                                    }
                                    disabled={saving}
                                >
                                    Cancel
                                </Button>


                                <Button
                                    type="submit"
                                    variant="contained"
                                    disabled={saving}
                                >
                                    {saving
                                        ? "Saving..."
                                        : editingId
                                            ? "Update Field"
                                            : "Create Field"
                                    }
                                </Button>

                            </Box>

                        </Box>

                    </CardContent>

                </Card>

            )}


            {/* ==================================
                FIELD LIST
            ================================== */}

            <Card>

                <CardContent>

                    <Typography
                        variant="h6"
                        fontWeight={600}
                        mb={2}
                    >
                        {module} Custom Fields
                    </Typography>


                    <Divider
                        sx={{
                            mb: 2
                        }}
                    />


                    {loading ? (

                        <Box
                            sx={{
                                display: "flex",
                                justifyContent: "center",
                                py: 5
                            }}
                        >

                            <CircularProgress />

                        </Box>

                    ) : fields.length === 0 ? (

                        <Typography
                            color="text.secondary"
                            sx={{
                                py: 4
                            }}
                        >
                            No custom fields have been created for this module.
                        </Typography>

                    ) : (

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

                                    {fields.map(
                                        field => (

                                            <TableRow
                                                key={
                                                    field._id
                                                }
                                            >

                                                <TableCell>
                                                    <Typography
                                                        fontWeight={600}
                                                    >
                                                        {
                                                            field.label
                                                        }
                                                    </Typography>
                                                </TableCell>


                                                <TableCell>
                                                    {
                                                        field.key
                                                    }
                                                </TableCell>


                                                <TableCell>
                                                    {
                                                        field.type
                                                    }
                                                </TableCell>


                                                <TableCell>

                                                    <Chip
                                                        size="small"
                                                        label={
                                                            field.required
                                                                ? "Required"
                                                                : "Optional"
                                                        }
                                                    />

                                                </TableCell>


                                                <TableCell>

                                                    <Chip
                                                        size="small"
                                                        label={
                                                            field.active
                                                                ? "Active"
                                                                : "Inactive"
                                                        }
                                                    />

                                                </TableCell>


                                                <TableCell
                                                    align="right"
                                                >

                                                    <IconButton
                                                        onClick={() =>
                                                            handleEdit(
                                                                field
                                                            )
                                                        }
                                                    >

                                                        <Edit />

                                                    </IconButton>


                                                    <IconButton
                                                        color="error"
                                                        onClick={() =>
                                                            handleDelete(
                                                                field._id
                                                            )
                                                        }
                                                    >

                                                        <Delete />

                                                    </IconButton>

                                                </TableCell>

                                            </TableRow>

                                        )
                                    )}

                                </TableBody>

                            </Table>

                        </TableContainer>

                    )}

                </CardContent>

            </Card>

        </Box>

    );

};


export default CustomFieldManagementPage;