
import {
    useState
} from "react";

import {
    Box,
    Button,
    Card,
    CardContent,
    FormControl,
    FormControlLabel,
    InputLabel,
    MenuItem,
    Select,
    TextField,
    Typography,
    Checkbox,
    IconButton,
    Divider
} from "@mui/material";

import {
    ArrowBack,
    Add,
    Delete
} from "@mui/icons-material";

import {
    useNavigate
} from "react-router-dom";

import {
    toast
} from "react-toastify";

import {
    createCustomFieldService
} from "../services/customFieldService";


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
// FIELD TYPES
// ==========================================================

const fieldTypes = [
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


// ==========================================================
// PAGE
// ==========================================================

const CustomFieldCreatePage = () => {

    const navigate = useNavigate();


    const [loading, setLoading] =
        useState(false);


    const [formData, setFormData] =
        useState({

            module: "Beneficiary",

            label: "",

            key: "",

            type: "text",

            required: false,

            options: []

        });


    // ======================================================
    // HANDLE GENERAL CHANGE
    // ======================================================

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


    // ======================================================
    // REQUIRED
    // ======================================================

    const handleRequiredChange = (event) => {

        setFormData(
            previous => ({

                ...previous,

                required:
                    event.target.checked

            })
        );

    };


    // ======================================================
    // GENERATE KEY FROM LABEL
    // ======================================================

    const handleLabelChange = (event) => {

        const label =
            event.target.value;


        const key =
            label
                .toLowerCase()
                .trim()
                .replace(
                    /[^a-z0-9]+/g,
                    "_"
                )
                .replace(
                    /^_+|_+$/g,
                    ""
                );


        setFormData(
            previous => ({

                ...previous,

                label,

                key

            })
        );

    };


    // ======================================================
    // OPTION LABEL CHANGE
    // ======================================================

    const handleOptionChange = (
        index,
        value
    ) => {

        setFormData(
            previous => {

                const options = [
                    ...previous.options
                ];


                const generatedValue =
                    value
                        .toLowerCase()
                        .trim()
                        .replace(
                            /[^a-z0-9]+/g,
                            "_"
                        )
                        .replace(
                            /^_+|_+$/g,
                            ""
                        );


                options[index] = {

                    ...options[index],

                    label: value,

                    value:
                        options[index]?.value
                            ? options[index].value
                            : generatedValue

                };


                return {

                    ...previous,

                    options

                };

            }
        );

    };


    // ======================================================
    // OPTION VALUE CHANGE
    // ======================================================

    const handleOptionValueChange = (
        index,
        value
    ) => {

        setFormData(
            previous => {

                const options = [
                    ...previous.options
                ];


                options[index] = {

                    ...options[index],

                    value

                };


                return {

                    ...previous,

                    options

                };

            }
        );

    };


    // ======================================================
    // ADD OPTION
    // ======================================================

    const addOption = () => {

        setFormData(
            previous => ({

                ...previous,

                options: [

                    ...previous.options,

                    {
                        label: "",
                        value: ""
                    }

                ]

            })
        );

    };


    // ======================================================
    // REMOVE OPTION
    // ======================================================

    const removeOption = (index) => {

        setFormData(
            previous => ({

                ...previous,

                options:
                    previous.options.filter(
                        (_, optionIndex) =>
                            optionIndex !== index
                    )

            })
        );

    };


    // ======================================================
    // SUBMIT
    // ======================================================

    const handleSubmit = async (event) => {

        event.preventDefault();


        // --------------------------------------------------
        // VALIDATE LABEL
        // --------------------------------------------------

        if (!formData.label.trim()) {

            toast.error(
                "Label is required"
            );

            return;

        }


        // --------------------------------------------------
        // VALIDATE KEY
        // --------------------------------------------------

        if (!formData.key.trim()) {

            toast.error(
                "Key is required"
            );

            return;

        }


        // --------------------------------------------------
        // PREPARE DATA
        // --------------------------------------------------

        let submitData = {

            ...formData,

            label:
                formData.label.trim(),

            key:
                formData.key.trim()

        };


        // --------------------------------------------------
        // SELECT OPTIONS
        // --------------------------------------------------

        if (
            formData.type === "select"
        ) {

            const validOptions =
                formData.options.filter(
                    option =>
                        option.label?.trim() &&
                        option.value?.trim()
                );


            if (
                validOptions.length === 0
            ) {

                toast.error(
                    "Add at least one option"
                );

                return;

            }


            submitData = {

                ...submitData,

                options:
                    validOptions.map(
                        option => ({

                            label:
                                option.label.trim(),

                            value:
                                option.value.trim()

                        })
                    )

            };

        }
        else {

            submitData.options = [];

        }


        // --------------------------------------------------
        // SEND REQUEST
        // --------------------------------------------------

        try {

            setLoading(true);




            const response =
                await createCustomFieldService(
                    submitData
                );




            if (response?.success) {

                toast.success(
                    "Custom field created successfully"
                );


                // IMPORTANT:
                // This must match AppRoutes.jsx

                navigate(
                    "/settings/custom-fields",
                    {
                        replace: true
                    }
                );

            }
            else {

                toast.error(
                    response?.message ||
                    "Failed to create custom field"
                );

            }

        }
        catch (error) {

            console.error(
                "Create custom field error:",
                error
            );


            toast.error(

                error.response?.data?.message ||

                error.message ||

                "Failed to create custom field"

            );

        }
        finally {

            setLoading(false);

        }

    };


    // ======================================================
    // PAGE
    // ======================================================

    return (

        <Box>

            {/* ==================================================
                HEADER
            ================================================== */}

            <Box
                sx={{
                    display: "flex",
                    alignItems: "center",
                    gap: 2,
                    mb: 3
                }}
            >

                <Button
                    startIcon={
                        <ArrowBack />
                    }
                    onClick={() =>
                        navigate(
                            "/settings/custom-fields"
                        )
                    }
                >
                    Back
                </Button>


                <Box>

                    <Typography
                        variant="h5"
                        fontWeight={700}
                    >
                        Create Custom Field
                    </Typography>


                    <Typography
                        variant="body2"
                        color="text.secondary"
                    >
                        Add a custom field to an
                        organization module.
                    </Typography>

                </Box>

            </Box>


            {/* ==================================================
                FORM
            ================================================== */}

            <Card
                sx={{
                    maxWidth: 750
                }}
            >

                <CardContent>

                    <Box
                        component="form"
                        onSubmit={
                            handleSubmit
                        }
                        sx={{
                            display: "flex",
                            flexDirection: "column",
                            gap: 3
                        }}
                    >

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
                                name="module"
                                value={
                                    formData.module
                                }
                                label="Module"
                                onChange={
                                    handleChange
                                }
                            >

                                {
                                    modules.map(
                                        item => (

                                            <MenuItem
                                                key={
                                                    item
                                                }
                                                value={
                                                    item
                                                }
                                            >
                                                {item}
                                            </MenuItem>

                                        )
                                    )
                                }

                            </Select>

                        </FormControl>


                        {/* ==================================================
                            LABEL
                        ================================================== */}

                        <TextField
                            label="Field Label"
                            value={
                                formData.label
                            }
                            onChange={
                                handleLabelChange
                            }
                            fullWidth
                            required
                            helperText={
                                "Example: Gender, Phone Number, Household Size"
                            }
                        />


                        {/* ==================================================
                            KEY
                        ================================================== */}

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
                            helperText={
                                "Unique internal key. Example: gender"
                            }
                        />


                        {/* ==================================================
                            TYPE
                        ================================================== */}

                        <FormControl
                            fullWidth
                            required
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
                                    (event) => {

                                        handleChange(
                                            event
                                        );


                                        if (
                                            event.target.value !==
                                            "select"
                                        ) {

                                            setFormData(
                                                previous => ({

                                                    ...previous,

                                                    options: []

                                                })
                                            );

                                        }

                                    }
                                }
                            >

                                {
                                    fieldTypes.map(
                                        type => (

                                            <MenuItem
                                                key={
                                                    type.value
                                                }
                                                value={
                                                    type.value
                                                }
                                            >
                                                {type.label}
                                            </MenuItem>

                                        )
                                    )
                                }

                            </Select>

                        </FormControl>


                        {/* ==================================================
                            SELECT OPTIONS
                        ================================================== */}

                        {
                            formData.type ===
                            "select" && (

                                <Box>

                                    <Typography
                                        variant="subtitle1"
                                        fontWeight={600}
                                        sx={{
                                            mb: 1
                                        }}
                                    >
                                        Select Options
                                    </Typography>


                                    <Typography
                                        variant="body2"
                                        color="text.secondary"
                                        sx={{
                                            mb: 2
                                        }}
                                    >
                                        Add the choices
                                        users will see
                                        in the dropdown.
                                    </Typography>


                                    {
                                        formData.options.map(
                                            (
                                                option,
                                                index
                                            ) => (

                                                <Box
                                                    key={
                                                        index
                                                    }
                                                    sx={{
                                                        display:
                                                            "flex",
                                                        gap: 1,
                                                        mb: 2,
                                                        alignItems:
                                                            "center"
                                                    }}
                                                >

                                                    <TextField
                                                        fullWidth
                                                        label={
                                                            `Option ${index + 1}`
                                                        }
                                                        value={
                                                            option.label
                                                        }
                                                        onChange={
                                                            (event) =>
                                                                handleOptionChange(
                                                                    index,
                                                                    event.target.value
                                                                )
                                                        }
                                                    />


                                                    <TextField
                                                        fullWidth
                                                        label="Value"
                                                        value={
                                                            option.value
                                                        }
                                                        onChange={
                                                            (event) =>
                                                                handleOptionValueChange(
                                                                    index,
                                                                    event.target.value
                                                                )
                                                        }
                                                    />


                                                    <IconButton
                                                        color="error"
                                                        onClick={() =>
                                                            removeOption(
                                                                index
                                                            )
                                                        }
                                                        disabled={
                                                            loading
                                                        }
                                                    >
                                                        <Delete />
                                                    </IconButton>

                                                </Box>

                                            )
                                        )
                                    }


                                    <Button
                                        variant="outlined"
                                        startIcon={
                                            <Add />
                                        }
                                        onClick={
                                            addOption
                                        }
                                        disabled={
                                            loading
                                        }
                                    >
                                        Add Option
                                    </Button>

                                </Box>

                            )
                        }


                        <Divider />


                        {/* ==================================================
                            REQUIRED
                        ================================================== */}

                        <FormControlLabel
                            control={
                                <Checkbox
                                    checked={
                                        formData.required
                                    }
                                    onChange={
                                        handleRequiredChange
                                    }
                                    disabled={
                                        loading
                                    }
                                />
                            }
                            label="Required field"
                        />


                        {/* ==================================================
                            ACTIONS
                        ================================================== */}

                        <Box
                            sx={{
                                display: "flex",
                                justifyContent:
                                    "flex-end",
                                gap: 2
                            }}
                        >

                            <Button
                                variant="outlined"
                                disabled={
                                    loading
                                }
                                onClick={() =>
                                    navigate(
                                        "/settings/custom-fields"
                                    )
                                }
                            >
                                Cancel
                            </Button>


                            <Button
                                type="submit"
                                variant="contained"
                                disabled={
                                    loading
                                }
                            >
                                {
                                    loading
                                        ? "Creating..."
                                        : "Create Custom Field"
                                }
                            </Button>

                        </Box>

                    </Box>

                </CardContent>

            </Card>

        </Box>

    );

};


export default CustomFieldCreatePage;
