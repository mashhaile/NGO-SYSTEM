import {
    useEffect,
    useState
} from "react";

import {
    useNavigate,
    useParams
} from "react-router-dom";

import {
    Box,
    Button,
    Card,
    CardContent,
    Checkbox,
    Divider,
    FormControlLabel,
    IconButton,
    TextField,
    Typography
} from "@mui/material";

import {
    ArrowBack,
    Add,
    Delete,
    Lock
} from "@mui/icons-material";

import {
    toast
} from "react-toastify";

import {
    getCustomFieldByIdService,
    updateCustomFieldService
} from "../services/customFieldService";


// ==========================================================
// GENERATE OPTION VALUE
// ==========================================================

const generateOptionValue = (label) => {

    return String(label || "")
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "_")
        .replace(/^_+|_+$/g, "");

};


// ==========================================================
// PAGE
// ==========================================================

const CustomFieldEditPage = () => {

    const navigate = useNavigate();

    const {
        id
    } = useParams();


    const [
        loading,
        setLoading
    ] = useState(true);


    const [
        saving,
        setSaving
    ] = useState(false);


    const [
        formData,
        setFormData
    ] = useState({

        module: "",

        label: "",

        key: "",

        type: "text",

        required: false,

        active: true,

        options: []

    });


    // ======================================================
    // LOAD CUSTOM FIELD
    // ======================================================

    useEffect(() => {

        const loadCustomField = async () => {

            try {

                setLoading(true);


                if (!id) {

                    throw new Error(
                        "Custom field ID is missing"
                    );

                }


                const field =
                    await getCustomFieldByIdService(id);


                if (!field) {

                    throw new Error(
                        "Custom field not found"
                    );

                }


                setFormData({

                    module:
                        field.module || "",

                    label:
                        field.label || "",

                    key:
                        field.key || "",

                    type:
                        field.type || "text",

                    required:
                        Boolean(field.required),

                    active:
                        field.active !== false,

                    options:
                        Array.isArray(field.options)
                            ? field.options.map(
                                option => ({

                                    label:
                                        option.label || "",

                                    value:
                                        option.value || "",

                                    isValueLocked:
                                        Boolean(
                                            option.isValueLocked
                                        )

                                })
                            )
                            : []

                });

            }
            catch (error) {

                console.error(
                    "Load custom field error:",
                    error
                );


                toast.error(

                    error.response?.data?.message ||

                    error.message ||

                    "Failed to load custom field"

                );


                navigate(
                    "/settings/custom-fields",
                    {
                        replace: true
                    }
                );

            }
            finally {

                setLoading(false);

            }

        };


        loadCustomField();

    }, [id, navigate]);


    // ======================================================
    // LABEL CHANGE
    // ======================================================

    const handleLabelChange = (event) => {

        setFormData(
            previous => ({

                ...previous,

                label:
                    event.target.value

            })
        );

    };


    // ======================================================
    // REQUIRED CHANGE
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
    // ACTIVE CHANGE
    // ======================================================

    const handleActiveChange = (event) => {

        setFormData(
            previous => ({

                ...previous,

                active:
                    event.target.checked

            })
        );

    };


    // ======================================================
    // OPTION LABEL CHANGE
    // ======================================================

    const handleOptionLabelChange = (
        index,
        value
    ) => {

        setFormData(
            previous => {

                const options = [
                    ...previous.options
                ];


                const currentOption =
                    options[index];


                options[index] = {

                    ...currentOption,

                    label: value

                };


                // ==================================================
                // AUTO GENERATE VALUE ONLY WHEN NOT LOCKED
                // ==================================================

                if (
                    !currentOption.isValueLocked
                ) {

                    options[index].value =
                        generateOptionValue(
                            value
                        );

                }


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


                if (
                    options[index]?.isValueLocked
                ) {

                    toast.warning(
                        "This option value is locked because it is already being used."
                    );


                    return previous;

                }


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

                        value: "",

                        isValueLocked: false

                    }

                ]

            })
        );

    };


    // ======================================================
    // REMOVE OPTION
    // ======================================================

    const removeOption = (index) => {

        const option =
            formData.options[index];


        if (
            option?.isValueLocked
        ) {

            toast.warning(

                "This option cannot be removed because its value is already being used."

            );

            return;

        }


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


        if (!id) {

            toast.error(
                "Custom field ID is missing"
            );

            return;

        }


        const label =
            formData.label.trim();


        if (!label) {

            toast.error(
                "Field label is required"
            );

            return;

        }


        const submitData = {

            label,

            required:
                formData.required,

            active:
                formData.active

        };


        // ==================================================
        // SELECT OPTIONS
        // ==================================================

        if (
            formData.type === "select"
        ) {

            const validOptions =
                formData.options
                    .map(
                        option => ({

                            label:
                                option.label?.trim() ||
                                "",

                            value:
                                option.value?.trim() ||

                                generateOptionValue(
                                    option.label
                                )

                        })
                    )
                    .filter(
                        option =>
                            option.label &&
                            option.value
                    );


            if (
                validOptions.length === 0
            ) {

                toast.error(
                    "Add at least one valid option"
                );

                return;

            }


            // ==================================================
            // DUPLICATE VALUES
            // ==================================================

            const duplicateValues =
                validOptions.map(
                    option =>
                        option.value.toLowerCase()
                );


            const hasDuplicateValues =
                new Set(
                    duplicateValues
                ).size !==
                duplicateValues.length;


            if (
                hasDuplicateValues
            ) {

                toast.error(
                    "Option values must be unique"
                );

                return;

            }


            // ==================================================
            // LOCKED VALUE PROTECTION
            // ==================================================

            for (
                const option of formData.options
            ) {

                if (
                    !option.isValueLocked
                ) {

                    continue;

                }


                const lockedValue =
                    String(
                        option.value || ""
                    ).trim();


                const stillExists =
                    validOptions.some(
                        validOption =>
                            validOption.value ===
                            lockedValue
                    );


                if (
                    !stillExists
                ) {

                    toast.error(

                        `The value "${lockedValue}" is already in use and cannot be changed or removed.`

                    );

                    return;

                }

            }


            submitData.options =
                validOptions;

        }


        // ==================================================
        // UPDATE
        // ==================================================

        try {

            setSaving(true);


            const response =
                await updateCustomFieldService(
                    id,
                    submitData
                );


            if (
                response?.success
            ) {

                toast.success(
                    response.message ||
                    "Custom field updated successfully"
                );


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

                    "Failed to update custom field"

                );

            }

        }
        catch (error) {

            console.error(
                "Update custom field error:",
                error
            );


            toast.error(

                error.response?.data?.message ||

                error.message ||

                "Failed to update custom field"

            );

        }
        finally {

            setSaving(false);

        }

    };


    // ======================================================
    // LOADING
    // ======================================================

    if (loading) {

        return (

            <Box>

                <Typography
                    variant="h5"
                    fontWeight={700}
                >
                    Loading Custom Field...
                </Typography>

            </Box>

        );

    }


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
                    disabled={saving}
                >
                    Back
                </Button>


                <Box>

                    <Typography
                        variant="h5"
                        fontWeight={700}
                    >
                        Edit Custom Field
                    </Typography>


                    <Typography
                        variant="body2"
                        color="text.secondary"
                    >
                        Update the custom field configuration.
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

                        <TextField
                            label="Module"
                            value={
                                formData.module
                            }
                            fullWidth
                            disabled
                        />


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
                            disabled={saving}
                        />


                        {/* ==================================================
                            KEY
                        ================================================== */}

                        <TextField
                            label="Field Key"
                            value={
                                formData.key
                            }
                            fullWidth
                            disabled
                            helperText={
                                "Field key cannot be changed after creation."
                            }
                        />


                        {/* ==================================================
                            TYPE
                        ================================================== */}

                        <TextField
                            label="Field Type"
                            value={
                                formData.type
                            }
                            fullWidth
                            disabled
                            helperText={
                                "Field type cannot be changed after creation."
                            }
                        />


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
                                        The value is used internally
                                        to store the selected option.
                                        It is generated automatically
                                        from the label, but can be edited
                                        until the option is used.
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

                                                    {/* ==========================================
                                                        OPTION LABEL
                                                    ========================================== */}

                                                    <TextField
                                                        fullWidth
                                                        label={
                                                            `Option ${index + 1}`
                                                        }
                                                        value={
                                                            option.label
                                                        }
                                                        onChange={
                                                            event =>
                                                                handleOptionLabelChange(
                                                                    index,
                                                                    event.target.value
                                                                )
                                                        }
                                                        disabled={
                                                            saving
                                                        }
                                                    />


                                                    {/* ==========================================
                                                        OPTION VALUE
                                                    ========================================== */}

                                                    <TextField
                                                        fullWidth
                                                        label="Value"
                                                        value={
                                                            option.value
                                                        }
                                                        onChange={
                                                            event =>
                                                                handleOptionValueChange(
                                                                    index,
                                                                    event.target.value
                                                                )
                                                        }
                                                        disabled={
                                                            saving ||
                                                            option.isValueLocked
                                                        }
                                                        InputProps={{
                                                            endAdornment:
                                                                option.isValueLocked
                                                                    ? (
                                                                        <Lock
                                                                            fontSize="small"
                                                                        />
                                                                    )
                                                                    : null
                                                        }}
                                                        helperText={
                                                            option.isValueLocked
                                                                ? "Locked because this value is already in use."
                                                                : "Editable until first use."
                                                        }
                                                    />


                                                    {/* ==========================================
                                                        DELETE OPTION
                                                    ========================================== */}

                                                    <IconButton
                                                        color="error"
                                                        onClick={() =>
                                                            removeOption(
                                                                index
                                                            )
                                                        }
                                                        disabled={
                                                            saving ||
                                                            option.isValueLocked
                                                        }
                                                    >

                                                        <Delete />

                                                    </IconButton>

                                                </Box>

                                            )
                                        )
                                    }


                                    <Button
                                        type="button"
                                        variant="outlined"
                                        startIcon={
                                            <Add />
                                        }
                                        onClick={
                                            addOption
                                        }
                                        disabled={
                                            saving
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
                                        saving
                                    }
                                />
                            }
                            label="Required field"
                        />


                        {/* ==================================================
                            ACTIVE
                        ================================================== */}

                        <FormControlLabel
                            control={
                                <Checkbox
                                    checked={
                                        formData.active
                                    }
                                    onChange={
                                        handleActiveChange
                                    }
                                    disabled={
                                        saving
                                    }
                                />
                            }
                            label="Active field"
                        />


                        {/* ==================================================
                            ACTIONS
                        ================================================== */}

                        <Box
                            sx={{
                                display: "flex",
                                justifyContent: "flex-end",
                                gap: 2
                            }}
                        >

                            <Button
                                type="button"
                                variant="outlined"
                                disabled={
                                    saving
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
                                    saving
                                }
                            >
                                {
                                    saving
                                        ? "Saving..."
                                        : "Save Changes"
                                }
                            </Button>

                        </Box>

                    </Box>

                </CardContent>

            </Card>

        </Box>

    );

};


export default CustomFieldEditPage;