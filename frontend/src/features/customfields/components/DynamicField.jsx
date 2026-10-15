import {
    TextField,
    MenuItem,
    FormControlLabel,
    Checkbox,
    Radio,
    RadioGroup,
    FormControl,
    FormLabel,
    FormGroup
} from "@mui/material";


// ==========================================================
// DYNAMIC FIELD
// ==========================================================

const DynamicField = ({
    field,
    value,
    onChange
}) => {

    // ======================================================
    // SAFETY
    // ======================================================

    if (!field) {
        return null;
    }


    // ======================================================
    // NORMALIZE OPTIONS
    // ======================================================

    const options =
        Array.isArray(field.options)

            ? field.options.map(
                (option) => {

                    if (
                        typeof option === "object" &&
                        option !== null
                    ) {

                        return {

                            label:
                                String(
                                    option.label ?? ""
                                ),

                            value:
                                String(
                                    option.value ?? ""
                                )

                        };

                    }


                    return {

                        label:
                            String(
                                option ?? ""
                            ),

                        value:
                            String(
                                option ?? ""
                            )

                    };

                }
            )

            : [];


    // ======================================================
    // CHANGE HANDLER
    // ======================================================

    const handleChange = (
        newValue
    ) => {

        if (!field.key) {
            return;
        }


        onChange(
            field.key,
            newValue
        );

    };


    // ======================================================
    // COMMON TEXT PROPS
    // ======================================================

    const commonProps = {

        fullWidth: true,

        label:
            field.label,

        placeholder:
            field.placeholder || "",

        required:
            Boolean(
                field.required
            )

    };


    // ======================================================
    // TEXT / EMAIL / PHONE
    // ======================================================

    switch (field.type) {

        case "text":

        case "email":

        case "phone":

            return (

                <TextField

                    {...commonProps}

                    type={
                        field.type === "email"
                            ? "email"
                            : "text"
                    }

                    value={
                        value ?? ""
                    }

                    inputProps={{

                        minLength:
                            field.validation?.minLength ??
                            undefined,

                        maxLength:
                            field.validation?.maxLength ??
                            undefined

                    }}

                    onChange={(e) =>
                        handleChange(
                            e.target.value
                        )
                    }

                />

            );


        // ==================================================
        // NUMBER / CURRENCY
        // ==================================================

        case "number":

        case "currency":

            return (

                <TextField

                    {...commonProps}

                    type="number"

                    value={
                        value ?? ""
                    }

                    inputProps={{

                        min:
                            field.validation?.minValue ??
                            undefined,

                        max:
                            field.validation?.maxValue ??
                            undefined

                    }}

                    onChange={(e) =>
                        handleChange(
                            e.target.value
                        )
                    }

                />

            );


        // ==================================================
        // DATE
        // ==================================================

        case "date":

            return (

                <TextField

                    {...commonProps}

                    type="date"

                    InputLabelProps={{
                        shrink: true
                    }}

                    value={
                        value ?? ""
                    }

                    onChange={(e) =>
                        handleChange(
                            e.target.value
                        )
                    }

                />

            );


        // ==================================================
        // TEXTAREA
        // ==================================================

        case "textarea":

            return (

                <TextField

                    {...commonProps}

                    multiline

                    rows={4}

                    value={
                        value ?? ""
                    }

                    inputProps={{

                        minLength:
                            field.validation?.minLength ??
                            undefined,

                        maxLength:
                            field.validation?.maxLength ??
                            undefined

                    }}

                    onChange={(e) =>
                        handleChange(
                            e.target.value
                        )
                    }

                />

            );


        // ==================================================
        // SELECT
        // ==================================================

        case "select":

            return (

                <TextField

                    {...commonProps}

                    select

                    value={
                        value ?? ""
                    }

                    onChange={(e) =>
                        handleChange(
                            e.target.value
                        )
                    }

                >

                    <MenuItem value="">
                        Select {field.label}
                    </MenuItem>


                    {
                        options.map(
                            (option) => (

                                <MenuItem

                                    key={
                                        option.value
                                    }

                                    value={
                                        option.value
                                    }

                                >

                                    {
                                        option.label
                                    }

                                </MenuItem>

                            )
                        )
                    }

                </TextField>

            );


        // ==================================================
        // RADIO
        // ==================================================

        case "radio":

            return (

                <FormControl
                    required={
                        Boolean(
                            field.required
                        )
                    }
                >

                    <FormLabel>

                        {
                            field.label
                        }

                    </FormLabel>


                    <RadioGroup

                        value={
                            value ?? ""
                        }

                        onChange={(e) =>
                            handleChange(
                                e.target.value
                            )
                        }

                    >

                        {
                            options.map(
                                (option) => (

                                    <FormControlLabel

                                        key={
                                            option.value
                                        }

                                        value={
                                            option.value
                                        }

                                        control={
                                            <Radio />
                                        }

                                        label={
                                            option.label
                                        }

                                    />

                                )
                            )
                        }

                    </RadioGroup>

                </FormControl>

            );


        // ==================================================
        // CHECKBOX
        // ==================================================

        case "checkbox":

            return (

                <FormControlLabel

                    control={

                        <Checkbox

                            checked={
                                value === true
                            }

                            onChange={(e) =>
                                handleChange(
                                    e.target.checked
                                )
                            }

                        />

                    }

                    label={
                        field.label
                    }

                />

            );


        // ==================================================
        // MULTI SELECT
        // ==================================================

        case "multi_select":
        {

            const selectedValues =
                Array.isArray(value)
                    ? value
                    : [];


            return (

                <FormGroup>

                    <FormLabel>

                        {
                            field.label
                        }

                    </FormLabel>


                    {
                        options.map(
                            (option) => (

                                <FormControlLabel

                                    key={
                                        option.value
                                    }

                                    control={

                                        <Checkbox

                                            checked={
                                                selectedValues.includes(
                                                    option.value
                                                )
                                            }

                                            onChange={(e) => {

                                                let newValue =
                                                    [
                                                        ...selectedValues
                                                    ];


                                                if (
                                                    e.target.checked
                                                ) {

                                                    if (
                                                        !newValue.includes(
                                                            option.value
                                                        )
                                                    ) {

                                                        newValue.push(
                                                            option.value
                                                        );

                                                    }

                                                }

                                                else {

                                                    newValue =
                                                        newValue.filter(
                                                            item =>
                                                                item !==
                                                                option.value
                                                        );

                                                }


                                                handleChange(
                                                    newValue
                                                );

                                            }}

                                        />

                                    }

                                    label={
                                        option.label
                                    }

                                />

                            )
                        )
                    }

                </FormGroup>

            );

        }


        // ==================================================
        // LOCATION
        // ==================================================

        case "location":

            return (

                <TextField

                    {...commonProps}

                    value={
                        value ?? ""
                    }

                    onChange={(e) =>
                        handleChange(
                            e.target.value
                        )
                    }

                />

            );


        // ==================================================
        // FILE
        // ==================================================

        case "file":

            return (

                <TextField

                    {...commonProps}

                    type="file"

                    InputLabelProps={{
                        shrink: true
                    }}

                    onChange={(e) => {

                        const file =
                            e.target.files?.[0] ||
                            null;


                        handleChange(
                            file
                        );

                    }}

                />

            );


        // ==================================================
        // UNKNOWN TYPE
        // ==================================================

        default:

            return null;

    }

};


export default DynamicField;