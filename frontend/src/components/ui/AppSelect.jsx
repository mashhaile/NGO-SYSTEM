import {
    TextField,
    MenuItem
} from "@mui/material";


const AppSelect = ({
    label,
    name,

    value = "",
    onChange,

    options = [],

    error = false,
    helperText = "",

    required = false,
    disabled = false,
    multiple = false,

    placeholder,

    fullWidth = true,
    size = "small",

    SelectProps: externalSelectProps = {},

    sx = {},

    children,

    ...props
}) => {

    const selectPlaceholder =
        placeholder ||
        `Select ${label || ""}`;


    const {
        MenuProps: externalMenuProps = {},
        ...otherSelectProps
    } = externalSelectProps;


    const normalizedOptions =
        Array.isArray(options)
            ? options.map(
                (
                    option,
                    index
                ) => {

                    const optionValue =
                        option?.value ??
                        option?.id ??
                        "";

                    return {

                        value:
                            String(
                                optionValue
                            ),

                        label:
                            option?.label ??
                            option?.name ??
                            option?.text ??
                            "",

                        key:
                            String(
                                optionValue
                            ) ||
                            `option-${index}`

                    };

                }
            )
            : [];


    /*
     * MUI requires an ARRAY when multiple=true.
     */
    const selectValue =
        multiple
            ? (
                Array.isArray(
                    value
                )
                    ? value.map(
                        (
                            item
                        ) =>
                            String(
                                item
                            )
                    )
                    : []
            )
            : (
                value === null ||
                value === undefined
                    ? ""
                    : String(
                        value
                    )
            );


    const hasOptions =
        normalizedOptions.length >
        0;


    const hasChildren =
        children !== undefined &&
        children !== null;


    return (

        <TextField
            {...props}

            select

            label={label}
            name={name}

            value={selectValue}

            onChange={onChange}

            error={error}
            helperText={helperText}

            required={required}
            disabled={disabled}

            fullWidth={fullWidth}
            size={size}

            variant="outlined"

            InputLabelProps={{
                shrink: true
            }}

            SelectProps={{
                ...otherSelectProps,

                multiple,

                value:
                    selectValue,

                displayEmpty:
                    !multiple,

                MenuProps: {

                    ...externalMenuProps,

                    PaperProps: {

                        ...externalMenuProps.PaperProps,

                        sx: {

                            mt: 0.75,

                            borderRadius: 2,

                            border:
                                "1px solid",

                            borderColor:
                                "divider",

                            boxShadow:
                                "0 12px 35px rgba(15,23,42,0.12)",

                            "& .MuiMenuItem-root": {

                                minHeight:
                                    42,

                                px:
                                    1.5,

                                borderRadius:
                                    1,

                                mx:
                                    0.5,

                                my:
                                    0.25,

                                "&:hover":
                                    {
                                        backgroundColor:
                                            "action.hover"
                                    },

                                "&.Mui-selected":
                                    {

                                        backgroundColor:
                                            "action.selected",

                                        color:
                                            "primary.main",

                                        fontWeight:
                                            600

                                    },

                                "&.Mui-selected:hover":
                                    {

                                        backgroundColor:
                                            "action.selected"

                                    }

                            },

                            ...externalMenuProps
                                .PaperProps
                                ?.sx

                        }

                    }

                }

            }}

            sx={{

                width:
                    "100%",

                minWidth:
                    0,

                "& .MuiOutlinedInput-root":
                    {

                        borderRadius:
                            1.5,

                        backgroundColor:
                            disabled
                                ? "action.disabledBackground"
                                : "background.paper",

                        "&:hover .MuiOutlinedInput-notchedOutline":
                            {

                                borderColor:
                                    error
                                        ? "error.main"
                                        : "primary.main"

                            },

                        "&.Mui-focused .MuiOutlinedInput-notchedOutline":
                            {

                                borderWidth:
                                    2

                            }

                    },

                "& .MuiSelect-select":
                    {

                        minWidth:
                            0,

                        whiteSpace:
                            "nowrap",

                        overflow:
                            "hidden",

                        textOverflow:
                            "ellipsis"

                    },

                "& .MuiInputLabel-root":
                    {

                        fontWeight:
                            500,

                        whiteSpace:
                            "nowrap"

                    },

                "& .MuiInputLabel-root.Mui-focused":
                    {

                        fontWeight:
                            600

                    },

                "& .MuiInputLabel-asterisk":
                    {

                        color:
                            "error.main"

                    },

                "& .MuiFormHelperText-root":
                    {

                        marginLeft:
                            0,

                        marginTop:
                            0.5

                    },

                ...sx

            }}

        >

            {!multiple && (

                <MenuItem
                    value=""
                    disabled
                >
                    {selectPlaceholder}
                </MenuItem>

            )}


            {
                hasOptions
                    ? (
                        normalizedOptions.map(
                            (
                                option
                            ) => (

                                <MenuItem
                                    key={
                                        option.key
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
                    )
                    : hasChildren
                        ? children
                        : null
            }

        </TextField>

    );

};


export default AppSelect;