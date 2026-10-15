import {
    TextField
} from "@mui/material";


const AppTextField = ({
    label,
    name,
    value = "",
    onChange,

    error = false,
    helperText = "",

    required = false,
    disabled = false,

    placeholder = "",

    type = "text",

    fullWidth = true,

    multiline = false,
    rows,

    size = "small",

    sx = {},

    ...props
}) => {

    return (
        <TextField
            label={label}
            name={name}

            value={
                value ?? ""
            }

            onChange={onChange}

            error={error}
            helperText={helperText}

            required={required}
            disabled={disabled}

            placeholder={placeholder}

            type={type}

            fullWidth={fullWidth}

            multiline={multiline}
            rows={rows}

            size={size}

            variant="outlined"

            InputLabelProps={{
                shrink: true
            }}

            {...props}

            sx={{
                width: "100%",
                minWidth: 0,

                "& .MuiOutlinedInput-root": {
                    borderRadius: 1.5,

                    backgroundColor:
                        disabled
                            ? "action.disabledBackground"
                            : "background.paper",

                    transition:
                        "border-color .15s ease, box-shadow .15s ease",

                    "&:hover .MuiOutlinedInput-notchedOutline": {
                        borderColor:
                            error
                                ? "error.main"
                                : "primary.main"
                    },

                    "&.Mui-focused .MuiOutlinedInput-notchedOutline": {
                        borderWidth: 2
                    }
                },

                "& .MuiInputLabel-root": {
                    fontWeight: 500,
                    whiteSpace: "nowrap"
                },

                "& .MuiInputLabel-root.Mui-focused": {
                    fontWeight: 600
                },

                "& .MuiInputLabel-asterisk": {
                    color: "error.main"
                },

                "& .MuiFormHelperText-root": {
                    marginLeft: 0,
                    marginTop: 0.5
                },

                ...sx
            }}
        />
    );
};


export default AppTextField;