import {
    TextField
} from "@mui/material";


const FormField = ({
    sx = {},

    InputProps,
    SelectProps,

    ...props
}) => {

    return (
        <TextField
            {...props}
            fullWidth={
                props.fullWidth !== false
            }
            sx={{
                width: "100%",

                "& .MuiOutlinedInput-root": {
                    borderRadius: 1.5,

                    bgcolor:
                        "background.paper",

                    "&:hover fieldset": {
                        borderColor:
                            "primary.main"
                    },

                    "&.Mui-focused fieldset": {
                        borderWidth: 2
                    }
                },

                "& .MuiInputLabel-root": {
                    fontWeight: 500
                },

                "& .MuiInputLabel-root.Mui-focused": {
                    fontWeight: 600
                },

                "& .MuiFormHelperText-root": {
                    marginLeft: 0,
                    marginTop: 0.5
                },

                ...sx
            }}
            slotProps={{
                input: {
                    ...InputProps
                },

                select: {
                    ...SelectProps
                }
            }} />
    );
};


export default FormField;