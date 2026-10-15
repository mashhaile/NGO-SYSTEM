import {
    Autocomplete,
    TextField
} from "@mui/material";

const AppAutocomplete = ({
    label,
    name,
    value = null,
    onChange,
    options = [],
    getOptionLabel,
    isOptionEqualToValue,
    error = false,
    helperText = "",
    required = false,
    disabled = false,
    placeholder = "",
    loading = false,
    fullWidth = true,
    size = "small",
    sx = {},
    ...props
}) => {
    const normalizedOptions =
        Array.isArray(options)
            ? options
            : [];

    return (
        <Autocomplete
            options={normalizedOptions}
            value={value}
            onChange={(
                event,
                newValue
            ) => {
                onChange?.(
                    newValue,
                    name
                );
            }}
            getOptionLabel={
                getOptionLabel ||
                ((option) =>
                    option?.label ??
                    option?.name ??
                    String(option ?? ""))
            }
            isOptionEqualToValue={
                isOptionEqualToValue ||
                ((option, selected) =>
                    option?.id != null &&
                    selected?.id != null
                        ? option.id ===
                          selected.id
                        : option === selected)
            }
            loading={loading}
            disabled={disabled}
            fullWidth={fullWidth}
            size={size}
            sx={{
                "& .MuiOutlinedInput-root": {
                    borderRadius: 1,
                    backgroundColor:
                        disabled
                            ? "#f8fafc"
                            : "#ffffff"
                },
                ...sx
            }}
            {...props}
            renderInput={(params) => (
                <TextField
                    {...params}
                    label={label}
                    name={name}
                    required={required}
                    error={error}
                    helperText={helperText}
                    placeholder={
                        placeholder
                    }
                    size={size}
                    variant="outlined"
                    InputLabelProps={{
                        shrink: true
                    }}
                />
            )}
        />
    );
};

export default AppAutocomplete;