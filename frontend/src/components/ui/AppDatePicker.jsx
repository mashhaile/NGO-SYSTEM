import {
    LocalizationProvider
} from "@mui/x-date-pickers/LocalizationProvider";

import {
    DatePicker
} from "@mui/x-date-pickers/DatePicker";

import {
    AdapterDayjs
} from "@mui/x-date-pickers/AdapterDayjs";

import dayjs from "dayjs";


const AppDatePicker = ({
    label = "Date",
    name,

    value = null,
    onChange,

    error = false,
    helperText = "",

    required = false,
    disabled = false,

    minDate,
    maxDate,

    disableFuture = false,
    disablePast = false,

    fullWidth = true,
    size = "small",

    ...props
}) => {

    const parsedValue =
        value
            ? dayjs(value)
            : null;


    return (
        <LocalizationProvider
            dateAdapter={AdapterDayjs}
        >

            <DatePicker
                label={label}

                value={parsedValue}

                format="DD/MM/YYYY"

                onChange={(newValue) => {

                    onChange?.(
                        newValue
                            ? newValue
                            : null,
                        name
                    );

                }}

                minDate={
                    minDate
                        ? dayjs(minDate)
                        : undefined
                }

                maxDate={
                    maxDate
                        ? dayjs(maxDate)
                        : undefined
                }

                disableFuture={disableFuture}
                disablePast={disablePast}

                disabled={disabled}

                slotProps={{
                    textField: {
                        name,
                        fullWidth,
                        size,
                        required,
                        error,
                        helperText,
                        variant: "outlined",

                        InputLabelProps: {
                            shrink: true
                        }
                    },

                    popper: {
                        sx: {
                            "& .MuiPaper-root": {
                                borderRadius: 2,
                                border: "1px solid",
                                borderColor: "divider",
                                boxShadow:
                                    "0 16px 40px rgba(15,23,42,0.14)"
                            },

                            "& .MuiPickersDay-root": {
                                borderRadius: 1.5
                            },

                            "& .MuiPickersDay-root.Mui-selected": {
                                fontWeight: 700
                            }
                        }
                    }
                }}

                {...props}
            />

        </LocalizationProvider>
    );
};


export default AppDatePicker;