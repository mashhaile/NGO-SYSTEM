import {
    Paper,
    Stack,
    TextField,
    Button,
    MenuItem,
    InputAdornment
} from "@mui/material";

import {
    Search,
    Refresh
} from "@mui/icons-material";


const SearchToolbar = ({
    search = "",
    onSearch,

    filters = [],

    onReset,

    children
}) => {

    return (
        <Paper
            elevation={0}
            sx={{
                p: {
                    xs: 1.5,
                    sm: 2
                },

                mb: 3,

                borderRadius: 3,

                border: "1px solid",
                borderColor: "divider",

                bgcolor: "background.paper"
            }}
        >

            <Stack sx={{ alignItems: {
                    xs: "stretch",
                    md: "center"
                } }}
                direction={{
                    xs: "column",
                    md: "row"
                }}

                spacing={1.5}
            >

                <TextField
                    value={search}

                    onChange={(event) =>
                        onSearch?.(
                            event.target.value
                        )
                    }

                    placeholder="Search..."

                    size="small"

                    sx={{
                        minWidth: {
                            xs: "100%",
                            md: 280
                        }
                    }}

                    slotProps={{
                        input: {
                            startAdornment: (
                                <InputAdornment
                                    position="start"
                                >
                                    <Search
                                        fontSize="small"
                                        color="action"
                                    />
                                </InputAdornment>
                            )
                        }
                    }}
                />


                {filters.map((filter) => (

                    <TextField
                        key={filter.key}
                        select

                        size="small"

                        label={filter.label}

                        value={
                            filter.value ?? ""
                        }

                        onChange={(event) =>
                            filter.onChange?.(
                                event.target.value
                            )
                        }

                        sx={{
                            minWidth: {
                                xs: "100%",
                                md: 180
                            }
                        }}
                    >

                        <MenuItem value="">
                            All
                        </MenuItem>


                        {(
                            filter.options || []
                        ).map((option) => (

                            <MenuItem
                                key={option.value}
                                value={option.value}
                            >
                                {option.label}
                            </MenuItem>

                        ))}

                    </TextField>

                ))}


                {onReset && (
                    <Button
                        variant="text"
                        startIcon={
                            <Refresh
                                fontSize="small"
                            />
                        }
                        onClick={onReset}
                        sx={{
                            alignSelf: {
                                xs: "flex-start",
                                md: "center"
                            }
                        }}
                    >
                        Reset
                    </Button>
                )}


                {children && (
                    <Stack
                        direction="row"
                        spacing={1}
                        sx={{
                            ml: {
                                xs: 0,
                                md: "auto"
                            }
                        }}
                    >
                        {children}
                    </Stack>
                )}

            </Stack>

        </Paper>
    );
};


export default SearchToolbar;