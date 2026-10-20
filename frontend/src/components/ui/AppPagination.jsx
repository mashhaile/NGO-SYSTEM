import {
    Pagination,
    Stack,
    Typography
} from "@mui/material";


const AppPagination = ({
    page = 1,

    totalPages = 1,

    onChange,

    showSummary = true
}) => {

    if (totalPages <= 1) {
        return null;
    }


    return (
        <Stack
            direction={{
                xs: "column",
                sm: "row"
            }}

            spacing={2}

            sx={{ alignItems: "center", justifyContent: "center",
                py: 2
            }}
        >

            {showSummary && (
                <Typography
                    variant="body2"
                    sx={{
                        color: "text.secondary"
                    }}
                >
                    Page {page} of {totalPages}
                </Typography>
            )}

            <Pagination
                page={page}
                count={totalPages}

                onChange={(_, value) =>
                    onChange?.(value)
                }

                color="primary"
                shape="rounded"
                size="small"
            />

        </Stack>
    );
};


export default AppPagination;