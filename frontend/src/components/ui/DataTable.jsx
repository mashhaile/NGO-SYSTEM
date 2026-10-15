import {
    Box,
    Typography
} from "@mui/material";

import {
    DataGrid
} from "@mui/x-data-grid";


const DataTable = ({
    rows = [],
    columns = [],

    loading = false,

    getRowId = (row) =>
        row._id ?? row.id,

    pageSize = 10,

    rowCount,

    paginationMode = "client",

    paginationModel,
    onPaginationModelChange,

    minHeight = 520,

    ...props
}) => {

    return (
        <Box
            sx={{
                width: "100%",

                bgcolor:
                    "background.paper",

                borderRadius: 3,

                border: "1px solid",
                borderColor: "divider",

                overflow: "hidden"
            }}
        >

            <DataGrid
                rows={rows}
                columns={columns}

                loading={loading}

                getRowId={getRowId}

                disableRowSelectionOnClick

                paginationMode={
                    paginationMode
                }

                rowCount={
                    paginationMode === "server"
                        ? rowCount
                        : undefined
                }

                paginationModel={
                    paginationModel
                }

                onPaginationModelChange={
                    onPaginationModelChange
                }

                pageSizeOptions={[
                    10,
                    25,
                    50,
                    100
                ]}

                initialState={{
                    pagination: {
                        paginationModel: {
                            pageSize
                        }
                    }
                }}

                slots={{
                    noRowsOverlay: () => (
                        <Box
                            sx={{
                                height: "100%",
                                minHeight: 220,

                                display: "flex",
                                flexDirection: "column",

                                alignItems: "center",
                                justifyContent: "center",

                                gap: 0.5
                            }}
                        >

                            <Typography
                                fontWeight={600}
                            >
                                No records found
                            </Typography>

                            <Typography
                                variant="body2"
                                color="text.secondary"
                            >
                                There is no data to display.
                            </Typography>

                        </Box>
                    )
                }}

                sx={{
                    border: 0,

                    minHeight,

                    "& .MuiDataGrid-columnHeaders": {
                        bgcolor: "action.hover",
                        borderBottom:
                            "1px solid",
                        borderColor:
                            "divider"
                    },

                    "& .MuiDataGrid-columnHeaderTitle": {
                        fontWeight: 700,
                        color: "text.primary"
                    },

                    "& .MuiDataGrid-cell": {
                        borderBottom:
                            "1px solid",
                        borderColor:
                            "divider"
                    },

                    "& .MuiDataGrid-row": {
                        transition:
                            "background-color .15s ease"
                    },

                    "& .MuiDataGrid-row:hover": {
                        bgcolor:
                            "action.hover"
                    },

                    "& .MuiDataGrid-footerContainer": {
                        borderTop:
                            "1px solid",
                        borderColor:
                            "divider",

                        minHeight: 56
                    },

                    "& .MuiDataGrid-cell:focus, & .MuiDataGrid-columnHeader:focus":
                        {
                            outline: "none"
                        },

                    "& .MuiDataGrid-cell:focus-within, & .MuiDataGrid-columnHeader:focus-within":
                        {
                            outline: "none"
                        }
                }}

                {...props}
            />

        </Box>
    );
};


export default DataTable;