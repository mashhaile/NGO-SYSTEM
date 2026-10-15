import { DataGrid } from "@mui/x-data-grid";

import {
    Box,
    IconButton,
    Stack,
    Tooltip,
    Typography
} from "@mui/material";

import {
    Visibility,
    Edit,
    Delete
} from "@mui/icons-material";

import { useNavigate } from "react-router-dom";
import { useDispatch } from "react-redux";

import { deleteAttendanceThunk } from "../store";

const AttendanceTable = ({
    data = [],
    loading = false
}) => {

    const navigate = useNavigate();
    const dispatch = useDispatch();

    const handleDelete = (id) => {

        const confirmed = window.confirm(
            "Delete this attendance session?"
        );

        if (!confirmed) return;

        dispatch(deleteAttendanceThunk(id));

    };

    const columns = [

        {
            field: "program",
            headerName: "Program",
            width: 170,
            renderCell: ({ row }) => (
                <Typography variant="body2">
                    {row.program?.programCode || "-"}
                </Typography>
            )
        },

        {
            field: "project",
            headerName: "Project",
            width: 170,
            renderCell: ({ row }) => (
                <Typography variant="body2">
                    {row.project?.projectCode || "-"}
                </Typography>
            )
        },

        {
            field: "activityRun",
            headerName: "Activity Run",
            flex: 1.3,
            minWidth: 250,
            renderCell: ({ row }) => (

                <Box>

                    <Typography fontWeight={700}>
                        {row.activityRun?.runCode || "-"}
                    </Typography>

                    <Typography
                        variant="body2"
                        color="text.secondary"
                    >
                        {row.activityRun?.name || "-"}
                    </Typography>

                </Box>

            )
        },

        {
            field: "sessionNumber",
            headerName: "Session #",
            width: 110,
            renderCell: ({ value }) => value || "-"
        },

        {
            field: "sessionTitle",
            headerName: "Session Title",
            flex: 1.2,
            minWidth: 220,
            renderCell: ({ value }) => (

                <Typography fontWeight={600}>
                    {value || "-"}
                </Typography>

            )
        },

        {
            field: "sessionDate",
            headerName: "Session Date",
            width: 140,
            renderCell: ({ value }) =>

                value
                    ? new Date(value).toLocaleDateString()
                    : "-"

        },

        {
            field: "notes",
            headerName: "Notes",
            flex: 1,
            minWidth: 220,
            renderCell: ({ value }) => (

                <Typography
                    variant="body2"
                    noWrap
                >
                    {value || "-"}
                </Typography>

            )
        },

        {
            field: "actions",
            headerName: "Actions",
            width: 170,
            sortable: false,
            filterable: false,

            renderCell: ({ row }) => (

                <Stack
                    direction="row"
                    spacing={0.5}
                >

                    <Tooltip title="Attendance Sheet">

                        <IconButton
                            color="primary"
                            onClick={() =>
                                navigate(`/attendance/${row._id}/sheet`)
                            }
                        >
                            <Visibility />
                        </IconButton>

                    </Tooltip>

                    <Tooltip title="Edit Session">

                        <IconButton
                            color="secondary"
                            onClick={() =>
                                navigate(`/attendance/${row._id}/edit`)
                            }
                        >
                            <Edit />
                        </IconButton>

                    </Tooltip>

                    <Tooltip title="Delete">

                        <IconButton
                            color="error"
                            onClick={() =>
                                handleDelete(row._id)
                            }
                        >
                            <Delete />
                        </IconButton>

                    </Tooltip>

                </Stack>

            )

        }

    ];

    return (

        <Box
            sx={{
                height: 650,
                backgroundColor: "#fff",
                borderRadius: 2,
                overflow: "hidden"
            }}
        >

            <DataGrid
                rows={data}
                columns={columns}
                loading={loading}
                getRowId={(row) => row._id}
                disableRowSelectionOnClick
                pageSizeOptions={[10, 25, 50]}
                initialState={{
                    pagination: {
                        paginationModel: {
                            pageSize: 10
                        }
                    }
                }}
                sx={{
                    border: 0,

                    "& .MuiDataGrid-columnHeaders": {
                        fontWeight: 700,
                        backgroundColor: "#fafafa"
                    },

                    "& .MuiDataGrid-cell": {
                        display: "flex",
                        alignItems: "center"
                    }
                }}
            />

        </Box>

    );

};

export default AttendanceTable;