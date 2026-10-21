import { DataGrid } from "@mui/x-data-grid";

import {
    Box,
    Chip,
    IconButton,
    MenuItem,
    Select,
    Tooltip,
    Typography
} from "@mui/material";

import { Delete } from "@mui/icons-material";

const AttendanceGrid = ({
    rows = [],
    setRows
}) => {

    const updateStatus = (id, value) => {

        setRows(prev =>
            prev.map(row =>
                (row.id || row._id) === id
                    ? {
                          ...row,
                          status: value
                      }
                    : row
            )
        );
    };

    const removeRow = (id) => {

        setRows(prev =>
            prev.filter(
                row => (row.id || row._id) !== id
            )
        );
    };

    const getParticipantName = (row) => {

        if (row.beneficiary) {
            return `${row.beneficiary.firstName || ""} ${row.beneficiary.lastName || ""}`.trim();
        }

        if (row.staff) {
            return (
                row.staff.name ||
                row.staff.fullName ||
                row.staff.email ||
                "-"
            );
        }

        if (row.board) {
            return (
                row.board.name ||
                row.board.fullName ||
                row.board.email ||
                "-"
            );
        }

        if (row.externalParticipant) {
            return row.externalParticipant.name || "-";
        }

        return "-";
    };

    const getOrganization = (row) => {

        if (!row.externalParticipant)
            return "-";

        return row.externalParticipant.organizationName || "-";
    };

    const getPosition = (row) => {

        if (!row.externalParticipant)
            return "-";

        return row.externalParticipant.position || "-";
    };

    const getPhone = (row) => {

        if (!row.externalParticipant)
            return "-";

        return row.externalParticipant.phone || "-";
    };

    const columns = [

        {
            field: "participant",
            headerName: "Participant",
            flex: 1.4,
            minWidth: 230,
            renderCell: ({ row }) => (
                <Typography sx={{
                    fontWeight: 600
                }}>
                    {getParticipantName(row)}
                </Typography>
            )
        },

        {
            field: "participantType",
            headerName: "Type",
            width: 150,
            renderCell: ({ row }) => (
                <Chip
                    label={row.participantType || "-"}
                    size="small"
                    color="primary"
                    variant="outlined"
                />
            )
        },

        {
            field: "organization",
            headerName: "Organization",
            flex: 1,
            minWidth: 170,
            renderCell: ({ row }) => (
                <Typography variant="body2">
                    {getOrganization(row)}
                </Typography>
            )
        },

        {
            field: "position",
            headerName: "Position",
            width: 150,
            renderCell: ({ row }) => (
                <Typography variant="body2">
                    {getPosition(row)}
                </Typography>
            )
        },

        {
            field: "phone",
            headerName: "Phone",
            width: 150,
            renderCell: ({ row }) => (
                <Typography variant="body2">
                    {getPhone(row)}
                </Typography>
            )
        },

        {
            field: "status",
            headerName: "Status",
            width: 170,
            renderCell: ({ row }) => (

                <Select
                    size="small"
                    fullWidth
                    value={row.status || "Present"}
                    onChange={(e) =>
                        updateStatus(
                            row.id || row._id,
                            e.target.value
                        )
                    }
                >
                    <MenuItem value="Present">
                        Present
                    </MenuItem>

                    <MenuItem value="Late">
                        Late
                    </MenuItem>

                    <MenuItem value="Absent">
                        Absent
                    </MenuItem>

                    <MenuItem value="Excused">
                        Excused
                    </MenuItem>
                </Select>
            )
        },

        {
            field: "notes",
            headerName: "Notes",
            flex: 1,
            minWidth: 180,
            renderCell: ({ row }) => (
                <Typography
                    variant="body2"
                    noWrap
                >
                    {row.notes || "-"}
                </Typography>
            )
        },

        {
            field: "actions",
            headerName: "Actions",
            width: 100,
            sortable: false,
            filterable: false,
            renderCell: ({ row }) => (

                <Tooltip title="Remove">

                    <IconButton
                        color="error"
                        onClick={() =>
                            removeRow(
                                row.id || row._id
                            )
                        }
                    >
                        <Delete />
                    </IconButton>

                </Tooltip>
            )
        }

    ];

    return (

        <Box
            sx={{
                height: 550,
                backgroundColor: "#fff",
                borderRadius: 2
            }}
        >

            <DataGrid
                rows={rows}
                columns={columns}
                getRowId={(row) =>
                    row.id || row._id
                }
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
                        fontWeight: 700
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

export default AttendanceGrid;