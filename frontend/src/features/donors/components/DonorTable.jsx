import {
    Box,
    IconButton,
    Chip,
    Tooltip
} from "@mui/material";


import {
    Visibility,
    Edit,
    Delete
} from "@mui/icons-material";


import {
    useNavigate
} from "react-router-dom";


import {
    useDeleteDonor
} from "../hooks/useDonors";


import {
    DataTable,
    EmptyState
} from "../../../components/ui";


// =====================================================
// DONOR TABLE
// =====================================================

const DonorTable = ({

    data = [],

    loading = false

}) => {


    const navigate =
        useNavigate();


    const deleteMutation =
        useDeleteDonor();


    // =================================================
    // DELETE
    // =================================================

    const remove = (id) => {


        const confirmed =
            window.confirm(
                "Are you sure you want to delete this donor?"
            );


        if (!confirmed) {
            return;
        }


        deleteMutation.mutate(id);

    };


    // =================================================
    // EMPTY STATE
    // =================================================

    if (
        !loading &&
        data.length === 0
    ) {

        return (

            <EmptyState

                title="No Donors Found"

                message="Create your first donor record."

            />

        );

    }


    // =================================================
    // COLUMNS
    // =================================================

    const columns = [

        {
            field: "name",

            headerName: "Donor Name",

            flex: 1,

            minWidth: 220
        },


        {
            field: "donorType",

            headerName: "Type",

            width: 150
        },


        {
            field: "country",

            headerName: "Country",

            width: 150,

            renderCell: (params) =>
                params.value || "-"
        },


        {
            field: "email",

            headerName: "Email",

            width: 230,

            renderCell: (params) =>
                params.value || "-"
        },


        {
            field: "phone",

            headerName: "Phone",

            width: 160,

            renderCell: (params) =>
                params.value || "-"
        },


        {
            field: "contactPerson",

            headerName: "Contact Person",

            width: 180,

            renderCell: (params) =>
                params.value || "-"
        },


        {
            field: "status",

            headerName: "Status",

            width: 130,

            renderCell: (params) => (

                <Chip

                    size="small"

                    label={
                        params.value ||
                        "Active"
                    }

                    color={
                        params.value === "Active"
                            ? "success"
                            : "default"
                    }

                />

            )
        },


        {
            field: "createdAt",

            headerName: "Created Date",

            width: 150,

            renderCell: (params) => (

                params.value

                    ? new Date(
                        params.value
                    ).toLocaleDateString()

                    : "-"

            )
        },


        // =================================================
        // ACTIONS
        // =================================================

        {
            field: "actions",

            headerName: "Actions",

            width: 160,

            sortable: false,

            filterable: false,

            renderCell: (params) => (

                <Box>

                    <Tooltip title="View">

                        <IconButton

                            onClick={() =>
                                navigate(
                                    `/donors/${params.row._id}`
                                )
                            }

                        >

                            <Visibility />

                        </IconButton>

                    </Tooltip>


                    <Tooltip title="Edit">

                        <IconButton

                            onClick={() =>
                                navigate(
                                    `/donors/${params.row._id}/edit`
                                )
                            }

                        >

                            <Edit />

                        </IconButton>

                    </Tooltip>


                    <Tooltip title="Delete">

                        <IconButton

                            color="error"

                            disabled={
                                deleteMutation.isPending
                            }

                            onClick={() =>
                                remove(
                                    params.row._id
                                )
                            }

                        >

                            <Delete />

                        </IconButton>

                    </Tooltip>

                </Box>

            )

        }

    ];


    // =================================================
    // RENDER
    // =================================================

    return (

        <DataTable

            rows={data}

            columns={columns}

            loading={loading}

            getRowId={(row) =>
                row._id
            }

        />

    );

};


export default DonorTable;