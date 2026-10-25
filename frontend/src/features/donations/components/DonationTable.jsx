import {
    useMemo,
    useState
} from "react";

import {
    useNavigate
} from "react-router-dom";

import {
    Visibility,
    Edit,
    Delete
} from "@mui/icons-material";

import {
    useDeleteDonation
} from "../hooks/useDonations";

import {
    DataTable,
    StatusChip,
    AppIconButton,
    ConfirmDeleteDialog
} from "../../../components/ui";
import { formatDate } from "../../../utils/date";


// =====================================================
// DONATION TABLE
// =====================================================

const DonationTable = ({
    data = [],
    loading = false
}) => {

    const navigate =
        useNavigate();


    // =====================================================
    // DELETE
    // =====================================================

    const deleteMutation =
        useDeleteDonation();

    const [
        deleteTarget,
        setDeleteTarget
    ] = useState(null);


    // =====================================================
    // COLUMNS
    // =====================================================

    const columns = useMemo(
        () => [

            // -----------------------------------------
            // DONATION CODE
            // -----------------------------------------

            {
                field: "donationCode",

                headerName: "Number",

                minWidth: 150,

                flex: 1,

                renderCell: (
                    params
                ) =>
                    params.value ||
                    "-"
            },


            // -----------------------------------------
            // TITLE
            // -----------------------------------------

            {
                field: "title",

                headerName: "Title",

                minWidth: 180,

                flex: 1.3,

                renderCell: (
                    params
                ) =>
                    params.value ||
                    "-"
            },


            // -----------------------------------------
            // DONOR
            // -----------------------------------------

            {
                field: "donor",

                headerName: "Donor",

                minWidth: 160,

                flex: 1,

                renderCell: (
                    params
                ) =>
                    params.row?.donor?.name ||
                    params.row?.donorName ||
                    "-"
            },


            // -----------------------------------------
            // ALLOCATION
            // -----------------------------------------

            {
                field: "allocation",

                headerName: "Allocation",

                minWidth: 220,

                flex: 1.5,

                renderCell: (
                    params
                ) => {

                    const donation =
                        params.row;


                    if (
                        donation?.activityRun
                    ) {

                        return (
                            donation
                                ?.activityRun
                                ?.name ||
                            donation
                                ?.activityRun
                                ?.runCode ||
                            "Activity Run"
                        );

                    }


                    if (
                        donation?.activity
                    ) {

                        return (
                            donation
                                ?.activity
                                ?.name ||
                            donation
                                ?.activity
                                ?.activityCode ||
                            "Activity"
                        );

                    }


                    if (
                        donation?.project
                    ) {

                        return (
                            donation
                                ?.project
                                ?.name ||
                            donation
                                ?.project
                                ?.projectCode ||
                            "Project"
                        );

                    }


                    if (
                        donation?.program
                    ) {

                        return (
                            donation
                                ?.program
                                ?.name ||
                            donation
                                ?.program
                                ?.programCode ||
                            "Program"
                        );

                    }


                    return "General";

                }

            },


            // -----------------------------------------
            // AMOUNT
            // -----------------------------------------

            {
                field: "amount",

                headerName: "Amount",

                minWidth: 120,

                flex: 0.8,

                renderCell: (
                    params
                ) =>
                    params.value ??
                    "-"
            },


            // -----------------------------------------
            // CURRENCY
            // -----------------------------------------

            {
                field: "currency",

                headerName: "Currency",

                width: 100,

                renderCell: (
                    params
                ) =>
                    params.value ||
                    "-"
            },


            // -----------------------------------------
            // DONATION DATE
            // -----------------------------------------

            {
                field: "donationDate",

                headerName: "Donation Date",

                minWidth: 140,

                flex: 1,

                renderCell: (
                    params
                ) => {

                    if (
                        !params.value
                    ) {
                        return "-";
                    }


                    const date =
                        new Date(
                            params.value
                        );


                    if (
                        Number.isNaN(
                            date.getTime()
                        )
                    ) {
                        return "-";
                    }


                    return formatDate(date);

                }

            },


            // -----------------------------------------
            // TYPE
            // -----------------------------------------

            {
                field: "donationType",

                headerName: "Type",

                minWidth: 130,

                flex: 1,

                renderCell: (
                    params
                ) =>
                    params.value ||
                    "-"
            },


            // -----------------------------------------
            // STATUS
            // -----------------------------------------

            {
                field: "status",

                headerName: "Status",

                width: 120,

                renderCell: (
                    params
                ) => (

                    <StatusChip
                        status={
                            params.value ||
                            "Unknown"
                        }
                    />

                )

            },


            // -----------------------------------------
            // ACTIONS
            // -----------------------------------------

            {
                field: "actions",

                headerName: "Actions",

                width: 150,

                sortable: false,

                filterable: false,

                renderCell: (
                    params
                ) => {

                    const id =
                        params.row?._id ||
                        params.row?.id;


                    return (

                        <>

                            <AppIconButton

                                icon={
                                    <Visibility
                                        fontSize="small"
                                    />
                                }

                                tooltip="View donation"

                                size="small"

                                onClick={() =>
                                    navigate(
                                        `/donations/${id}`
                                    )
                                }

                            />


                            <AppIconButton

                                icon={
                                    <Edit
                                        fontSize="small"
                                    />
                                }

                                tooltip="Edit donation"

                                size="small"

                                onClick={() =>
                                    navigate(
                                        `/donations/${id}/edit`
                                    )
                                }

                            />


                            <AppIconButton

                                icon={
                                    <Delete
                                        fontSize="small"
                                    />
                                }

                                tooltip="Delete donation"

                                size="small"

                                color="error"

                                onClick={() =>
                                    setDeleteTarget(
                                        params.row
                                    )
                                }

                            />

                        </>

                    );

                }

            }

        ],
        [
            navigate
        ]
    );


    // =====================================================
    // DELETE
    // =====================================================

    const handleDelete = async () => {

        if (
            !deleteTarget?._id &&
            !deleteTarget?.id
        ) {
            return;
        }


        const id =
            deleteTarget._id ||
            deleteTarget.id;


        try {

            await deleteMutation.mutateAsync(
                id
            );

            setDeleteTarget(
                null
            );

        }

        catch (error) {

            console.error(
                "Failed to delete donation:",
                error
            );

        }

    };


    // =====================================================
    // ROWS
    // =====================================================

    const rows =
        Array.isArray(data)
            ? data.map(
                item => ({

                    ...item,

                    id:
                        item?._id ||
                        item?.id

                })
            )
            : [];


    // =====================================================
    // RENDER
    // =====================================================

    return (

        <>

            <DataTable

                rows={
                    rows
                }

                columns={
                    columns
                }

                loading={
                    loading
                }

                getRowId={
                    row =>
                        row._id ||
                        row.id
                }

            />


            <ConfirmDeleteDialog

                open={
                    Boolean(
                        deleteTarget
                    )
                }

                title="Delete Donation"

                message={
                    deleteTarget

                        ? `Are you sure you want to delete ${deleteTarget.title || "this donation"}? This action cannot be undone.`

                        : ""
                }

                loading={
                    deleteMutation.isPending
                }

                onConfirm={
                    handleDelete
                }

                onClose={() =>
                    !deleteMutation.isPending &&
                    setDeleteTarget(
                        null
                    )
                }

            />

        </>

    );

};


export default DonationTable;