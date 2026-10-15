import {
    useState
} from "react";

import {
    useNavigate
} from "react-router-dom";

import {
    useDispatch
} from "react-redux";

import {
    Visibility,
    Edit,
    Delete
} from "@mui/icons-material";

import {
    deleteProgramThunk,
    getProgramsThunk
} from "../store";

import {
    DataTable,
    StatusChip,
    AppIconButton,
    ConfirmDeleteDialog
} from "../../../components/ui";


// =====================================================
// PROGRAM TABLE
// =====================================================

const ProgramTable = ({
    data = [],
    loading = false
}) => {

    const navigate = useNavigate();

    const dispatch = useDispatch();


    // =====================================================
    // DELETE STATE
    // =====================================================

    const [
        deleteTarget,
        setDeleteTarget
    ] = useState(null);

    const [
        deleting,
        setDeleting
    ] = useState(false);


    // =====================================================
    // DELETE PROGRAM
    // =====================================================

    const handleDelete = async () => {

        if (!deleteTarget?._id) {
            return;
        }


        try {

            setDeleting(true);


            const result = await dispatch(
                deleteProgramThunk(
                    deleteTarget._id
                )
            );


            if (
                deleteProgramThunk.fulfilled.match(
                    result
                )
            ) {

                /*
                 * Reload programs after deletion.
                 * This keeps pagination/list data
                 * synchronized with the backend.
                 */

                await dispatch(
                    getProgramsThunk({
                        search: "",
                        page: 1,
                        limit: 10
                    })
                );


                setDeleteTarget(null);

            }


            if (
                deleteProgramThunk.rejected.match(
                    result
                )
            ) {

                console.error(
                    "DELETE PROGRAM ERROR:",
                    result.payload ||
                    result.error
                );

            }

        } catch (error) {

            console.error(
                "DELETE PROGRAM ERROR:",
                error
            );

        } finally {

            setDeleting(false);

        }

    };


    // =====================================================
    // FORMAT DATE
    // =====================================================

    const formatDate = (value) => {

        if (!value) {
            return "-";
        }


        const date =
            new Date(value);


        if (
            Number.isNaN(
                date.getTime()
            )
        ) {

            return "-";

        }


        return date.toLocaleDateString();

    };


    // =====================================================
    // FORMAT NUMBER
    // =====================================================

    const formatNumber = (value) => {

        if (
            value === null ||
            value === undefined ||
            value === ""
        ) {

            return "-";

        }


        const number =
            Number(value);


        if (
            Number.isNaN(number)
        ) {

            return "-";

        }


        return number.toLocaleString();

    };


    // =====================================================
    // COLUMNS
    // =====================================================

    const columns = [

        {
            field: "programCode",

            headerName: "Code",

            minWidth: 140,

            flex: 1
        },


        {
            field: "name",

            headerName: "Program Name",

            minWidth: 200,

            flex: 1.5,

            renderCell: (params) =>
                params.value || "-"
        },


        {
            field: "category",

            headerName: "Category",

            minWidth: 140,

            flex: 1,

            renderCell: (params) =>
                params.value || "-"
        },


        {
            field: "status",

            headerName: "Status",

            width: 110,

            renderCell: (params) => (

                <StatusChip
                    status={
                        params.value ||
                        "Planned"
                    }
                />

            )
        },


        {
            field: "startDate",

            headerName: "Start Date",

            width: 110,

            renderCell: (params) =>
                formatDate(
                    params.value
                )
        },


        {
            field: "endDate",

            headerName: "End Date",

            width: 110,

            renderCell: (params) =>
                formatDate(
                    params.value
                )
        },


        {
            field: "budget",

            headerName: "Budget",

            width: 110,

            align: "right",

            headerAlign: "right",

            renderCell: (params) =>
                formatNumber(
                    params.value
                )
        },


        {
            field: "targetBeneficiaries",

            headerName: "Target",

            width: 110,

            align: "right",

            headerAlign: "right",

            renderCell: (params) =>
                formatNumber(
                    params.value
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

            renderCell: (params) => {

                const id =
                    params.row._id ||
                    params.row.id;


                return (

                    <>

                        {/* VIEW */}

                        <AppIconButton
                            icon={
                                <Visibility
                                    fontSize="small"
                                />
                            }

                            tooltip="View program"

                            size="small"

                            onClick={() =>
                                navigate(
                                    `/programs/${id}`
                                )
                            }
                        />


                        {/* EDIT */}

                        <AppIconButton
                            icon={
                                <Edit
                                    fontSize="small"
                                />
                            }

                            tooltip="Edit program"

                            size="small"

                            onClick={() =>
                                navigate(
                                    `/programs/${id}/edit`
                                )
                            }
                        />


                        {/* DELETE */}

                        <AppIconButton
                            icon={
                                <Delete
                                    fontSize="small"
                                />
                            }

                            tooltip="Delete program"

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

    ];


    // =====================================================
    // ROWS
    // =====================================================

    const rows = Array.isArray(data)

        ? data.map(
            (item) => ({
                ...item,
                id:
                    item._id ||
                    item.id
            })
        )

        : [];


    // =====================================================
    // RENDER
    // =====================================================

    return (

        <>

            <DataTable

                rows={rows}

                columns={columns}

                loading={loading}

                getRowId={(row) =>
                    row._id ||
                    row.id
                }

            />


            {/* =================================================
                DELETE CONFIRMATION
            ================================================= */}

            <ConfirmDeleteDialog

                open={
                    Boolean(deleteTarget)
                }

                title="Delete Program"

                message={
                    deleteTarget
                        ? `Are you sure you want to delete "${deleteTarget.name || "this program"}"? This action cannot be undone.`
                        : ""
                }

                loading={deleting}

                onConfirm={
                    handleDelete
                }

                onClose={() =>
                    !deleting &&
                    setDeleteTarget(null)
                }

            />

        </>

    );

};


export default ProgramTable;