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
    deleteProjectThunk
} from "../store/projectThunks";


import {
    DataTable,
    StatusChip,
    AppIconButton,
    ConfirmDeleteDialog
} from "../../../components/ui";



const ProjectTable = ({
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
    // DELETE
    // =====================================================

    const handleDelete = async () => {

        if (!deleteTarget?._id) {
            return;
        }


        try {

            setDeleting(true);


            const result = await dispatch(
                deleteProjectThunk(
                    deleteTarget._id
                )
            );


            if (
                deleteProjectThunk.fulfilled.match(
                    result
                )
            ) {

                setDeleteTarget(null);

            }

        }

        catch (error) {

            console.error(
                "DELETE PROJECT ERROR:",
                error
            );

        }

        finally {

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


        const date = new Date(value);


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
    // FORMAT BUDGET
    // =====================================================

    const formatBudget = (value) => {

        if (
            value === null ||
            value === undefined ||
            value === ""
        ) {

            return "-";

        }


        const number = Number(value);


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
            field: "projectCode",

            headerName: "Code",

            minWidth: 150,

            flex: 0.8
        },


        {
            field: "name",

            headerName: "Project Name",

            minWidth: 220,

            flex: 1.5
        },


        {
            field: "program",

            headerName: "Program",

            minWidth: 220,

            flex: 1.3,

            renderCell: (params) => {

                const program =
                    params.row.program;


                if (!program) {
                    return "-";
                }


                if (
                    typeof program === "string"
                ) {

                    return program;

                }


                return (
                    program.programCode
                        ? `${program.programCode} - ${
                            program.name || ""
                        }`
                        : program.name || "-"
                );

            }
        },


        {
            field: "donor",

            headerName: "Donor",

            minWidth: 160,

            flex: 1,

            renderCell: (params) => {

                const donor =
                    params.row.donor;


                if (!donor) {
                    return "-";
                }


                if (
                    typeof donor === "string"
                ) {

                    return donor;

                }


                return (
                    donor.name ||
                    donor.value ||
                    "-"
                );

            }
        },


        {
            field: "projectManager",

            headerName: "Project Manager",

            minWidth: 170,

            flex: 1,

            renderCell: (params) => {

                const manager =
                    params.row.projectManager;


                if (!manager) {
                    return "-";
                }


                if (
                    typeof manager === "string"
                ) {

                    return manager;

                }


                return (
                    manager.name ||
                    manager.fullName ||
                    manager.username ||
                    "-"
                );

            }
        },


        {
            field: "approvedBudget",

            headerName: "Budget",

            width: 150,

            align: "right",

            headerAlign: "right",

            renderCell: (params) =>
                formatBudget(
                    params.value
                )
        },


        {
            field: "startDate",

            headerName: "Start Date",

            width: 140,

            renderCell: (params) =>
                formatDate(
                    params.value
                )
        },


        {
            field: "endDate",

            headerName: "End Date",

            width: 140,

            renderCell: (params) =>
                formatDate(
                    params.value
                )
        },


        {
            field: "status",

            headerName: "Status",

            width: 130,

            renderCell: (params) => (

                <StatusChip
                    status={
                        params.value ||
                        "Draft"
                    }
                />

            )
        },


        {
            field: "actions",

            headerName: "Actions",

            width: 150,

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
                            tooltip="View project"
                            size="small"
                            onClick={() =>
                                navigate(
                                    `/projects/${id}`
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
                            tooltip="Edit project"
                            size="small"
                            onClick={() =>
                                navigate(
                                    `/projects/${id}/edit`
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
                            tooltip="Delete project"
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
        ? data.map((item) => ({
            ...item,
            id: item._id || item.id
        }))
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
                    Boolean(
                        deleteTarget
                    )
                }

                title="Delete Project"

                message={
                    deleteTarget
                        ? `Are you sure you want to delete "${deleteTarget.name || "this project"}"? This action cannot be undone.`
                        : ""
                }

                loading={
                    deleting
                }

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


export default ProjectTable;