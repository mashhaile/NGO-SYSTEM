import {
    useEffect,
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
    useDispatch
} from "react-redux";


import {
    getLookupsByModuleAndCategoryService
} from "../../lookups/services/lookupService";


import {
    deleteEnterpriseThunk,
    getEnterprisesThunk
} from "../store/enterpriseThunks";


import {
    DataTable,
    StatusChip,
    AppIconButton,
    ConfirmDeleteDialog
} from "../../../components/ui";


// =====================================================
// HELPERS
// =====================================================

const normalizeArray = (
    response
) => {

    if (Array.isArray(response)) {
        return response;
    }


    if (Array.isArray(response?.data?.data)) {
        return response.data.data;
    }


    if (Array.isArray(response?.data?.rows)) {
        return response.data.rows;
    }


    if (Array.isArray(response?.data)) {
        return response.data;
    }


    if (Array.isArray(response?.rows)) {
        return response.rows;
    }


    return [];

};


// =====================================================
// LOOKUP VALUE
// =====================================================

const getLookupValue = (
    value,
    options = []
) => {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {

        return "-";

    }


    // ---------------------------------------------
    // Populated lookup object
    // ---------------------------------------------

    if (
        typeof value === "object"
    ) {

        return (
            value?.value ||
            value?.name ||
            value?.label ||
            value?.text ||
            value?.code ||
            "-"
        );

    }


    // ---------------------------------------------
    // Lookup ID
    // ---------------------------------------------

    const lookup =
        options.find(
            item =>
                String(
                    item?._id ||
                    item?.id
                ) ===
                String(value)
        );


    if (lookup) {

        return (
            lookup?.value ||
            lookup?.name ||
            lookup?.label ||
            lookup?.text ||
            lookup?.code ||
            "-"
        );

    }


    return String(value);

};


// =====================================================
// ENTERPRISE TABLE
// =====================================================

const EnterpriseTable = ({
    data = [],
    loading = false
}) => {

    const navigate =
        useNavigate();


    const dispatch =
        useDispatch();


    // =================================================
    // DELETE
    // =================================================

    const [
        deleteTarget,
        setDeleteTarget
    ] = useState(null);


    const [
        deleting,
        setDeleting
    ] = useState(false);


    // =================================================
    // LOOKUPS
    // =================================================

    const [
        lookups,
        setLookups
    ] = useState({

        enterpriseTypes: [],

        ownershipTypes: [],

        businessSectors: []

    });


    const [
        lookupLoading,
        setLookupLoading
    ] = useState(true);


    // =================================================
    // LOAD LOOKUPS
    // =================================================

    useEffect(
        () => {

            loadLookups();

        },
        []
    );


    const loadLookups = async () => {

        try {

            setLookupLoading(true);


            const [

                enterpriseTypeResponse,

                ownershipTypeResponse,

                businessSectorResponse

            ] = await Promise.all([

                getLookupsByModuleAndCategoryService(
                    "Enterprise",
                    "EnterpriseType"
                ),

                getLookupsByModuleAndCategoryService(
                    "Enterprise",
                    "OwnershipType"
                ),

                getLookupsByModuleAndCategoryService(
                    "Enterprise",
                    "BusinessSector"
                )

            ]);


            setLookups({

                enterpriseTypes:
                    normalizeArray(
                        enterpriseTypeResponse
                    ),

                ownershipTypes:
                    normalizeArray(
                        ownershipTypeResponse
                    ),

                businessSectors:
                    normalizeArray(
                        businessSectorResponse
                    )

            });

        }

        catch (error) {

            console.error(
                "Failed loading enterprise lookups:",
                error
            );

        }

        finally {

            setLookupLoading(false);

        }

    };


    // =================================================
    // DELETE
    // =================================================

    const handleDelete = async () => {

        if (
            !deleteTarget?._id
        ) {

            return;

        }


        try {

            setDeleting(true);


            await dispatch(
                deleteEnterpriseThunk(
                    deleteTarget._id
                )
            );


            await dispatch(
                getEnterprisesThunk({

                    page: 1,

                    limit: 10

                })
            );


            setDeleteTarget(null);

        }

        finally {

            setDeleting(false);

        }

    };


    // =================================================
    // COLUMNS
    // =================================================

    const columns = useMemo(
        () => [

            // -----------------------------------------
            // ENTERPRISE NUMBER
            // -----------------------------------------

            {
                field:
                    "enterpriseNumber",

                headerName:
                    "Enterprise Number",

                minWidth:
                    160,

                flex:
                    1
            },


            // -----------------------------------------
            // NAME
            // -----------------------------------------

            {
                field:
                    "name",

                headerName:
                    "Enterprise Name",

                minWidth:
                    180,

                flex:
                    1
            },


            // -----------------------------------------
            // ENTERPRISE TYPE
            // -----------------------------------------

            {
                field:
                    "enterpriseType",

                headerName:
                    "Enterprise Type",

                minWidth:
                    160,

                flex:
                    1,

                renderCell: (
                    params
                ) =>
                    getLookupValue(
                        params.row.enterpriseType,
                        lookups.enterpriseTypes
                    )
            },


            // -----------------------------------------
            // OWNERSHIP TYPE
            // -----------------------------------------

            {
                field:
                    "ownershipType",

                headerName:
                    "Ownership Type",

                minWidth:
                    160,

                flex:
                    1,

                renderCell: (
                    params
                ) =>
                    getLookupValue(
                        params.row.ownershipType,
                        lookups.ownershipTypes
                    )
            },


            // -----------------------------------------
            // BUSINESS SECTOR
            // -----------------------------------------

            {
                field:
                    "businessSector",

                headerName:
                    "Business Sector",

                minWidth:
                    160,

                flex:
                    1,

                renderCell: (
                    params
                ) =>
                    getLookupValue(
                        params.row.businessSector,
                        lookups.businessSectors
                    )
            },


            // -----------------------------------------
            // PHONE
            // -----------------------------------------

            {
                field:
                    "phone",

                headerName:
                    "Phone",

                minWidth:
                    140,

                flex:
                    1,

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
                field:
                    "status",

                headerName:
                    "Status",

                width:
                    120,

                renderCell: (
                    params
                ) => (

                    <StatusChip
                        status={
                            getLookupValue(
                                params.row.status,
                                []
                            ) ||
                            "Active"
                        }
                    />

                )
            },


            // -----------------------------------------
            // CREATED
            // -----------------------------------------

            {
                field:
                    "createdAt",

                headerName:
                    "Created",

                width:
                    130,

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


                    return date.toLocaleDateString();

                }
            },


            // -----------------------------------------
            // ACTIONS
            // -----------------------------------------

            {
                field:
                    "actions",

                headerName:
                    "Actions",

                width:
                    150,

                sortable:
                    false,

                filterable:
                    false,

                renderCell: (
                    params
                ) => {

                    const id =
                        params.row?._id ||
                        params.row?.id;


                    return (

                        <>

                            {/* VIEW */}

                            <AppIconButton

                                icon={
                                    <Visibility
                                        fontSize="small"
                                    />
                                }

                                tooltip="View enterprise"

                                size="small"

                                onClick={() =>
                                    navigate(
                                        `/enterprises/${id}`
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

                                tooltip="Edit enterprise"

                                size="small"

                                onClick={() =>
                                    navigate(
                                        `/enterprises/${id}/edit`
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

                                tooltip="Delete enterprise"

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
            navigate,
            lookups
        ]
    );


    // =================================================
    // ROWS
    // =================================================

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


    // =================================================
    // RENDER
    // =================================================

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
                    loading ||
                    lookupLoading
                }

                getRowId={
                    row =>
                        row?._id ||
                        row?.id
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

                title="Delete Enterprise"

                message={
                    deleteTarget

                        ? `Are you sure you want to delete ${deleteTarget.name || "this enterprise"}? This action cannot be undone.`

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


export default EnterpriseTable;