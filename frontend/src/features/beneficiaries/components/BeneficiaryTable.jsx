import {
    useCallback,
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
    deleteBeneficiaryThunk,
    getBeneficiariesThunk
} from "../store";

import {
    DataTable,
    StatusChip,
    AppIconButton,
    ConfirmDeleteDialog
} from "../../../components/ui";


// =====================================================
// HELPERS
// =====================================================

const normalizeArray = (response) => {

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
// LOOKUP DISPLAY VALUE
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


    // -------------------------------------------------
    // Populated Lookup object
    // -------------------------------------------------

    if (
        typeof value === "object" &&
        !Array.isArray(value)
    ) {

        return (
            value?.value ??
            value?.name ??
            value?.label ??
            value?.text ??
            value?.code ??
            "-"
        );

    }


    // -------------------------------------------------
    // Lookup ID
    // -------------------------------------------------

    const lookup = options.find(
        item =>
            String(
                item?._id ??
                item?.id
            ) === String(value)
    );


    if (lookup) {

        return (
            lookup?.value ??
            lookup?.name ??
            lookup?.label ??
            lookup?.text ??
            lookup?.code ??
            "-"
        );

    }


    // -------------------------------------------------
    // Backend may already return a display value
    // -------------------------------------------------

    return String(value);

};


// =====================================================
// DISPLAY VALUE
// =====================================================

const displayValue = (value) => {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return "-";
    }

    return String(value);

};


// =====================================================
// BENEFICIARY TABLE
// =====================================================

const BeneficiaryTable = ({
    data = [],
    loading = false
}) => {

    const navigate = useNavigate();

    const dispatch = useDispatch();


    // =================================================
    // DELETE STATE
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
    // LOOKUP STATE
    // =================================================

    const [
        lookups,
        setLookups
    ] = useState({

        genders: [],

        educationLevels: [],

        occupations: []

    });

    const [
        lookupLoading,
        setLookupLoading
    ] = useState(true);


    // =================================================
    // LOAD LOOKUPS
    // =================================================

    const loadLookups = useCallback(
        async () => {

            try {

                setLookupLoading(true);


                const [
                    genderResponse,
                    educationResponse,
                    occupationResponse
                ] = await Promise.all([

                    getLookupsByModuleAndCategoryService(
                        "Beneficiary",
                        "Gender"
                    ),

                    getLookupsByModuleAndCategoryService(
                        "Beneficiary",
                        "EducationLevel"
                    ),

                    getLookupsByModuleAndCategoryService(
                        "Beneficiary",
                        "Occupation"
                    )

                ]);


                setLookups({

                    genders:
                        normalizeArray(
                            genderResponse
                        ),

                    educationLevels:
                        normalizeArray(
                            educationResponse
                        ),

                    occupations:
                        normalizeArray(
                            occupationResponse
                        )

                });

            }

            catch (error) {

                console.error(
                    "Failed loading beneficiary lookups:",
                    error
                );


                // Keep the table usable even if
                // lookup loading fails.

                setLookups({

                    genders: [],

                    educationLevels: [],

                    occupations: []

                });

            }

            finally {

                setLookupLoading(false);

            }

        },
        []
    );


    // =================================================
    // LOAD LOOKUPS ON MOUNT
    // =================================================

    useEffect(
        () => {

            loadLookups();

        },
        [
            loadLookups
        ]
    );


    // =================================================
    // DELETE
    // =================================================

    const handleDelete = async () => {

        const beneficiaryId =
            deleteTarget?._id ||
            deleteTarget?.id;


        if (!beneficiaryId) {
            return;
        }


        try {

            setDeleting(true);


            const result =
                await dispatch(
                    deleteBeneficiaryThunk(
                        beneficiaryId
                    )
                );


            // -------------------------------------------------
            // If Redux Toolkit thunk is rejected, this will
            // throw and the dialog will remain open.
            // -------------------------------------------------

            if (
                result?.meta?.requestStatus ===
                "rejected"
            ) {

                throw (
                    result?.error ||
                    new Error(
                        "Failed to delete beneficiary."
                    )
                );

            }


            // -------------------------------------------------
            // Refresh first page after deletion.
            // -------------------------------------------------

            await dispatch(
                getBeneficiariesThunk({

                    page: 1,

                    limit: 10

                })
            );


            setDeleteTarget(null);

        }

        catch (error) {

            console.error(
                "Failed deleting beneficiary:",
                error
            );

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

            // =============================================
            // BENEFICIARY NUMBER
            // =============================================

            {
                field: "beneficiaryNumber",

                headerName: "Number",

                minWidth: 150,

                flex: 1,

                renderCell: (params) =>
                    displayValue(
                        params.value
                    )

            },


            // =============================================
            // FIRST NAME
            // =============================================

            {
                field: "firstName",

                headerName: "First Name",

                minWidth: 140,

                flex: 1,

                renderCell: (params) =>
                    displayValue(
                        params.value
                    )

            },


            // =============================================
            // MIDDLE NAME
            // =============================================

            {
                field: "middleName",

                headerName: "Middle Name",

                minWidth: 140,

                flex: 1,

                renderCell: (params) =>
                    displayValue(
                        params.value
                    )

            },


            // =============================================
            // LAST NAME
            // =============================================

            {
                field: "lastName",

                headerName: "Last Name",

                minWidth: 140,

                flex: 1,

                renderCell: (params) =>
                    displayValue(
                        params.value
                    )

            },


            // =============================================
            // GENDER
            // =============================================

            {
                field: "gender",

                headerName: "Gender",

                minWidth: 110,

                flex: 1,

                renderCell: (params) =>
                    getLookupValue(
                        params.row.gender,
                        lookups.genders
                    )

            },


            // =============================================
            // AGE
            // =============================================
            //
            // IMPORTANT:
            //
            // Age is READ-ONLY.
            //
            // It is calculated by the backend from
            // dateOfBirth.
            //
            // This table does NOT calculate or edit age.
            //
            // =============================================

            {
                field: "age",

                headerName: "Age",

                width: 80,

                sortable: true,

                renderCell: (params) => {

                    const age =
                        params.row?.age;

                    if (
                        age === null ||
                        age === undefined ||
                        age === ""
                    ) {
                        return "-";
                    }

                    return String(age);

                }

            },


            // =============================================
            // PHONE
            // =============================================

            {
                field: "phone",

                headerName: "Phone",

                minWidth: 140,

                flex: 1,

                renderCell: (params) =>
                    displayValue(
                        params.value
                    )

            },


            // =============================================
            // REGION
            // =============================================

            {
                field: "region",

                headerName: "Region",

                minWidth: 120,

                flex: 1,

                renderCell: (params) =>
                    displayValue(
                        params.value
                    )

            },


            // =============================================
            // EDUCATION
            // =============================================

            {
                field: "educationLevel",

                headerName: "Education",

                minWidth: 140,

                flex: 1,

                renderCell: (params) =>
                    getLookupValue(
                        params.row.educationLevel,
                        lookups.educationLevels
                    )

            },


            // =============================================
            // OCCUPATION
            // =============================================

            {
                field: "occupation",

                headerName: "Occupation",

                minWidth: 150,

                flex: 1,

                renderCell: (params) =>
                    getLookupValue(
                        params.row.occupation,
                        lookups.occupations
                    )

            },


            // =============================================
            // STATUS
            // =============================================

            {
                field: "status",

                headerName: "Status",

                width: 120,

                renderCell: (params) => (

                    <StatusChip
                        status={
                            params.value ||
                            "Inactive"
                        }
                    />

                )

            },


            // =============================================
            // CREATED
            // =============================================

            {
                field: "createdAt",

                headerName: "Created",

                width: 130,

                renderCell: (params) => {

                    if (!params.value) {
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


            // =============================================
            // ACTIONS
            // =============================================

            {
                field: "actions",

                headerName: "Actions",

                width: 150,

                sortable: false,

                filterable: false,

                disableColumnMenu: true,

                renderCell: (params) => {

                    const id =
                        params.row?._id ||
                        params.row?.id;


                    if (!id) {
                        return null;
                    }


                    return (

                        <>

                            {/* =================================
                                VIEW
                            ================================= */}

                            <AppIconButton
                                icon={
                                    <Visibility
                                        fontSize="small"
                                    />
                                }

                                tooltip="View beneficiary"

                                size="small"

                                onClick={() =>
                                    navigate(
                                        `/beneficiaries/${id}`
                                    )
                                }
                            />


                            {/* =================================
                                EDIT
                            ================================= */}

                            <AppIconButton
                                icon={
                                    <Edit
                                        fontSize="small"
                                    />
                                }

                                tooltip="Edit beneficiary"

                                size="small"

                                onClick={() =>
                                    navigate(
                                        `/beneficiaries/${id}/edit`
                                    )
                                }
                            />


                            {/* =================================
                                DELETE
                            ================================= */}

                            <AppIconButton
                                icon={
                                    <Delete
                                        fontSize="small"
                                    />
                                }

                                tooltip="Delete beneficiary"

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

    const rows = useMemo(
        () => {

            if (!Array.isArray(data)) {
                return [];
            }


            return data.map(
                item => ({

                    ...item,

                    id:
                        item?._id ||
                        item?.id

                })
            );

        },
        [
            data
        ]
    );


    // =================================================
    // RENDER
    // =================================================

    return (

        <>

            <DataTable
                rows={rows}

                columns={columns}

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

                title="Delete Beneficiary"

                message={
                    deleteTarget

                        ? `Are you sure you want to delete ${deleteTarget.firstName || ""} ${deleteTarget.lastName || ""}? This action cannot be undone.`

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


export default BeneficiaryTable;
