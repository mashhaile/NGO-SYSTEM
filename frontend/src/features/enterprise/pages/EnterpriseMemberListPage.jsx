import {
    useEffect
} from "react";


import {
    useDispatch,
    useSelector
} from "react-redux";


import {
    useNavigate
} from "react-router-dom";


import {
    Add,
    Edit,
    Delete,
    Visibility
} from "@mui/icons-material";


import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    AppButton,
    AppIconButton,
    StatusChip,
    DataTable,
    ErrorState,
    AppPagination
} from "../../../components/ui";


import {
    getEnterpriseMembersThunk,
    deleteEnterpriseMemberThunk
} from "../store/enterpriseMemberThunks";


import {
    clearEnterpriseMemberMessage
} from "../store/enterpriseMemberSlice";


// =====================================================
// LOOKUP DISPLAY
// =====================================================

const getLookupLabel = (
    lookup,
    fallback = "-"
) => {

    if (
        lookup === null ||
        lookup === undefined ||
        lookup === ""
    ) {

        return fallback;

    }


    if (
        typeof lookup === "object"
    ) {

        return (
            lookup.value ||
            lookup.label ||
            lookup.name ||
            lookup.code ||
            fallback
        );

    }


    return String(
        lookup
    );

};


// =====================================================
// BENEFICIARY NAME
// =====================================================

const getBeneficiaryName = (
    beneficiary
) => {

    if (!beneficiary) {

        return "Unknown Beneficiary";

    }


    if (
        typeof beneficiary !== "object"
    ) {

        return String(
            beneficiary
        );

    }


    const fullName = [

        beneficiary.firstName,
        beneficiary.middleName,
        beneficiary.lastName

    ]
        .filter(Boolean)
        .join(" ");


    return (

        fullName ||
        beneficiary.beneficiaryNumber ||
        beneficiary.phone ||
        beneficiary.email ||
        "Unknown Beneficiary"

    );

};


// =====================================================
// ENTERPRISE NAME
// =====================================================

const getEnterpriseName = (
    enterprise
) => {

    if (!enterprise) {

        return "Unknown Enterprise";

    }


    if (
        typeof enterprise !== "object"
    ) {

        return String(
            enterprise
        );

    }


    return (

        enterprise.name ||
        enterprise.enterpriseName ||
        enterprise.businessName ||
        enterprise.enterpriseNumber ||
        enterprise.registrationNumber ||
        "Unknown Enterprise"

    );

};


// =====================================================
// DATE DISPLAY
// =====================================================

const getDateValue = (
    value
) => {

    if (!value) {

        return "—";

    }


    const date =
        new Date(value);


    if (
        Number.isNaN(
            date.getTime()
        )
    ) {

        return "—";

    }


    return date.toLocaleDateString();

};


// =====================================================
// ENTERPRISE MEMBER LIST PAGE
// =====================================================

const EnterpriseMemberListPage = () => {

    const dispatch =
        useDispatch();


    const navigate =
        useNavigate();


    // =================================================
    // REDUX
    // =================================================

    const {

        members = [],

        pagination = {
            page: 1,
            limit: 10,
            totalRecords: 0,
            totalActive: 0,
            totalInactive: 0,
            totalPages: 0
        },

        loading = false,

        actionLoading = false,

        error = null,

        successMessage = null

    } = useSelector(
        state =>
            state.enterpriseMembers || {}
    );


    // =================================================
    // LOAD MEMBERS
    // =================================================

    useEffect(() => {

        dispatch(
            getEnterpriseMembersThunk({
                page: 1,
                limit: 10
            })
        );

    }, [
        dispatch
    ]);


    // =================================================
    // CLEAR SUCCESS MESSAGE
    // =================================================

    useEffect(() => {

        if (!successMessage) {

            return;

        }


        const timer =
            setTimeout(() => {

                dispatch(
                    clearEnterpriseMemberMessage()
                );

            }, 3000);


        return () =>
            clearTimeout(timer);

    }, [
        successMessage,
        dispatch
    ]);


    // =================================================
    // SAFE MEMBERS
    // =================================================

    const memberList =
        Array.isArray(members)
            ? members
            : [];


    // =================================================
    // PAGINATION
    // =================================================

    const totalPages =
        Number(
            pagination?.totalPages || 0
        );


    const currentPage =
        Number(
            pagination?.page || 1
        );


    const totalRecords =
        Number(
            pagination?.totalRecords || 0
        );


    const totalActive =
        Number(
            pagination?.totalActive || 0
        );


    const totalInactive =
        Number(
            pagination?.totalInactive || 0
        );


    const pageSize =
        Number(
            pagination?.limit || 10
        );


    // =================================================
    // PAGE CHANGE
    // =================================================

    const handlePageChange = (
        page
    ) => {

        if (
            page < 1 ||
            (
                totalPages > 0 &&
                page > totalPages
            )
        ) {

            return;

        }


        dispatch(
            getEnterpriseMembersThunk({
                page,
                limit: pageSize
            })
        );

    };


    // =================================================
    // DELETE
    // =================================================

    const handleDelete = async (
        memberId
    ) => {

        if (!memberId) {

            return;

        }


        const confirmed =
            window.confirm(
                "Are you sure you want to remove this beneficiary from the enterprise?"
            );


        if (!confirmed) {

            return;

        }


        const result =
            await dispatch(
                deleteEnterpriseMemberThunk(
                    memberId
                )
            );


        if (
            deleteEnterpriseMemberThunk.fulfilled.match(
                result
            )
        ) {

            dispatch(
                getEnterpriseMembersThunk({
                    page: currentPage,
                    limit: pageSize
                })
            );

        }

    };


    // =================================================
    // TABLE COLUMNS
    // =================================================

    const columns = [

        {
            field: "beneficiaryName",
            headerName: "Beneficiary",
            flex: 1,
            minWidth: 180,

            valueGetter: (
                value,
                row
            ) =>
                getBeneficiaryName(
                    row?.beneficiary
                )
        },


        {
            field: "beneficiaryNumber",
            headerName: "Beneficiary Number",
            flex: 1,
            minWidth: 160,

            valueGetter: (
                value,
                row
            ) =>
                row?.beneficiary?.beneficiaryNumber ||
                "-"
        },


        {
            field: "enterpriseName",
            headerName: "Enterprise",
            flex: 1,
            minWidth: 180,

            valueGetter: (
                value,
                row
            ) =>
                getEnterpriseName(
                    row?.enterprise
                )
        },


        {
            field: "enterpriseNumber",
            headerName: "Enterprise Number",
            flex: 1,
            minWidth: 150,

            valueGetter: (
                value,
                row
            ) =>
                row?.enterprise?.enterpriseNumber ||
                "-"
        },


        {
            field: "memberRole",
            headerName: "Member Role",
            flex: 1,
            minWidth: 130,

            valueGetter: (
                value,
                row
            ) =>
                getLookupLabel(
                    row?.memberRole,
                    "Member"
                )
        },


        {
            field: "joinedDate",
            headerName: "Joined Date",
            flex: 1,
            minWidth: 130,

            valueGetter: (
                value,
                row
            ) =>
                getDateValue(
                    row?.joinedDate
                )
        },


        {
            field: "leftDate",
            headerName: "Left Date",
            flex: 1,
            minWidth: 130,

            valueGetter: (
                value,
                row
            ) =>
                getDateValue(
                    row?.leftDate
                )
        },


        {
            field: "status",
            headerName: "Status",
            width: 120,

            renderCell: (
                params
            ) => (

                <StatusChip
                    status={
                        getLookupLabel(
                            params?.row?.status,
                            "Active"
                        )
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
    disableColumnMenu: true,
    align: "right",
    headerAlign: "right",

    renderCell: (params) => {

        const member =
            params?.row || {};

        const memberId =
            member?._id ||
            member?.id;

        const enterprise =
            member?.enterprise;

        const enterpriseId =
            enterprise?._id ||
            enterprise?.id ||
            (
                typeof enterprise === "string"
                    ? enterprise
                    : null
            ) ||
            member?.enterpriseId;

        return (
            <>
                {/* VIEW */}

                <AppIconButton
                    icon={
                        <Visibility />
                    }
                    tooltip="View"
                    disabled={
                        !memberId ||
                        !enterpriseId
                    }
                    onClick={() => {

                        if (
                            !memberId ||
                            !enterpriseId
                        ) {
                            console.error(
                                "Missing enterprise member route data",
                                {
                                    memberId,
                                    enterpriseId,
                                    member
                                }
                            );

                            return;
                        }

                        navigate(
                            `/enterprises/${enterpriseId}/members/${memberId}`
                        );

                    }}
                />


                {/* EDIT */}

                <AppIconButton
                    icon={
                        <Edit />
                    }
                    tooltip="Edit"
                    disabled={
                        actionLoading ||
                        !memberId ||
                        !enterpriseId
                    }
                    onClick={() => {

                        if (
                            !memberId ||
                            !enterpriseId
                        ) {
                            return;
                        }

                        navigate(
                            `/enterprises/${enterpriseId}/members/${memberId}/edit`
                        );

                    }}
                />


                {/* DELETE */}

                <AppIconButton
                    icon={
                        <Delete />
                    }
                    tooltip="Delete"
                    color="error"
                    disabled={
                        actionLoading ||
                        !memberId
                    }
                    onClick={() =>
                        handleDelete(
                            memberId
                        )
                    }
                />

            </>
        );

    }

}

    ];


    // =================================================
    // RENDER
    // =================================================

    return (

        <PageContainer>

            {/* =================================================
                HEADER
            ================================================= */}

            <PageHeader
    title="Enterprise Members"
    subtitle="Manage beneficiaries participating in enterprises"
/>

            {/* =================================================
                SUMMARY
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Enterprise Member Summary"
                >

                    <StatusChip
                        status={
                            `Total: ${totalRecords}`
                        }
                    />


                    <StatusChip
                        status={
                            `Active: ${totalActive}`
                        }
                    />


                    <StatusChip
                        status={
                            `Inactive: ${totalInactive}`
                        }
                    />

                </FormSection>

            </PageCard>


            {/* =================================================
                ERROR
            ================================================= */}

            {
                error && (

                    <ErrorState
                        message={

                            typeof error === "object"

                                ? (
                                    error.message ||
                                    "Failed to load enterprise members"
                                )

                                : error

                        }
                    />

                )
            }


            {/* =================================================
                SUCCESS
            ================================================= */}

            {
                successMessage && (

                    <PageCard>

                        <FormSection>

                            <StatusChip
                                status={
                                    successMessage
                                }
                            />

                        </FormSection>

                    </PageCard>

                )
            }


            {/* =================================================
                TABLE
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Enterprise Member List"
                >

                    <DataTable

                        rows={
                            memberList
                        }

                        columns={
                            columns
                        }

                        loading={
                            loading
                        }

                        getRowId={
                            row =>
                                row._id
                        }

                        paginationMode="server"

                        rowCount={
                            totalRecords
                        }

                        paginationModel={{

                            page:
                                Math.max(
                                    currentPage - 1,
                                    0
                                ),

                            pageSize:
                                pageSize

                        }}

                        onPaginationModelChange={(
                            model
                        ) => {

                            const newPage =
                                model.page + 1;


                            const newLimit =
                                model.pageSize;


                            dispatch(
                                getEnterpriseMembersThunk({

                                    page:
                                        newPage,

                                    limit:
                                        newLimit

                                })
                            );

                        }}

                    />

                </FormSection>

            </PageCard>


            {/* =================================================
                PAGINATION
            ================================================= */}

            <AppPagination

                page={
                    currentPage
                }

                totalPages={
                    totalPages
                }

                onChange={
                    handlePageChange
                }

            />


            {/* =================================================
                BACK
            ================================================= */}

            <AppButton
                variant="outlined"
                sx={{
                    mt: 3,
                    mb: 5
                }}
                onClick={() =>
                    navigate(
                        "/enterprises"
                    )
                }
            >
                Back to Enterprises
            </AppButton>

        </PageContainer>

    );

};


export default EnterpriseMemberListPage;