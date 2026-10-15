import {
    DataTable,
    EmptyState,
    LoadingState,
    AppIconButton,
    StatusChip
} from "../../../components/ui";


import {
    Edit,
    Delete,
    Visibility
} from "@mui/icons-material";


// =====================================================
// ENTERPRISE MEMBER TABLE
// =====================================================

const EnterpriseMemberTable = ({
    members = [],
    loading = false,
    onView,
    onEdit,
    onDelete
}) => {


    // =================================================
    // BENEFICIARY NAME
    // =================================================

    const getBeneficiaryName = (
        beneficiary
    ) => {

        if (
            !beneficiary ||
            typeof beneficiary !== "object"
        ) {

            return "Unknown Beneficiary";

        }


        const name = [

            beneficiary.firstName,

            beneficiary.middleName,

            beneficiary.lastName

        ]
            .filter(Boolean)
            .join(" ");


        return (

            name ||

            beneficiary.beneficiaryNumber ||

            beneficiary.phone ||

            beneficiary.email ||

            "Unknown Beneficiary"

        );

    };


    // =================================================
    // ENTERPRISE NAME
    // =================================================

    const getEnterpriseName = (
        enterprise
    ) => {

        if (
            enterprise &&
            typeof enterprise === "object"
        ) {

            return (

                enterprise.name ||

                enterprise.enterpriseName ||

                enterprise.businessName ||

                enterprise.enterpriseNumber ||

                "—"

            );

        }


        return enterprise || "—";

    };


    // =================================================
    // MEMBER ROLE
    // =================================================

    const getMemberRole = (
        member
    ) => {

        const role =
            member?.memberRole ??
            member?.role;


        if (
            role === null ||
            role === undefined ||
            role === ""
        ) {

            return "—";

        }


        if (
            typeof role === "object"
        ) {

            return (

                role.label ||

                role.value ||

                role.name ||

                role.code ||

                "—"

            );

        }


        return String(role);

    };


    // =================================================
    // STATUS
    // =================================================

    const getStatus = (
        status
    ) => {

        if (
            !status
        ) {

            return "Active";

        }


        if (
            typeof status === "object"
        ) {

            return (

                status.label ||

                status.value ||

                status.name ||

                "Active"

            );

        }


        return String(status);

    };


    // =================================================
    // DATE
    // =================================================

    const formatDate = (
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


    // =================================================
    // COLUMNS
    // =================================================

    const columns = [

        {
            field: "enterprise",

            headerName: "Enterprise",

            render: member =>
                getEnterpriseName(
                    member.enterprise
                )

        },


        {
            field: "beneficiary",

            headerName: "Beneficiary",

            render: member =>
                getBeneficiaryName(
                    member.beneficiary
                )

        },


        {
            field: "memberRole",

            headerName: "Member Role",

            render: member =>
                getMemberRole(
                    member
                )

        },


        {
            field: "joinedDate",

            headerName: "Joined Date",

            render: member =>
                formatDate(
                    member.joinedDate
                )

        },


        {
            field: "leftDate",

            headerName: "Left Date",

            render: member =>
                formatDate(
                    member.leftDate
                )

        },


        {
            field: "status",

            headerName: "Status",

            render: member => (

                <StatusChip
                    status={
                        getStatus(
                            member.status
                        )
                    }
                />

            )

        },


        {
            field: "actions",

            headerName: "Actions",

            align: "right",

            render: member => (

                <>

                    {
                        onView && (

                            <AppIconButton

                                title="View"

                                onClick={() =>
                                    onView(
                                        member
                                    )
                                }

                            >

                                <Visibility />

                            </AppIconButton>

                        )
                    }


                    {
                        onEdit && (

                            <AppIconButton

                                title="Edit"

                                onClick={() =>
                                    onEdit(
                                        member
                                    )
                                }

                            >

                                <Edit />

                            </AppIconButton>

                        )
                    }


                    {
                        onDelete && (

                            <AppIconButton

                                title="Delete"

                                color="error"

                                onClick={() =>
                                    onDelete(
                                        member
                                    )
                                }

                            >

                                <Delete />

                            </AppIconButton>

                        )
                    }

                </>

            )

        }

    ];


    // =================================================
    // LOADING
    // =================================================

    if (loading) {

        return (

            <LoadingState
                message="Loading enterprise members..."
            />

        );

    }


    // =================================================
    // EMPTY
    // =================================================

    if (
        !Array.isArray(members) ||
        members.length === 0
    ) {

        return (

            <EmptyState
                title="No enterprise members found."
            />

        );

    }


    // =================================================
    // TABLE
    // =================================================

    return (

        <DataTable

            columns={
                columns
            }

            rows={
                members
            }

            getRowId={
                member =>
                    member?._id
            }

        />

    );

};


export default EnterpriseMemberTable;