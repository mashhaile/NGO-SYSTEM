import {
    useEffect
} from "react";


import {
    useDispatch,
    useSelector
} from "react-redux";


import {
    useNavigate,
    useParams
} from "react-router-dom";


import {
    Box,
    Typography,
    Alert,
    Divider
} from "@mui/material";


import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    FormActions,
    AppButton
} from "../../../components/ui";


import {
    getEnterpriseMemberByIdThunk,
    deleteEnterpriseMemberThunk
} from "../store/enterpriseMemberThunks";


// =====================================================
// ENTERPRISE MEMBER DETAILS PAGE
// =====================================================

const EnterpriseMemberDetailsPage = () => {

    const dispatch =
        useDispatch();


    const navigate =
        useNavigate();


    const {
        id,
        memberId,
        enterpriseId: routeEnterpriseId
    } = useParams();


    // =================================================
    // MEMBER ID
    // =================================================

    const memberIdentifier =
        memberId || id;


    // =================================================
    // REDUX
    // =================================================

    const {
        selectedMember = null,
        loading = false,
        actionLoading = false,
        error = null
    } = useSelector(
        state =>
            state.enterpriseMembers || {}
    );


    // =================================================
    // LOAD MEMBER
    // =================================================

    useEffect(() => {

        if (!memberIdentifier) {

            return;

        }


        dispatch(
            getEnterpriseMemberByIdThunk(
                memberIdentifier
            )
        );

    }, [
        dispatch,
        memberIdentifier
    ]);


    // =================================================
    // VALUE HELPER
    // =================================================

    const getValue = (
        value,
        fallback = "—"
    ) => {

        if (
            value === null ||
            value === undefined ||
            value === ""
        ) {

            return fallback;

        }


        if (
            typeof value === "object"
        ) {

            return (

                value.value ||

                value.label ||

                value.name ||

                value.code ||

                fallback

            );

        }


        return String(
            value
        );

    };


    // =================================================
    // BENEFICIARY
    // =================================================

    const beneficiary =
        selectedMember?.beneficiary;


    const getBeneficiaryName = () => {

        if (!beneficiary) {

            return "—";

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

            "—"

        );

    };


    // =================================================
    // ENTERPRISE
    // =================================================

    const enterprise =
        selectedMember?.enterprise;


    const getEnterpriseName = () => {

        if (!enterprise) {

            return "—";

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

            "—"

        );

    };


    // =================================================
    // ENTERPRISE ID
    // =================================================

    const enterpriseId =

        (
            typeof enterprise === "object"

                ? (
                    enterprise?._id ||
                    enterprise?.id
                )

                : enterprise
        ) ||

        selectedMember?.enterpriseId ||

        routeEnterpriseId;


    // =================================================
    // DATE
    // =================================================

    const getDate = (
        value
    ) => {

        if (!value) {

            return "—";

        }


        const date =
            new Date(
                value
            );


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
    // DELETE
    // =================================================

    const handleDelete = async () => {

        if (!memberIdentifier) {

            return;

        }


        const confirmed =
            window.confirm(
                "Are you sure you want to remove this enterprise member?"
            );


        if (!confirmed) {

            return;

        }


        const result =
            await dispatch(
                deleteEnterpriseMemberThunk(
                    memberIdentifier
                )
            );


        if (
            deleteEnterpriseMemberThunk.fulfilled.match(
                result
            )
        ) {

            if (enterpriseId) {

                navigate(
                    `/enterprises/${enterpriseId}/members`
                );

            } else {

                navigate(
                    "/enterprise-members"
                );

            }

        }

    };


    // =================================================
    // ROUTES
    // =================================================

    const membersListPath =

        enterpriseId

            ? `/enterprises/${enterpriseId}/members`

            : "/enterprise-members";


    const editPath =

        enterpriseId

            ? `/enterprises/${enterpriseId}/members/${memberIdentifier}/edit`

            : `/enterprise-members/${memberIdentifier}/edit`;


    // =================================================
    // LOADING
    // =================================================

    if (
        loading
    ) {

        return (

            <PageContainer>

                <Box
                    sx={{
                        p: 3
                    }}
                >

                    <Typography>

                        Loading enterprise member...

                    </Typography>

                </Box>

            </PageContainer>

        );

    }


    // =================================================
    // NOT FOUND / ERROR
    // =================================================

    if (!selectedMember) {

        return (

            <PageContainer>

                <PageHeader
                    title="Enterprise Member Details"
                    subtitle="View beneficiary participation in an enterprise"
                />


                <Alert
                    severity="error"
                    sx={{
                        mb: 2
                    }}
                >

                    {
                        error

                            ? (
                                typeof error === "object"

                                    ? (
                                        error.message ||
                                        "Failed to load enterprise member."
                                    )

                                    : error
                            )

                            : "Enterprise member not found."
                    }

                </Alert>


                <AppButton
                    variant="outlined"
                    onClick={() =>
                        navigate(
                            membersListPath
                        )
                    }
                >

                    Back to Enterprise Members

                </AppButton>

            </PageContainer>

        );

    }


    // =================================================
    // RENDER
    // =================================================

    return (
        <PageContainer>

            {/* =================================================
                HEADER
            ================================================= */}

            <PageHeader

                title="Enterprise Member Details"

                subtitle="View beneficiary participation in this enterprise"

            />

            {/* =================================================
                ERROR
            ================================================= */}

            {
                error && (

                    <Alert
                        severity="error"
                        sx={{
                            mb: 2
                        }}
                    >

                        {
                            typeof error === "object"

                                ? (
                                    error.message ||
                                    "Failed to load enterprise member."
                                )

                                : error
                        }

                    </Alert>

                )
            }

            {/* =================================================
                MEMBER INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Enterprise Member Information"
                >

                    <Box
                        sx={{
                            display: "grid",
                            gap: 2
                        }}
                    >

                        {/* =====================================
                            ENTERPRISE
                        ===================================== */}

                        <Box>

                            <Typography
                                variant="caption"
                                sx={{
                                    color: "text.secondary"
                                }}
                            >

                                Enterprise

                            </Typography>


                            <Typography>

                                {
                                    getEnterpriseName()
                                }

                            </Typography>

                        </Box>


                        <Divider />


                        {/* =====================================
                            ENTERPRISE NUMBER
                        ===================================== */}

                        <Box>

                            <Typography
                                variant="caption"
                                sx={{
                                    color: "text.secondary"
                                }}
                            >

                                Enterprise Number

                            </Typography>


                            <Typography>

                                {
                                    getValue(
                                        typeof enterprise === "object"
                                            ? enterprise?.enterpriseNumber
                                            : null
                                    )
                                }

                            </Typography>

                        </Box>


                        <Divider />


                        {/* =====================================
                            BENEFICIARY
                        ===================================== */}

                        <Box>

                            <Typography
                                variant="caption"
                                sx={{
                                    color: "text.secondary"
                                }}
                            >

                                Beneficiary

                            </Typography>


                            <Typography>

                                {
                                    getBeneficiaryName()
                                }

                            </Typography>

                        </Box>


                        <Divider />


                        {/* =====================================
                            BENEFICIARY NUMBER
                        ===================================== */}

                        <Box>

                            <Typography
                                variant="caption"
                                sx={{
                                    color: "text.secondary"
                                }}
                            >

                                Beneficiary Number

                            </Typography>


                            <Typography>

                                {
                                    getValue(
                                        typeof beneficiary === "object"
                                            ? beneficiary?.beneficiaryNumber
                                            : null
                                    )
                                }

                            </Typography>

                        </Box>


                        <Divider />


                        {/* =====================================
                            MEMBER ROLE
                        ===================================== */}

                        <Box>

                            <Typography
                                variant="caption"
                                sx={{
                                    color: "text.secondary"
                                }}
                            >

                                Member Role

                            </Typography>


                            <Typography>

                                {
                                    getValue(
                                        selectedMember?.memberRole,
                                        "Member"
                                    )
                                }

                            </Typography>

                        </Box>


                        <Divider />


                        {/* =====================================
                            JOINED DATE
                        ===================================== */}

                        <Box>

                            <Typography
                                variant="caption"
                                sx={{
                                    color: "text.secondary"
                                }}
                            >

                                Joined Date

                            </Typography>


                            <Typography>

                                {
                                    getDate(
                                        selectedMember?.joinedDate
                                    )
                                }

                            </Typography>

                        </Box>


                        <Divider />


                        {/* =====================================
                            LEFT DATE
                        ===================================== */}

                        <Box>

                            <Typography
                                variant="caption"
                                sx={{
                                    color: "text.secondary"
                                }}
                            >

                                Left Date

                            </Typography>


                            <Typography>

                                {
                                    getDate(
                                        selectedMember?.leftDate
                                    )
                                }

                            </Typography>

                        </Box>


                        <Divider />


                        {/* =====================================
                            STATUS
                        ===================================== */}

                        <Box>

                            <Typography
                                variant="caption"
                                sx={{
                                    color: "text.secondary"
                                }}
                            >

                                Status

                            </Typography>


                            <Typography>

                                {
                                    getValue(
                                        selectedMember?.status,
                                        "Active"
                                    )
                                }

                            </Typography>

                        </Box>

                    </Box>

                </FormSection>

            </PageCard>

            {/* =================================================
                ACTIONS
            ================================================= */}

            <FormActions>

                <AppButton

                    type="button"

                    variant="outlined"

                    onClick={() =>
                        navigate(
                            membersListPath
                        )
                    }

                >

                    Back

                </AppButton>


                <AppButton

                    type="button"

                    variant="outlined"

                    disabled={
                        !memberIdentifier
                    }

                    onClick={() =>
                        navigate(
                            editPath
                        )
                    }

                >

                    Edit

                </AppButton>


                <AppButton

                    type="button"

                    variant="contained"

                    color="error"

                    disabled={
                        actionLoading ||
                        !memberIdentifier
                    }

                    onClick={
                        handleDelete
                    }

                >

                    {
                        actionLoading

                            ? "Removing..."

                            : "Remove Member"
                    }

                </AppButton>

            </FormActions>

        </PageContainer>
    );

};


export default EnterpriseMemberDetailsPage;