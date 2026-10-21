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
    Edit
} from "@mui/icons-material";


import {
    Box,
    Typography
} from "@mui/material";


import {
    PageContainer,
    PageHeader,
    LoadingState,
    PageCard,
    FormSection,
    InfoRow,
    AppButton,
    EmptyState,
    StatusChip
} from "../../../components/ui";

import useZoneLabel
    from "../../locations/hooks/useZoneLabel";


import {
    getEnterpriseByIdThunk
} from "../store/enterpriseThunks";


import {
    getMembersByEnterpriseThunk
} from "../store/enterpriseMemberThunks";


// =========================================================
// LOOKUP DISPLAY
// =========================================================

const getLookupValue = (
    value
) => {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {

        return "-";

    }


    if (
        typeof value === "object"
    ) {

        return (
            value?.value ||
            value?.name ||
            value?.label ||
            value?.code ||
            "-"
        );

    }


    return String(
        value
    );

};


// =========================================================
// NORMALIZE MEMBERS RESPONSE
// =========================================================



// =========================================================
// DATE
// =========================================================

const formatDate = (
    value
) => {

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


// =========================================================
// DATE TIME
// =========================================================

const formatDateTime = (
    value
) => {

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


    return date.toLocaleString();

};


// =========================================================
// BENEFICIARY NAME
// =========================================================

const getBeneficiaryName = (
    beneficiary
) => {

    if (
        !beneficiary ||
        typeof beneficiary !== "object"
    ) {

        return "Beneficiary";

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

        "Beneficiary"

    );

};


// =========================================================
// COMPONENT
// =========================================================

const EnterpriseDetailsPage = () => {

    const {
        id
    } = useParams();


    const navigate =
        useNavigate();


    const dispatch =
        useDispatch();


    // =====================================================
    // ENTERPRISE
    // =====================================================

    const enterprise =
        useSelector(
            state =>
                state.enterprises
                    ?.selectedEnterprise
        );


    const zoneLabel =
        useZoneLabel(
            enterprise?.regionCode
        );


    const enterpriseLoading =
        useSelector(
            state =>
                state.enterprises
                    ?.loading
        );


    // =====================================================
    // MEMBERS STATE
    // =====================================================

    const memberState =
        useSelector(
            state =>
                state.enterpriseMembers || {}
        );


    const members =
        memberState.enterpriseMembers || [];


    const memberLoading =
        memberState.loading || false;


    // =====================================================
    // LOAD ENTERPRISE + MEMBERS
    // =====================================================

    useEffect(() => {

        if (!id) {

            return;

        }


        dispatch(
            getEnterpriseByIdThunk(
                id
            )
        );


        dispatch(
            getMembersByEnterpriseThunk({
                enterpriseId: id
            })
        );

    }, [
        dispatch,
        id
    ]);


    // =====================================================
    // SAFE MEMBERS
    // =====================================================

    const enterpriseMembers =
        Array.isArray(members)
            ? members
            : [];


    // =====================================================
    // LOADING
    // =====================================================

    if (
        enterpriseLoading &&
        !enterprise
    ) {

        return (

            <PageContainer>

                <LoadingState
                    message="Loading enterprise..."
                />

            </PageContainer>

        );

    }


    // =====================================================
    // NOT FOUND
    // =====================================================

    if (!enterprise) {

        return (

            <PageContainer>

                <PageHeader
                    title="Enterprise Details"
                    subtitle="Enterprise record could not be found."
                />


                <PageCard>

                    <FormSection
                        title="Record Not Found"
                    >

                        <EmptyState
                            title="Enterprise not found"
                            message="No enterprise information is available for this record."
                        />

                    </FormSection>

                </PageCard>


                <AppButton
                    variant="outlined"
                    onClick={() =>
                        navigate(
                            "/enterprises"
                        )
                    }
                    sx={{
                        mt: 3,
                        mb: 5
                    }}
                >
                    Back to Enterprises
                </AppButton>

            </PageContainer>

        );

    }


    // =====================================================
    // RENDER
    // =====================================================

    return (
        <PageContainer>

            {/* =================================================
                HEADER
            ================================================= */}

            <PageHeader
                title="Enterprise Details"
                subtitle={
                    enterprise.name ||
                    "Enterprise record"
                }
            />

            {/* =================================================
                ACTION
            ================================================= */}

            <PageCard>

                <FormSection>

                    <AppButton
                        variant="contained"
                        startIcon={
                            <Edit />
                        }
                        onClick={() =>
                            navigate(
                                `/enterprises/${id}/edit`
                            )
                        }
                    >
                        Edit Enterprise
                    </AppButton>

                </FormSection>

            </PageCard>

            {/* =================================================
                ENTERPRISE INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Enterprise Information"
                >

                    <InfoRow
                        label="Enterprise Name"
                        value={
                            enterprise.name
                        }
                    />


                    <InfoRow
                        label="Enterprise Type"
                        value={
                            getLookupValue(
                                enterprise.enterpriseType
                            )
                        }
                    />


                    <InfoRow
                        label="Ownership Type"
                        value={
                            getLookupValue(
                                enterprise.ownershipType
                            )
                        }
                    />


                    <InfoRow
                        label="Business Sector"
                        value={
                            getLookupValue(
                                enterprise.businessSector ||
                                enterprise.sector
                            )
                        }
                    />


                    <InfoRow
                        label="Business Status"
                        value={
                            getLookupValue(
                                enterprise.businessStatus
                            )
                        }
                    />


                    <InfoRow
                        label="Start Date"
                        value={
                            formatDate(
                                enterprise.startDate
                            )
                        }
                    />


                    <InfoRow
                        label="End Date"
                        value={
                            formatDate(
                                enterprise.endDate
                            )
                        }
                    />


                    <InfoRow
                        label="Description"
                        value={
                            enterprise.description
                        }
                    />

                </FormSection>

            </PageCard>

            {/* =================================================
                CONTACT
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Contact Information"
                >

                    <InfoRow
                        label="Phone"
                        value={
                            enterprise.phone
                        }
                    />


                    <InfoRow
                        label="Alternative Phone"
                        value={
                            enterprise.alternativePhone
                        }
                    />


                    <InfoRow
                        label="Email"
                        value={
                            enterprise.email
                        }
                    />


                    <InfoRow
                        label="Registration Number"
                        value={
                            enterprise.registrationNumber
                        }
                    />


                    <InfoRow
                        label="Capital"
                        value={
                            enterprise.capital
                        }
                    />

                </FormSection>

            </PageCard>

            {/* =================================================
                ADDRESS
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Address Information"
                >

                    <InfoRow
                        label="Country"
                        value={
                            enterprise.country
                        }
                    />


                    <InfoRow
                        label="Region"
                        value={
                            enterprise.region
                        }
                    />


                    <InfoRow
                        label={zoneLabel}
                        value={
                            enterprise.zone
                        }
                    />


                    <InfoRow
                        label="Woreda"
                        value={
                            enterprise.woreda
                        }
                    />


                    <InfoRow
                        label="Kebele"
                        value={
                            enterprise.kebele
                        }
                    />


                    <InfoRow
                        label="Address"
                        value={
                            enterprise.address
                        }
                    />

                </FormSection>

            </PageCard>

            {/* =================================================
                ENTERPRISE MEMBERS
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Enterprise Members"
                >

                    <Box
                        sx={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            mb: 3,
                            gap: 2
                        }}
                    >

                        <Typography
                            variant="body2"
                            sx={{
                                color: "text.secondary"
                            }}
                        >
                            Beneficiaries participating in this enterprise
                        </Typography>


                        <AppButton
                            variant="contained"
                            onClick={() =>
                                navigate(
                                    `/enterprises/${id}/members/create`
                                )
                            }
                        >
                            Add Member
                        </AppButton>

                    </Box>


                    {/* =================================================
                        MEMBER LOADING
                    ================================================= */}

                    {memberLoading ? (

                        <LoadingState
                            message="Loading enterprise members..."
                        />

                    ) : enterpriseMembers.length === 0 ? (

                        <EmptyState
                            title="No enterprise members"
                            message="No beneficiaries are currently linked to this enterprise."
                        />

                    ) : (

                        <Box
                            sx={{
                                display: "flex",
                                flexDirection: "row",
                                flexWrap: "wrap",
                                gap: 2,
                                width: "100%"
                            }}
                        >

                            {enterpriseMembers.map(
                                member => {

                                    const beneficiary =
                                        member?.beneficiary ||
                                        member?.beneficiaryId ||
                                        member?.beneficiaryData ||
                                        {};


                                    const memberId =
                                        member?._id ||
                                        member?.id;


                                    const memberRole =
                                        getLookupValue(
                                            member?.memberRole ||
                                            member?.role
                                        );


                                    const memberStatus =
                                        getLookupValue(
                                            member?.status
                                        );


                                    return (

                                        <Box
                                            key={
                                                memberId
                                            }
                                            sx={{
                                                flex: {
                                                    xs: "1 1 100%",
                                                    sm: "1 1 calc(50% - 8px)",
                                                    md: "1 1 calc(33.333% - 11px)"
                                                },
                                                minWidth: 0
                                            }}
                                        >

                                            <PageCard
                                                sx={{
                                                    height: "100%",
                                                    border: "1px solid",
                                                    borderColor: "divider",
                                                    borderRadius: 2
                                                }}
                                            >

                                                <FormSection
                                                    title={
                                                        getBeneficiaryName(
                                                            beneficiary
                                                        )
                                                    }
                                                >

                                                    <InfoRow
                                                        label="Beneficiary Number"
                                                        value={
                                                            beneficiary?.beneficiaryNumber ||
                                                            "-"
                                                        }
                                                    />


                                                    <InfoRow
                                                        label="Member Role"
                                                        value={
                                                            memberRole
                                                        }
                                                    />


                                                    <InfoRow
                                                        label="Joined Date"
                                                        value={
                                                            formatDate(
                                                                member?.joinedDate
                                                            )
                                                        }
                                                    />


                                                    <InfoRow
                                                        label="Left Date"
                                                        value={
                                                            formatDate(
                                                                member?.leftDate
                                                            )
                                                        }
                                                    />


                                                    <InfoRow
                                                        label="Status"
                                                        value={

                                                            <StatusChip
                                                                status={
                                                                    memberStatus ||
                                                                    "Active"
                                                                }
                                                            />

                                                        }
                                                    />


                                                    <Box
                                                        sx={{
                                                            mt: 2
                                                        }}
                                                    >

                                                        <AppButton
                                                            variant="outlined"
                                                            size="small"
                                                            onClick={() =>
                                                                navigate(
                                                                    `/enterprises/${id}/members/${memberId}`
                                                                )
                                                            }
                                                        >
                                                            View Member
                                                        </AppButton>

                                                    </Box>

                                                </FormSection>

                                            </PageCard>

                                        </Box>

                                    );

                                }
                            )}

                        </Box>

                    )}

                </FormSection>

            </PageCard>

            {/* =================================================
                RECORD INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Record Information"
                >

                    <InfoRow
                        label="Status"
                        value={

                            <StatusChip
                                status={
                                    getLookupValue(
                                        enterprise.status
                                    ) ||
                                    "Active"
                                }
                            />

                        }
                    />


                    <InfoRow
                        label="Created At"
                        value={
                            formatDateTime(
                                enterprise.createdAt
                            )
                        }
                    />


                    <InfoRow
                        label="Updated At"
                        value={
                            formatDateTime(
                                enterprise.updatedAt
                            )
                        }
                    />

                </FormSection>

            </PageCard>

            {/* =================================================
                BACK
            ================================================= */}

            <AppButton
                variant="outlined"
                onClick={() =>
                    navigate(
                        "/enterprises"
                    )
                }
                sx={{
                    mt: 3,
                    mb: 5
                }}
            >
                Back to Enterprises
            </AppButton>

        </PageContainer>
    );

};


export default EnterpriseDetailsPage;