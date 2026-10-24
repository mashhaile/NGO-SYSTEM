import {
    useParams,
    useNavigate
} from "react-router-dom";


import {
    Edit,
    ArrowBack
} from "@mui/icons-material";


import {
    useDonor
} from "../hooks/useDonors";


import {
    PageContainer,
    PageHeader,
    LoadingState,
    PageCard,
    FormSection,
    InfoRow,
    AppButton,
    StatusChip
} from "../../../components/ui";

import DonorTraceSection
    from "../../donations/components/DonorTraceSection";

import DonorShareLinksSection
    from "../../donations/components/DonorShareLinksSection";


// =====================================================
// PAGE
// =====================================================

const DonorDetailsPage = () => {


    const {
        id
    } = useParams();


    const navigate =
        useNavigate();


    // =================================================
    // LOAD DONOR
    // =================================================

    const {
        data,
        isLoading,
        isError
    } = useDonor(id);


    // =================================================
    // NORMALIZE RESPONSE
    // =================================================
    //
    // Supports:
    //
    // 1. { data: donor }
    // 2. { data: { data: donor } }
    // 3. donor
    //
    // =================================================

    const donor =
        data?.data?.data ||
        data?.data ||
        data?.donor ||
        data ||
        null;


    // =================================================
    // LOADING
    // =================================================

    if (isLoading) {

        return (

            <PageContainer>

                <PageHeader
                    title="Donor Details"
                    subtitle="Loading donor information"
                />

                <LoadingState
                    message="Loading donor..."
                />

            </PageContainer>

        );

    }


    // =================================================
    // ERROR / NOT FOUND
    // =================================================

    if (
        isError ||
        !donor ||
        !donor._id
    ) {

        return (

            <PageContainer>

                <PageHeader
                    title="Donor Details"
                    subtitle="Donor record could not be loaded."
                />

                <PageCard>

                    <FormSection
                        title="Record Not Found"
                    >

                        <InfoRow
                            label="Donor"
                            value="No donor information available."
                        />

                    </FormSection>

                </PageCard>


                <AppButton
                    variant="outlined"
                    startIcon={
                        <ArrowBack />
                    }
                    onClick={() =>
                        navigate(
                            "/donors"
                        )
                    }
                    sx={{
                        mt: 3,
                        mb: 5
                    }}
                >
                    Back to Donors
                </AppButton>

            </PageContainer>

        );

    }


    // =================================================
    // SAFE VALUE
    // =================================================

    const displayValue = (
        value
    ) => {

        if (
            value === null ||
            value === undefined ||
            value === ""
        ) {
            return "-";
        }

        return String(value);

    };


    // =================================================
    // DATE FORMAT
    // =================================================

    const formatDate = (
        value
    ) => {

        if (
            value === null ||
            value === undefined ||
            value === ""
        ) {
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


    // =================================================
    // DATE TIME FORMAT
    // =================================================

    const formatDateTime = (
        value
    ) => {

        if (
            value === null ||
            value === undefined ||
            value === ""
        ) {
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


    // =================================================
    // RENDER
    // =================================================

    return (

        <PageContainer>


            <PageHeader

                title="Donor Details"

                subtitle={
                    displayValue(
                        donor.name
                    )
                }

                action={() =>
                    navigate(
                        `/donors/${id}/edit`
                    )
                }

                actionLabel="Edit Donor"

                actionIcon={
                    <Edit />
                }

            />


            {/* =================================================
                BASIC INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Basic Information"
                >

                    <InfoRow
                        label="Donor Name"
                        value={
                            displayValue(
                                donor.name
                            )
                        }
                    />


                    <InfoRow
                        label="Donor Type"
                        value={
                            displayValue(
                                donor.donorType
                            )
                        }
                    />


                    <InfoRow
                        label="Registration Number"
                        value={
                            displayValue(
                                donor.registrationNumber
                            )
                        }
                    />


                    <InfoRow
                        label="Country"
                        value={
                            displayValue(
                                donor.country
                            )
                        }
                    />


                    <InfoRow
                        label="Website"
                        value={
                            displayValue(
                                donor.website
                            )
                        }
                    />


                    <InfoRow
                        label="Status"
                        value={
                            <StatusChip
                                status={
                                    donor.status ||
                                    "Inactive"
                                }
                            />
                        }
                    />

                </FormSection>

            </PageCard>


            {/* =================================================
                CONTACT INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Contact Information"
                >

                    <InfoRow
                        label="Email"
                        value={
                            displayValue(
                                donor.email
                            )
                        }
                    />


                    <InfoRow
                        label="Phone"
                        value={
                            displayValue(
                                donor.phone
                            )
                        }
                    />


                    <InfoRow
                        label="Contact Person"
                        value={
                            displayValue(
                                donor.contactPerson
                            )
                        }
                    />


                    <InfoRow
                        label="Address"
                        value={
                            displayValue(
                                donor.address
                            )
                        }
                    />

                </FormSection>

            </PageCard>


            {/* =================================================
                DONOR DATES
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Donor Dates"
                >

                    <InfoRow
                        label="Donor Since"
                        value={
                            formatDate(
                                donor.donorSince
                            )
                        }
                    />


                    <InfoRow
                        label="Last Contact Date"
                        value={
                            formatDate(
                                donor.lastContactDate
                            )
                        }
                    />


                    <InfoRow
                        label="Next Follow-up Date"
                        value={
                            formatDate(
                                donor.nextFollowUpDate
                            )
                        }
                    />

                </FormSection>

            </PageCard>


            {/* =================================================
                DONATION TRACE
            ================================================= */}

            <DonorTraceSection
                donorId={id}
            />

            <DonorShareLinksSection
                donorId={id}
                shareBeneficiaryNames={
                    Boolean(donor.shareBeneficiaryNames)
                }
            />


            {/* =================================================
                NOTES
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Notes"
                >

                    <InfoRow
                        label="Notes"
                        value={
                            donor.notes ||
                            "No notes"
                        }
                    />

                </FormSection>

            </PageCard>


            {/* The donations are listed in "Donations and Where They Went" above */}



            {/* =================================================
                RECORD INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Record Information"
                >

                    <InfoRow
                        label="Created At"
                        value={
                            formatDateTime(
                                donor.createdAt
                            )
                        }
                    />


                    <InfoRow
                        label="Updated At"
                        value={
                            formatDateTime(
                                donor.updatedAt
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
                startIcon={
                    <ArrowBack />
                }
                onClick={() =>
                    navigate(
                        "/donors"
                    )
                }
                sx={{
                    mt: 3,
                    mb: 5
                }}
            >
                Back to Donors
            </AppButton>


        </PageContainer>

    );

};


export default DonorDetailsPage;
