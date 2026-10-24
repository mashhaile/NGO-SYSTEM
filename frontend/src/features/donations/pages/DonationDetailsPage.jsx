import {
    useParams,
    useNavigate
} from "react-router-dom";

import {
    Stack
} from "@mui/material";

import {
    Edit,
    Timeline
} from "@mui/icons-material";

import {
    useDonation
} from "../hooks/useDonations";

import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    InfoRow,
    AppButton,
    LoadingState,
    AppAlert,
    StatusChip
} from "../../../components/ui";


// =====================================================
// DONATION DETAILS PAGE
// =====================================================

const DonationDetailsPage = () => {

    const {
        id
    } = useParams();

    const navigate =
        useNavigate();


    // =================================================
    // GET DONATION
    // =================================================

    const {
        data,
        isLoading,
        error
    } = useDonation(id);


    // =================================================
    // RESPONSE DATA
    // =================================================

    const currentDonation =
        data?.data ||
        data ||
        null;


    // =================================================
    // DATE
    // =================================================

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


    // =================================================
    // DATE TIME
    // =================================================

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


    // =================================================
    // AMOUNT
    // =================================================

    const formatAmount = () => {

        const amount =
            Number(
                currentDonation?.amount || 0
            );

        const currency =
            currentDonation?.currency || "";

        return `${amount.toLocaleString()} ${currency}`.trim();

    };

    const formatMoney = (value) =>
        `${Number(value || 0).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })} ${currentDonation?.funding?.currency || currentDonation?.currency || ""}`.trim();


    // =================================================
    // RELATION VALUE
    // =================================================

    const getRelationValue = (
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
            typeof value === "string" ||
            typeof value === "number"
        ) {
            return String(value);
        }

        if (
            typeof value === "object"
        ) {

            return (
                value?.name ||
                value?.title ||
                value?.label ||
                value?.value ||
                value?.code ||
                "-"
            );

        }

        return "-";

    };


    // =================================================
    // LOADING
    // =================================================

    if (isLoading) {

        return (

            <PageContainer>

                <PageHeader
                    title="Donation Details"
                    subtitle="Loading donation information"
                />

                <PageCard>

                    <LoadingState
                        message="Loading donation..."
                    />

                </PageCard>

            </PageContainer>

        );

    }


    // =================================================
    // NOT FOUND / ERROR
    // =================================================

    if (
        error ||
        !currentDonation
    ) {

        return (

            <PageContainer>

                <PageHeader
                    title="Donation Details"
                    subtitle="Donation record could not be found."
                />

                <AppAlert
                    severity="error"
                    message={
                        error
                            ?.response
                            ?.data
                            ?.message ||

                        error?.message ||

                        "Donation not found."
                    }
                />

                <AppButton
                    variant="outlined"
                    onClick={() =>
                        navigate(
                            "/donations"
                        )
                    }
                    sx={{
                        mt: 3,
                        mb: 5
                    }}
                >
                    Back to Donations
                </AppButton>

            </PageContainer>

        );

    }


    // =================================================
    // RENDER
    // =================================================

    return (

        <PageContainer>

            <PageHeader

                title="Donation Details"

                subtitle={
                    currentDonation.donationCode ||
                    currentDonation.title ||
                    "Donation record"
                }

            />


            {/* =================================================
                ACTION
            ================================================= */}

            <PageCard>

                <FormSection>

                    <Stack
                        direction={{
                            xs: "column",
                            sm: "row"
                        }}
                        spacing={1.5}
                    >

                        <AppButton
                            variant="contained"
                            startIcon={
                                <Edit />
                            }
                            onClick={() =>
                                navigate(
                                    `/donations/${id}/edit`
                                )
                            }
                        >
                            Edit Donation
                        </AppButton>

                        <AppButton
                            variant="outlined"
                            startIcon={
                                <Timeline />
                            }
                            onClick={() =>
                                navigate(
                                    `/donations/${id}/trace`
                                )
                            }
                        >
                            Where Did It Go?
                        </AppButton>

                    </Stack>

                </FormSection>

            </PageCard>


            {/* =================================================
                DONATION INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Donation Information"
                >

                    <InfoRow
                        label="Donation Code"
                        value={
                            currentDonation.donationCode ||
                            "-"
                        }
                    />

                    <InfoRow
                        label="Donation Title"
                        value={
                            currentDonation.title ||
                            "-"
                        }
                    />

                    <InfoRow
                        label="Donor"
                        value={
                            getRelationValue(
                                currentDonation.donor
                            )
                        }
                    />

                    <InfoRow
                        label="Donation Date"
                        value={
                            formatDate(
                                currentDonation.donationDate
                            )
                        }
                    />

                    <InfoRow
                        label="Donation Type"
                        value={
                            currentDonation.donationType ||
                            "-"
                        }
                    />

                </FormSection>

            </PageCard>


            {/* =================================================
                FINANCIAL INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Financial Information"
                >

                    <InfoRow
                        label="Amount"
                        value={
                            formatAmount()
                        }
                    />

                    <InfoRow
                        label="Currency"
                        value={
                            currentDonation.currency ||
                            "-"
                        }
                    />

                    <InfoRow
                        label="Financial Year"
                        value={
                            currentDonation.financialYear ||
                            "-"
                        }
                    />

                    {/* What it has paid for so far, and what is left */}

                    {currentDonation.funding && (
                        <>
                            <InfoRow
                                label="Used in service deliveries"
                                value={formatMoney(currentDonation.funding.byDeliveries)}
                            />

                            <InfoRow
                                label="Used in expenses (submitted / approved)"
                                value={formatMoney(currentDonation.funding.byExpenses)}
                            />

                            {Number(currentDonation.funding.givenFromExpenses) > 0 && (
                                <InfoRow
                                    label="Given out, bought with those expenses (not counted again)"
                                    value={formatMoney(currentDonation.funding.givenFromExpenses)}
                                />
                            )}

                            <InfoRow
                                label="Left to use"
                                value={formatMoney(currentDonation.funding.left)}
                            />
                        </>
                    )}

                </FormSection>

            </PageCard>


            {/* =================================================
                PROGRAM / PROJECT / ACTIVITY
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Program & Project"
                >

                    <InfoRow
                        label="Program"
                        value={
                            getRelationValue(
                                currentDonation.program
                            )
                        }
                    />

                    <InfoRow
                        label="Project"
                        value={
                            getRelationValue(
                                currentDonation.project
                            )
                        }
                    />

                    <InfoRow
                        label="Activity"
                        value={
                            getRelationValue(
                                currentDonation.activity
                            )
                        }
                    />

                    <InfoRow
                        label="Activity Run"
                        value={
                            getRelationValue(
                                currentDonation.activityRun
                            )
                        }
                    />

                </FormSection>

            </PageCard>


            {/* =================================================
                FUNDING INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Funding Information"
                >

                    <InfoRow
                        label="Funding Source"
                        value={
                            currentDonation.fundingSource ||
                            "-"
                        }
                    />

                    <InfoRow
                        label="Funding Restriction"
                        value={
                            currentDonation.fundingRestriction ||
                            "-"
                        }
                    />

                    <InfoRow
                        label="Status"
                        value={
                            <StatusChip
                                status={
                                    currentDonation.status ||
                                    "Inactive"
                                }
                            />
                        }
                    />

                </FormSection>

            </PageCard>


            {/* =================================================
                REFERENCES
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Donation References"
                >

                    <InfoRow
                        label="Receipt Number"
                        value={
                            currentDonation.receiptNumber ||
                            "-"
                        }
                    />

                    <InfoRow
                        label="Reference Number"
                        value={
                            currentDonation.referenceNumber ||
                            "-"
                        }
                    />

                </FormSection>

            </PageCard>


            {/* =================================================
                DESCRIPTION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Description"
                >

                    <InfoRow
                        label="Description"
                        value={
                            currentDonation.description ||
                            "-"
                        }
                    />

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
                        label="Created At"
                        value={
                            formatDateTime(
                                currentDonation.createdAt
                            )
                        }
                    />

                    <InfoRow
                        label="Updated At"
                        value={
                            formatDateTime(
                                currentDonation.updatedAt
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
                        "/donations"
                    )
                }
                sx={{
                    mt: 3,
                    mb: 5
                }}
            >
                Back to Donations
            </AppButton>

        </PageContainer>

    );

};


export default DonationDetailsPage;