import {
    useNavigate
} from "react-router-dom";


import {
    ArrowBack
} from "@mui/icons-material";


import DonorForm
    from "../components/DonorForm";


import {
    useCreateDonor
} from "../hooks/useDonors";


import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    InfoRow,
    AppButton
} from "../../../components/ui";


// =====================================================
// PAGE
// =====================================================

const DonorCreatePage = () => {


    const navigate =
        useNavigate();


    // =================================================
    // CREATE
    // =================================================

    const createMutation =
        useCreateDonor();


    // =================================================
    // SUBMIT
    // =================================================

    const handleSubmit = (
        data
    ) => {

        createMutation.mutate(

            data,

            {
                onSuccess: () => {

                    navigate(
                        "/donors"
                    );

                }
            }

        );

    };


    // =================================================
    // RENDER
    // =================================================

    return (

        <PageContainer>


            <PageHeader

                title="Create Donor"

                subtitle="Add a new donor or funding partner"

                action={() =>
                    navigate(
                        "/donors"
                    )
                }

                actionLabel="Back"

                actionIcon={
                    <ArrowBack />
                }

            />


            {/* =================================================
                ERROR
            ================================================= */}

            {
                createMutation.error && (

                    <PageCard>

                        <FormSection
                            title="Unable to Create Donor"
                        >

                            <InfoRow
                                label="Error"
                                value={
                                    createMutation.error
                                        ?.response
                                        ?.data
                                        ?.message ||
                                    createMutation.error
                                        ?.message ||
                                    "Failed to create donor."
                                }
                            />

                        </FormSection>

                    </PageCard>

                )
            }


            {/* =================================================
                FORM
            ================================================= */}

            <DonorForm

                onSubmit={
                    handleSubmit
                }

                loading={
                    createMutation.isPending
                }

            />


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


export default DonorCreatePage;
