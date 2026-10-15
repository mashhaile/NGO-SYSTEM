import {
    useParams,
    useNavigate
} from "react-router-dom";


import {
    ArrowBack
} from "@mui/icons-material";


import DonorForm
    from "../components/DonorForm";


import {
    useDonor,
    useUpdateDonor
} from "../hooks/useDonors";


import {
    PageContainer,
    PageHeader,
    LoadingState,
    PageCard,
    FormSection,
    InfoRow,
    AppButton
} from "../../../components/ui";


// =====================================================
// PAGE
// =====================================================

const DonorEditPage = () => {


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


    const donor =
        data?.data;


    // =================================================
    // UPDATE
    // =================================================

    const updateMutation =
        useUpdateDonor();


    // =================================================
    // LOADING
    // =================================================

    if (isLoading) {

        return (

            <PageContainer>

                <PageHeader
                    title="Edit Donor"
                    subtitle="Loading donor information"
                />

                <LoadingState
                    message="Loading donor..."
                />

            </PageContainer>

        );

    }


    // =================================================
    // NOT FOUND / ERROR
    // =================================================

    if (
        isError ||
        !donor
    ) {

        return (

            <PageContainer>

                <PageHeader
                    title="Edit Donor"
                    subtitle="Donor record could not be loaded."
                />

                <PageCard>

                    <FormSection
                        title="Donor Not Found"
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
    // SUBMIT
    // =================================================

    const handleSubmit = (
        formData
    ) => {

        updateMutation.mutate(

            {
                id,
                data: formData
            },

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

                title="Edit Donor"

                subtitle={
                    donor.name ||
                    "Update donor information"
                }

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


            <DonorForm

                initialData={
                    donor
                }

                onSubmit={
                    handleSubmit
                }

                loading={
                    updateMutation.isPending
                }

            />


        </PageContainer>

    );

};


export default DonorEditPage;