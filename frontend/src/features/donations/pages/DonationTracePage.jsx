import {
    useEffect,
    useState
} from "react";


import {
    useNavigate,
    useParams
} from "react-router-dom";


import {
    Alert,
    Stack,
    Typography
} from "@mui/material";


import {
    ArrowBack,
    PictureAsPdf
} from "@mui/icons-material";


import {
    PageContainer,
    PageHeader,
    PageCard,
    AppButton,
    LoadingState,
    ErrorState
} from "../../../components/ui";


import DonationTraceView
    from "../components/DonationTraceView";


import {
    getDonationTraceApi,
    downloadDonationStatementApi
} from "../api/donationTraceApi";



// =====================================================
// DONATION TRACE PAGE (staff)
// =====================================================

const DonationTracePage = () => {

    const {
        id
    } = useParams();

    const navigate =
        useNavigate();

    const [trace, setTrace] =
        useState(null);

    const [error, setError] =
        useState("");

    const [pdfError, setPdfError] =
        useState("");


    useEffect(() => {

        let cancelled = false;

        getDonationTraceApi(id)

            .then(data => {
                if (!cancelled) {
                    setTrace(data);
                }
            })

            .catch(loadError => {
                if (!cancelled) {
                    setError(
                        loadError?.response?.data?.message ||
                        "Failed to load the donation trace."
                    );
                }
            });

        return () => {
            cancelled = true;
        };

    }, [id]);


    const header = (

        <PageHeader
            title="Where the Donation Went"
            subtitle={
                trace
                    ? `${trace.donation.code} · ${trace.donation.donor?.name || ""}`
                    : "Donation trace"
            }
            action={() =>
                navigate(`/donations/${id}`)
            }
            actionLabel="Back to Donation"
            actionIcon={<ArrowBack />}
        />

    );


    if (error) {

        return (
            <PageContainer>
                {header}
                <ErrorState message={error} />
            </PageContainer>
        );

    }


    if (!trace) {

        return (
            <PageContainer>
                {header}
                <LoadingState message="Tracing donation..." />
            </PageContainer>
        );

    }


    const handlePdf = async () => {

        setPdfError("");

        try {

            await downloadDonationStatementApi(
                id,
                `${trace.donation.code}-statement.pdf`
            );

        }
        catch {

            setPdfError("Failed to download the donor statement.");

        }

    };


    return (

        <PageContainer>

            {header}


            {/* ACTIONS */}

            <PageCard sx={{ mb: 3 }}>

                <Stack
                    direction={{
                        xs: "column",
                        sm: "row"
                    }}
                    spacing={2}
                    alignItems={{
                        xs: "flex-start",
                        sm: "center"
                    }}
                    justifyContent="space-between"
                >

                    <AppButton
                        variant="contained"
                        startIcon={<PictureAsPdf />}
                        onClick={handlePdf}
                    >
                        Download Donor Statement
                    </AppButton>

                    <Typography
                        variant="body2"
                        color="text.secondary"
                    >
                        {trace.donation.donor?.shareBeneficiaryNames
                            ? "The statement includes beneficiary names (donor setting)."
                            : "The statement shows numbers only; names are not shared with this donor."}
                    </Typography>

                </Stack>

                {pdfError && (
                    <Alert severity="error" sx={{ mt: 2 }}>
                        {pdfError}
                    </Alert>
                )}

            </PageCard>


            <DonationTraceView
                trace={trace}
                staff
                onOpenDelivery={(deliveryId) =>
                    navigate(`/service-deliveries/${deliveryId}`)
                }
                onOpenTor={(torId) =>
                    navigate(`/tors/${torId}`)
                }
            />


            <AppButton
                variant="outlined"
                onClick={() => navigate(`/donations/${id}`)}
                sx={{ mt: 3, mb: 5 }}
            >
                Back to Donation
            </AppButton>

        </PageContainer>

    );

};


export default DonationTracePage;
