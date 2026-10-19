import {
    useEffect,
    useState
} from "react";


import {
    useParams
} from "react-router-dom";


import {
    Alert,
    Box,
    Divider,
    Stack,
    Typography
} from "@mui/material";


import {
    LockOutlined,
    PictureAsPdf
} from "@mui/icons-material";


import {
    PageContainer,
    PageCard,
    AppButton,
    LoadingState
} from "../../../components/ui";


import DonationTraceView
    from "../components/DonationTraceView";


import {
    getPublicShareApi,
    downloadPublicStatementApi
} from "../api/donorShareApi";


import {
    formatMoney,
    formatDate
} from "../api/donationTraceApi";



// =====================================================
// DONOR SHARE PAGE (public, no login)
// =====================================================
//
// What a donor sees when opening their private link:
// where each of their donations went.
//
// =====================================================

const DonorSharePage = () => {

    const {
        token
    } = useParams();

    const [view, setView] =
        useState(null);

    const [error, setError] =
        useState("");

    const [pdfError, setPdfError] =
        useState("");


    useEffect(() => {

        let cancelled = false;

        getPublicShareApi(token)

            .then(data => {
                if (!cancelled) {
                    setView(data);
                }
            })

            .catch(loadError => {
                if (!cancelled) {
                    setError(
                        loadError?.response?.data?.message ||
                        "This link could not be opened."
                    );
                }
            });

        return () => {
            cancelled = true;
        };

    }, [token]);


    const handlePdf = async (trace) => {

        setPdfError("");

        try {

            await downloadPublicStatementApi(
                token,
                trace.donation.id,
                `${trace.donation.code}-statement.pdf`
            );

        }
        catch {

            setPdfError("The statement could not be downloaded. Please try again later.");

        }

    };


    if (error) {

        return (

            <PageContainer sx={{ pt: 6, maxWidth: 720 }}>

                <PageCard>

                    <Stack spacing={2} alignItems="center" sx={{ py: 3, textAlign: "center" }}>

                        <LockOutlined color="action" fontSize="large" />

                        <Typography variant="h6" fontWeight={700}>
                            Link not available
                        </Typography>

                        <Typography color="text.secondary">
                            {error}
                        </Typography>

                    </Stack>

                </PageCard>

            </PageContainer>

        );

    }


    if (!view) {

        return (
            <PageContainer sx={{ pt: 6 }}>
                <LoadingState message="Loading your donation report..." />
            </PageContainer>
        );

    }


    return (

        <PageContainer sx={{ pt: 4 }}>

            {/* HEADER */}

            <Box sx={{ mb: 3 }}>

                <Typography variant="overline" color="text.secondary">
                    {view.organization.name}
                </Typography>

                <Typography variant="h4" fontWeight={700}>
                    Where your donation went
                </Typography>

                <Typography color="text.secondary" sx={{ mt: 0.5 }}>
                    Prepared for <strong>{view.donor.name}</strong> · updated {formatDate(view.generatedAt)}
                </Typography>

            </Box>


            <Alert
                severity="info"
                icon={<LockOutlined fontSize="inherit" />}
                sx={{ mb: 3 }}
            >
                This is a private link for {view.donor.name}. Please do not forward it.
                {" "}It works until {formatDate(view.expiresAt)}.
                {view.namesIncluded
                    ? " Beneficiary names are included with your agreement; please keep them confidential."
                    : " To protect beneficiaries, figures are shown as totals only."}
            </Alert>


            {pdfError && (
                <Alert severity="error" sx={{ mb: 3 }}>
                    {pdfError}
                </Alert>
            )}


            {/* ALL DONATIONS SUMMARY */}

            {view.summary && view.donations.length > 1 && (

                <PageCard sx={{ mb: 3 }}>

                    <Typography variant="h6" fontWeight={700} sx={{ mb: 1 }}>
                        All your donations
                    </Typography>

                    <Typography color="text.secondary">
                        {view.summary.donations} donations · {formatMoney(view.summary.received)} received ·{" "}
                        {formatMoney(view.summary.used)} used ({view.summary.percentUsed}%) ·{" "}
                        {view.summary.beneficiariesReached} people reached
                    </Typography>

                </PageCard>

            )}


            {view.donations.length === 0 && (

                <Alert severity="info">
                    No donations to show yet.
                </Alert>

            )}


            {/* EACH DONATION */}

            {view.donations.map((trace, index) => (

                <Box key={trace.donation.id}>

                    {index > 0 && (
                        <Divider sx={{ my: 4 }} />
                    )}

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
                        sx={{ mb: 2 }}
                    >

                        <Box>

                            <Typography variant="h5" fontWeight={700}>
                                {trace.donation.title || trace.donation.code}
                            </Typography>

                            <Typography color="text.secondary">
                                {trace.donation.code} · {formatDate(trace.donation.date)}
                            </Typography>

                        </Box>

                        <AppButton
                            variant="outlined"
                            startIcon={<PictureAsPdf />}
                            onClick={() => handlePdf(trace)}
                        >
                            Download Statement
                        </AppButton>

                    </Stack>

                    <DonationTraceView
                        trace={trace}
                    />

                </Box>

            ))}


            <Typography
                variant="caption"
                color="text.secondary"
                sx={{ display: "block", mt: 4, mb: 5, textAlign: "center" }}
            >
                Figures cover delivered services recorded against each donation by {view.organization.name}.
            </Typography>

        </PageContainer>

    );

};


export default DonorSharePage;
