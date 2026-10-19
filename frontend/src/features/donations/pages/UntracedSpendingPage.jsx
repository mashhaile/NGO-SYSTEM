import {
    useEffect,
    useState
} from "react";


import {
    useNavigate
} from "react-router-dom";


import {
    Alert,
    Link
} from "@mui/material";


import {
    ArrowBack
} from "@mui/icons-material";


import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    InfoRow,
    LoadingState,
    ErrorState
} from "../../../components/ui";


import TraceTable
    from "../components/TraceTable";


import {
    getUntracedSpendingApi,
    formatMoney,
    formatDate
} from "../api/donationTraceApi";



// =====================================================
// UNTRACED SPENDING
// =====================================================
//
// Delivered service items that are not linked to any
// donation, so they appear in no donor's trace. Staff
// fix them by editing the delivery and choosing the
// donation that paid for the item.
//
// =====================================================

const UntracedSpendingPage = () => {

    const navigate =
        useNavigate();

    const [result, setResult] =
        useState(null);

    const [error, setError] =
        useState("");


    useEffect(() => {

        let cancelled = false;

        getUntracedSpendingApi()

            .then(data => {
                if (!cancelled) {
                    setResult(data);
                }
            })

            .catch(loadError => {
                if (!cancelled) {
                    setError(
                        loadError?.response?.data?.message ||
                        "Failed to load untraced spending."
                    );
                }
            });

        return () => {
            cancelled = true;
        };

    }, []);


    const header = (

        <PageHeader
            title="Untraced Spending"
            subtitle="Delivered services not linked to any donation."
            action={() => navigate("/donations")}
            actionLabel="Back to Donations"
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


    if (!result) {
        return (
            <PageContainer>
                {header}
                <LoadingState message="Loading..." />
            </PageContainer>
        );
    }


    return (

        <PageContainer>

            {header}

            {result.rows.length === 0
                ? (
                    <Alert severity="success">
                        All delivered services are linked to a donation.
                    </Alert>
                )
                : (
                    <Alert severity="warning" sx={{ mb: 3 }}>
                        These costs do not appear in any donor&apos;s trace. Open the delivery, choose the donation that paid for each item, and save.
                    </Alert>
                )}


            <PageCard>
                <FormSection title="Summary">
                    <InfoRow label="Untraced items" value={result.totals.items} />
                    <InfoRow label="Untraced amount" value={formatMoney(result.totals.amount)} />
                </FormSection>
            </PageCard>


            <PageCard>
                <FormSection title="Items to Link">
                    <TraceTable
                        rows={result.rows}
                        getRowKey={(row, index) => `${row.deliveryId}-${index}`}
                        empty="Nothing to fix."
                        columns={[
                            { key: "date", label: "Date", render: row => formatDate(row.date) },
                            {
                                key: "deliveryNumber",
                                label: "Delivery",
                                render: row => (
                                    <Link
                                        component="button"
                                        underline="hover"
                                        onClick={() => navigate(`/service-deliveries/${row.deliveryId}/edit`)}
                                    >
                                        {row.deliveryNumber}
                                    </Link>
                                )
                            },
                            { key: "project", label: "Project", render: row => row.project?.name || "-" },
                            { key: "service", label: "Service" },
                            { key: "location", label: "Location", render: row => row.location || "-" },
                            { key: "amount", label: "Amount", align: "right", render: row => formatMoney(row.amount) }
                        ]}
                    />
                </FormSection>
            </PageCard>

        </PageContainer>

    );

};


export default UntracedSpendingPage;
