import {
    useEffect,
    useState
} from "react";


import {
    useNavigate
} from "react-router-dom";


import {
    LinearProgress,
    Link,
    Stack,
    Typography
} from "@mui/material";


import {
    PageCard,
    FormSection,
    InfoRow
} from "../../../components/ui";


import TraceTable
    from "./TraceTable";


import {
    getDonorTraceApi,
    formatMoney,
    formatDate
} from "../api/donationTraceApi";



// =====================================================
// DONOR: DONATIONS AND WHERE THEY WENT
// =====================================================

const DonorTraceSection = ({
    donorId
}) => {

    const navigate =
        useNavigate();

    const [trace, setTrace] =
        useState(null);

    const [error, setError] =
        useState("");


    useEffect(() => {

        let cancelled = false;

        getDonorTraceApi(donorId)

            .then(data => {
                if (!cancelled) {
                    setTrace(data);
                }
            })

            .catch(() => {
                if (!cancelled) {
                    setError("Could not load donation tracing for this donor.");
                }
            });

        return () => {
            cancelled = true;
        };

    }, [donorId]);


    return (

        <PageCard>

            <FormSection
                title="Donations and Where They Went"
                subtitle="Open a donation to see the services, places and people it reached."
            >

                {error && (
                    <Typography variant="body2" color="error">
                        {error}
                    </Typography>
                )}

                {!trace && !error && (
                    <LinearProgress />
                )}

                {trace && (

                    <>

                        <InfoRow label="Received" value={formatMoney(trace.totals.received)} />

                        <InfoRow
                            label="Used so far"
                            value={`${formatMoney(trace.totals.used)} (${trace.totals.percentUsed}%)`}
                        />

                        <InfoRow label="Remaining" value={formatMoney(trace.totals.remaining)} />

                        <InfoRow
                            label="People reached"
                            value={`${trace.totals.beneficiariesReached} (counted once across all donations)`}
                        />

                        <InfoRow
                            label="Beneficiary names"
                            value={
                                trace.donor.shareBeneficiaryNames
                                    ? "Shared with this donor"
                                    : "Not shared (numbers only)"
                            }
                        />

                        <Stack sx={{ mt: 2 }}>

                            <TraceTable
                                rows={trace.donations}
                                empty="This donor has no donations yet."
                                columns={[
                                    {
                                        key: "code",
                                        label: "Donation",
                                        render: row => (
                                            <Link
                                                component="button"
                                                underline="hover"
                                                fontWeight={600}
                                                onClick={() =>
                                                    navigate(`/donations/${row.id}/trace`)
                                                }
                                            >
                                                {[row.code, row.title].filter(Boolean).join(" - ")}
                                            </Link>
                                        )
                                    },
                                    { key: "date", label: "Date", render: row => formatDate(row.date) },
                                    { key: "received", label: "Received", align: "right", render: row => formatMoney(row.totals.received, row.currency) },
                                    { key: "used", label: "Used", align: "right", render: row => `${formatMoney(row.totals.used, row.currency)} (${row.totals.percentUsed}%)` },
                                    { key: "reached", label: "People", align: "right", render: row => row.totals.beneficiariesReached }
                                ]}
                            />

                        </Stack>

                    </>

                )}

            </FormSection>

        </PageCard>

    );

};


export default DonorTraceSection;
