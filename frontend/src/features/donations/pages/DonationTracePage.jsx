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
    Box,
    Chip,
    Grid,
    LinearProgress,
    Link,
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
    FormSection,
    InfoRow,
    AppButton,
    LoadingState,
    ErrorState
} from "../../../components/ui";


import TraceTable
    from "../components/TraceTable";


import {
    getDonationTraceApi,
    downloadDonationStatementApi,
    formatMoney,
    formatDate
} from "../api/donationTraceApi";



// =====================================================
// SUMMARY TILE
// =====================================================

const Tile = ({
    label,
    value,
    hint
}) => (

    <PageCard
        sx={{
            height: "100%"
        }}
    >

        <Typography
            variant="body2"
            color="text.secondary"
        >
            {label}
        </Typography>

        <Typography
            variant="h6"
            fontWeight={700}
            sx={{ mt: 0.5 }}
        >
            {value}
        </Typography>

        {hint && (
            <Typography
                variant="caption"
                color="text.secondary"
            >
                {hint}
            </Typography>
        )}

    </PageCard>

);


const nameOf = (item) =>
    item
        ? [item.code, item.name].filter(Boolean).join(" - ")
        : "-";


const CountChips = ({ items }) =>
    items?.length
        ? (
            <Stack
                direction="row"
                spacing={1}
                useFlexGap
                flexWrap="wrap"
            >
                {items.map(item => (
                    <Chip
                        key={item.label}
                        size="small"
                        label={`${item.label}: ${item.count}`}
                    />
                ))}
            </Stack>
        )
        : "-";



// =====================================================
// DONATION TRACE PAGE
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


    const {
        donation,
        totals,
        breakdown,
        reach
    } = trace;

    const currency =
        totals.currency;


    const handlePdf = async () => {

        setPdfError("");

        try {

            await downloadDonationStatementApi(
                id,
                `${donation.code}-statement.pdf`
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
                        {donation.donor?.shareBeneficiaryNames
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


            {donation.fundingRestriction === "Unrestricted" && (

                <Alert
                    severity="info"
                    sx={{ mb: 3 }}
                >
                    This is an unrestricted donation. Only spending recorded against it is shown here.
                </Alert>

            )}


            {/* SUMMARY TILES */}

            <Grid
                container
                spacing={2}
                sx={{ mb: 3 }}
            >

                <Grid size={{ xs: 12, sm: 6, md: 3 }}>
                    <Tile
                        label="Received"
                        value={formatMoney(totals.received, currency)}
                        hint={totals.pledged ? `Pledged: ${formatMoney(totals.pledged, currency)}` : donation.status}
                    />
                </Grid>

                <Grid size={{ xs: 12, sm: 6, md: 3 }}>
                    <Tile
                        label="Used so far"
                        value={formatMoney(totals.used, currency)}
                        hint={`${totals.percentUsed}% of received`}
                    />
                </Grid>

                <Grid size={{ xs: 12, sm: 6, md: 3 }}>
                    <Tile
                        label="Remaining"
                        value={formatMoney(totals.remaining, currency)}
                        hint={totals.overspent ? `Overspent by ${formatMoney(totals.overspent, currency)}` : " "}
                    />
                </Grid>

                <Grid size={{ xs: 12, sm: 6, md: 3 }}>
                    <Tile
                        label="Reached"
                        value={`${totals.beneficiariesReached} people`}
                        hint={`${totals.groupsReached} groups / institutions · ${totals.deliveries} deliveries`}
                    />
                </Grid>

            </Grid>


            <PageCard sx={{ mb: 3 }}>

                <Stack
                    direction="row"
                    justifyContent="space-between"
                    sx={{ mb: 1 }}
                >
                    <Typography variant="body2" fontWeight={600}>
                        Utilization
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                        {totals.percentUsed}% used
                    </Typography>
                </Stack>

                <LinearProgress
                    variant="determinate"
                    value={Math.min(totals.percentUsed, 100)}
                    color={totals.overspent ? "error" : "primary"}
                    sx={{
                        height: 10,
                        borderRadius: 5
                    }}
                />

            </PageCard>


            {/* DONATION */}

            <PageCard>
                <FormSection title="Donation">
                    <InfoRow label="Donation" value={[donation.code, donation.title].filter(Boolean).join(" - ")} />
                    <InfoRow label="Donor" value={donation.donor?.name} />
                    <InfoRow label="Date" value={formatDate(donation.date)} />
                    <InfoRow label="Program" value={nameOf(donation.program)} />
                    <InfoRow label="Project" value={nameOf(donation.project)} />
                    <InfoRow label="Restriction" value={donation.fundingRestriction} />
                </FormSection>
            </PageCard>


            {/* WHAT IT PAID FOR */}

            <PageCard>
                <FormSection title="What It Paid For">
                    <TraceTable
                        rows={breakdown.byService}
                        getRowKey={(row) => `${row.service}-${row.unit}`}
                        empty="No services have been recorded against this donation yet."
                        columns={[
                            { key: "service", label: "Service" },
                            { key: "quantity", label: "Quantity", align: "right", render: row => `${row.quantity} ${row.unit}`.trim() },
                            { key: "deliveries", label: "Deliveries", align: "right" },
                            { key: "amount", label: "Amount", align: "right", render: row => formatMoney(row.amount, currency) }
                        ]}
                    />
                </FormSection>
            </PageCard>


            {/* WHERE */}

            <PageCard>
                <FormSection title="Where It Was Used">

                    <Box sx={{ display: "grid", gap: 2 }}>

                        <TraceTable
                            rows={breakdown.byLocation}
                            getRowKey={(row) => row.location}
                            empty="No locations recorded yet."
                            columns={[
                                { key: "location", label: "Location" },
                                { key: "deliveries", label: "Deliveries", align: "right" },
                                { key: "amount", label: "Amount", align: "right", render: row => formatMoney(row.amount, currency) }
                            ]}
                        />

                        <TraceTable
                            rows={breakdown.byProject}
                            getRowKey={(row) => row.project?.id}
                            empty=""
                            columns={[
                                { key: "project", label: "Project", render: row => nameOf(row.project) },
                                { key: "deliveries", label: "Deliveries", align: "right" },
                                { key: "amount", label: "Amount", align: "right", render: row => formatMoney(row.amount, currency) }
                            ]}
                        />

                    </Box>

                </FormSection>
            </PageCard>


            {/* WHO */}

            <PageCard>
                <FormSection title="People Reached">
                    <InfoRow label="Total" value={`${reach.total} people`} />
                    <InfoRow label="By gender" value={<CountChips items={reach.byGender} />} />
                    <InfoRow label="By age" value={<CountChips items={reach.byAge} />} />
                    <InfoRow label="By region" value={<CountChips items={reach.byRegion} />} />
                    <InfoRow label="By woreda" value={<CountChips items={reach.byWoreda} />} />
                    <InfoRow
                        label="Groups / institutions"
                        value={
                            reach.groups.length
                                ? reach.groups.map(group => `${group.recipientName} (${group.recipientType})`).join(", ")
                                : "-"
                        }
                    />
                </FormSection>
            </PageCard>


            {/* DELIVERIES */}

            <PageCard>
                <FormSection title="Deliveries Funded">
                    <TraceTable
                        rows={trace.deliveries}
                        empty="No deliveries yet."
                        columns={[
                            { key: "date", label: "Date", render: row => formatDate(row.date) },
                            {
                                key: "deliveryNumber",
                                label: "Reference",
                                render: row => (
                                    <Link
                                        component="button"
                                        underline="hover"
                                        onClick={() => navigate(`/service-deliveries/${row.id}`)}
                                    >
                                        {row.deliveryNumber}
                                    </Link>
                                )
                            },
                            { key: "services", label: "Services", render: row => row.services.map(s => s.service).join(", ") },
                            { key: "location", label: "Location", render: row => row.location || "-" },
                            {
                                key: "beneficiaries",
                                label: "Reached",
                                align: "right",
                                render: row =>
                                    row.beneficiaries > 0 || row.recipientType === "Individual"
                                        ? row.beneficiaries
                                        : row.recipientType
                            },
                            { key: "amount", label: "Amount", align: "right", render: row => formatMoney(row.amount, currency) }
                        ]}
                    />
                </FormSection>
            </PageCard>


            {/* ACTIVITIES + TORS */}

            <PageCard>
                <FormSection title="Activities and Approved Plans">

                    <Box sx={{ display: "grid", gap: 2 }}>

                        <TraceTable
                            rows={trace.activities}
                            getRowKey={(row) => row.run?.id}
                            empty="No activity sessions linked."
                            columns={[
                                { key: "activity", label: "Activity", render: row => row.activity?.name || "-" },
                                { key: "run", label: "Session / batch", render: row => row.run?.name || "-" },
                                { key: "dates", label: "Dates", render: row => row.startDate ? `${formatDate(row.startDate)}${row.endDate ? ` – ${formatDate(row.endDate)}` : ""}` : "-" },
                                { key: "attended", label: "Attended", align: "right" }
                            ]}
                        />

                        {trace.tors.length > 0 && (
                            <TraceTable
                                rows={trace.tors}
                                empty=""
                                columns={[
                                    {
                                        key: "torNumber",
                                        label: "Approved TOR",
                                        render: row => (
                                            <Link
                                                component="button"
                                                underline="hover"
                                                onClick={() => navigate(`/tors/${row.id}`)}
                                            >
                                                {row.torNumber} – {row.title}
                                            </Link>
                                        )
                                    },
                                    { key: "plannedBudget", label: "Planned budget", align: "right", render: row => formatMoney(row.plannedBudget, row.currency) }
                                ]}
                            />
                        )}

                    </Box>

                </FormSection>
            </PageCard>


            {/* TIMELINE */}

            <PageCard>
                <FormSection title="Timeline">
                    {trace.timeline.map((event, index) => (
                        <InfoRow
                            key={`${event.date}-${index}`}
                            label={formatDate(event.date)}
                            value={
                                <>
                                    <strong>{event.type}</strong>
                                    {event.reference ? ` · ${event.reference}` : ""}
                                    {" · "}
                                    {event.label}
                                    {" · "}
                                    {formatMoney(event.amount, currency)}
                                </>
                            }
                        />
                    ))}
                </FormSection>
            </PageCard>


            {/* NAMES (staff only, beneficiary.read) */}

            {trace.namesIncluded && (

                <PageCard>
                    <FormSection
                        title="Beneficiaries"
                        subtitle={
                            donation.donor?.shareBeneficiaryNames
                                ? "Staff view. This donor's statement also includes these names."
                                : "Staff view only. Names are NOT included in this donor's statement."
                        }
                    >
                        <TraceTable
                            rows={trace.beneficiaries || []}
                            getRowKey={(row) => row.number || row.name}
                            empty="No individual beneficiaries recorded yet."
                            columns={[
                                { key: "number", label: "No." },
                                { key: "name", label: "Name" },
                                { key: "gender", label: "Gender" },
                                { key: "ageGroup", label: "Age group" },
                                { key: "location", label: "Location", render: row => [row.kebele && `Kebele ${row.kebele}`, row.location].filter(Boolean).join(", ") || "-" },
                                { key: "value", label: "Support value", align: "right", render: row => row.value ? formatMoney(row.value, currency) : "-" }
                            ]}
                        />
                    </FormSection>
                </PageCard>

            )}


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
