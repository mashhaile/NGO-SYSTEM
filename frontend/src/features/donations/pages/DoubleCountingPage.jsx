import {
    useEffect,
    useState
} from "react";


import {
    useNavigate
} from "react-router-dom";


import {
    Alert,
    Link,
    Stack
} from "@mui/material";


import {
    ArrowBack
} from "@mui/icons-material";


import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    LoadingState,
    ErrorState,
    AppButton
} from "../../../components/ui";


import TraceTable
    from "../components/TraceTable";


import {
    formatMoney,
    formatDate
} from "../api/donationTraceApi";


import {
    getDoubleCountingApi,
    setExpenseLinkApi
} from "../../ServiceDelivery/api/serviceDeliveryApi";



// =====================================================
// POSSIBLE DOUBLE COUNTING
// =====================================================
//
// A delivery item and an expense on the same donation
// with about the same amount, not linked: probably the
// same money (kits bought with the expense, then given
// out), so the donation is charged twice. Staff either
// link them (charged once, by the expense) or mark them
// as separate (not suggested again).
//
// =====================================================

const DoubleCountingPage = () => {

    const navigate =
        useNavigate();

    const [rows, setRows] =
        useState(null);

    const [error, setError] =
        useState("");

    const [busy, setBusy] =
        useState("");

    const [reload, setReload] =
        useState(0);


    useEffect(() => {

        let cancelled = false;

        getDoubleCountingApi()

            .then(data => {
                if (!cancelled) {
                    setRows(data);
                }
            })

            .catch(loadError => {
                if (!cancelled) {
                    setError(
                        loadError?.response?.data?.message ||
                        "Failed to load the review."
                    );
                }
            });

        return () => {
            cancelled = true;
        };

    }, [reload]);


    const act = async (row, separate) => {

        const key = `${row.item._id}-${row.expense._id}`;

        setBusy(key);
        setError("");

        try {
            await setExpenseLinkApi(row.delivery._id, row.item._id, { expense: row.expense._id, separate });
            setReload(value => value + 1);
        }
        catch (actionError) {
            setError(actionError?.response?.data?.message || "Could not save.");
        }
        finally {
            setBusy("");
        }

    };


    const header = (

        <PageHeader
            title="Possible Double Counting"
            subtitle="Items given out and expenses on the same donation with about the same amount, not linked."
            action={() => navigate("/donations")}
            actionLabel="Back to Donations"
            actionIcon={<ArrowBack />}
        />

    );


    if (!rows && !error) {
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

            {error && (
                rows
                    ? <Alert severity="error" sx={{ mb: 3 }}>{error}</Alert>
                    : <ErrorState message={error} />
            )}

            {rows && (rows.length === 0
                ? (
                    <Alert severity="success">
                        Nothing to review: no item and expense on the same donation look like the same money.
                    </Alert>
                )
                : (
                    <Alert severity="warning" sx={{ mb: 3 }}>
                        Each line is a delivery item and an expense on the same donation with about the same amount. If the items were bought with that expense, choose <strong>Link</strong>: the donation is then charged once, by the expense. If they are different money, choose <strong>Separate</strong>: the pair is not shown again.
                    </Alert>
                ))}

            {rows && rows.length > 0 && (

                <PageCard>
                    <FormSection title="To review">
                        <TraceTable
                            rows={rows}
                            getRowKey={row => `${row.item._id}-${row.expense._id}`}
                            empty="Nothing to review."
                            columns={[
                                { key: "donation", label: "Donation", render: row => `${row.donation.donationCode} ${row.donation.title || ""}` },
                                {
                                    key: "delivery",
                                    label: "Given out",
                                    render: row => (
                                        <Link component="button" underline="hover" onClick={() => navigate(`/service-deliveries/${row.delivery._id}`)}>
                                            {row.delivery.deliveryNumber} · {row.item.name} ({formatDate(row.delivery.deliveryDate)})
                                        </Link>
                                    )
                                },
                                { key: "itemValue", label: "Item", align: "right", render: row => formatMoney(row.item.value, row.donation.currency) },
                                {
                                    key: "expense",
                                    label: "Expense",
                                    render: row => (
                                        <Link component="button" underline="hover" onClick={() => navigate(`/expenses/${row.expense._id}`)}>
                                            {row.expense.expenseCode}{row.expense.description ? ` · ${row.expense.description}` : ""} ({formatDate(row.expense.expenseDate)})
                                        </Link>
                                    )
                                },
                                { key: "expenseValue", label: "Not yet linked", align: "right", render: row => formatMoney(row.expense.value, row.donation.currency) },
                                {
                                    key: "actions",
                                    label: "",
                                    render: row => (
                                        <Stack direction="row" spacing={1}>
                                            <AppButton size="small" variant="contained" loading={busy === `${row.item._id}-${row.expense._id}`} disabled={Boolean(busy)} onClick={() => act(row, false)}>
                                                Link
                                            </AppButton>
                                            <AppButton size="small" variant="outlined" disabled={Boolean(busy)} onClick={() => act(row, true)}>
                                                Separate
                                            </AppButton>
                                        </Stack>
                                    )
                                }
                            ]}
                        />
                    </FormSection>
                </PageCard>

            )}

        </PageContainer>

    );

};


export default DoubleCountingPage;
