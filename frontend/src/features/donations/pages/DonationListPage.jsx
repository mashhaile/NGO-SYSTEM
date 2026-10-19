import {
    useCallback,
    useEffect,
    useState
} from "react";

import {
    useNavigate
} from "react-router-dom";

import {
    Add,
    Refresh,
    WarningAmber
} from "@mui/icons-material";

import {
    useDonations
} from "../hooks/useDonations";

import DonationTable
    from "../components/DonationTable";

import {
    PageContainer,
    PageHeader,
    StatsCards,
    SearchToolbar,
    PageCard,
    EmptyState,
    LoadingState,
    AppAlert,
    AppButton,
    ActionToolbar,
    AppPagination
} from "../../../components/ui";


const DonationListPage = () => {

    const navigate =
        useNavigate();


    // =====================================================
    // LOCAL STATE
    // =====================================================

    const [search, setSearch] =
        useState("");

    const [page, setPage] =
        useState(1);

    const [limit, setLimit] =
        useState(10);


    // =====================================================
    // GET DONATIONS
    // =====================================================

    const {
        data,
        isLoading,
        error,
        refetch
    } = useDonations();


    // =====================================================
    // DONATIONS
    // =====================================================

    const donations =
        Array.isArray(data?.data)
            ? data.data
            : [];


    // =====================================================
    // SEARCH
    // =====================================================

    const handleSearch = useCallback(
        (value) => {

            setSearch(value);
            setPage(1);

        },
        []
    );


    // =====================================================
    // LIMIT
    // =====================================================

    const handleLimitChange = (
        value
    ) => {

        setLimit(
            Number(value)
        );

        setPage(1);

    };


    // =====================================================
    // RESET
    // =====================================================

    const resetSearch = () => {

        setSearch("");
        setPage(1);

    };


    // =====================================================
    // REFRESH
    // =====================================================

    const handleRefresh = () => {

        refetch();

    };


    // =====================================================
    // SEARCH FILTER
    // =====================================================

    const filteredDonations =
        donations.filter(
            (donation) => {

                if (!search.trim()) {
                    return true;
                }

                const value =
                    search
                        .trim()
                        .toLowerCase();

                return (

                    String(
                        donation?.title || ""
                    )
                        .toLowerCase()
                        .includes(value)

                    ||

                    String(
                        donation?.donationCode || ""
                    )
                        .toLowerCase()
                        .includes(value)

                    ||

                    String(
                        donation?.donor?.name ||
                        donation?.donorName ||
                        ""
                    )
                        .toLowerCase()
                        .includes(value)

                    ||

                    String(
                        donation?.referenceNumber || ""
                    )
                        .toLowerCase()
                        .includes(value)

                );

            }
        );


    // =====================================================
    // STATS
    // =====================================================

    const totalDonations =
        donations.length;

    const currentRecords =
        filteredDonations.length;

    const receivedCount =
        donations.filter(
            (donation) =>
                String(
                    donation?.status || ""
                )
                    .trim()
                    .toLowerCase() ===
                "received"
        ).length;


    // =====================================================
    // PAGINATION
    // =====================================================

    const totalPages =
        Math.ceil(
            filteredDonations.length /
            limit
        );

    const paginatedDonations =
        filteredDonations.slice(
            (page - 1) * limit,
            page * limit
        );


    // =====================================================
    // KEEP PAGE VALID
    // =====================================================

    useEffect(() => {

        if (
            totalPages > 0 &&
            page > totalPages
        ) {

            setPage(totalPages);

        }

    }, [
        page,
        totalPages
    ]);


    // =====================================================
    // RENDER
    // =====================================================

    return (

        <PageContainer>


            {/* =================================================
                HEADER
            ================================================= */}

            <PageHeader

                title="Donations"

                subtitle={
                    "Manage donation records and contributions"
                }

                action={() =>
                    navigate(
                        "/donations/create"
                    )
                }

                actionLabel="Add Donation"

                actionIcon={
                    <Add />
                }

            />


            {/* =================================================
                ACTIONS
            ================================================= */}

            <PageCard>

                <ActionToolbar>

                    <AppButton
                        variant="outlined"
                        startIcon={
                            <Refresh />
                        }
                        onClick={
                            handleRefresh
                        }
                        loading={
                            isLoading
                        }
                    >
                        Refresh
                    </AppButton>

                    <AppButton
                        variant="outlined"
                        color="warning"
                        startIcon={
                            <WarningAmber />
                        }
                        onClick={() =>
                            navigate(
                                "/donations/untraced"
                            )
                        }
                    >
                        Untraced Spending
                    </AppButton>

                </ActionToolbar>

            </PageCard>


            {/* =================================================
                STATISTICS
            ================================================= */}

            <StatsCards

                items={[

                    {
                        label:
                            "Total Donations",

                        value:
                            totalDonations
                    },

                    {
                        label:
                            "Current Records",

                        value:
                            currentRecords
                    },

                    {
                        label:
                            "Received",

                        value:
                            receivedCount
                    }

                ]}

            />


            {/* =================================================
                SEARCH
            ================================================= */}

            <SearchToolbar

                search={
                    search
                }

                onSearch={
                    handleSearch
                }

                onReset={
                    resetSearch
                }

                filters={[

                    {
                        key:
                            "limit",

                        label:
                            "Rows",

                        value:
                            limit,

                        onChange:
                            handleLimitChange,

                        options: [

                            {
                                value: 10,
                                label: "10"
                            },

                            {
                                value: 25,
                                label: "25"
                            },

                            {
                                value: 50,
                                label: "50"
                            }

                        ]

                    }

                ]}

            />


            {/* =================================================
                ERROR
            ================================================= */}

            {error && (

                <AppAlert
                    severity="error"
                    message={
                        error
                            ?.response
                            ?.data
                            ?.message ||

                        error
                            ?.message ||

                        "Failed to fetch donations"
                    }
                />

            )}


            {/* =================================================
                TABLE
            ================================================= */}

            <PageCard>

                {isLoading ? (

                    <LoadingState
                        message={
                            "Loading donations..."
                        }
                    />

                ) : paginatedDonations.length === 0 ? (

                    <EmptyState

                        title={
                            "No donations found"
                        }

                        message={
                            search
                                ? "No donations match your search."
                                : "Add your first donation record."
                        }

                    />

                ) : (

                    <DonationTable

                        data={
                            paginatedDonations
                        }

                        loading={
                            isLoading
                        }

                    />

                )}

            </PageCard>


            {/* =================================================
                PAGINATION
            ================================================= */}

            {totalPages > 1 && (

                <AppPagination

                    page={
                        page
                    }

                    count={
                        totalPages
                    }

                    onChange={(
                        _event,
                        value
                    ) => {

                        setPage(
                            value
                        );

                    }}

                />

            )}

        </PageContainer>

    );

};


export default DonationListPage;
