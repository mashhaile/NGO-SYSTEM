import {
    useEffect,
    useState,
    useCallback
} from "react";

import {
    useDispatch,
    useSelector
} from "react-redux";

import {
    useNavigate
} from "react-router-dom";

import {
    Add,
    UploadFile,
    Download,
    Refresh
} from "@mui/icons-material";

import {
    getBeneficiariesThunk
} from "../store";

import BeneficiaryTable
    from "../components/BeneficiaryTable";

import {
    PageContainer,
    PageHeader,
    StatsCards,
    SearchToolbar,
    PageCard,
    EmptyState,
    LoadingState,
    AppButton,
    AppAlert,
    ActionToolbar,
    AppPagination
} from "../../../components/ui";


const BeneficiaryListPage = () => {

    const dispatch = useDispatch();

    const navigate = useNavigate();


    // =====================================================
    // REDUX
    // =====================================================

    const {
        beneficiaries = [],
        pagination = {},
        loading,
        error
    } = useSelector(
        (state) => state.beneficiaries
    );


    // =====================================================
    // LOCAL STATE
    // =====================================================

    const [search, setSearch] = useState("");

    const [page, setPage] = useState(1);

    const [limit, setLimit] = useState(10);


    // =====================================================
    // LOAD DATA
    // =====================================================

    const loadData = useCallback(() => {

        dispatch(
            getBeneficiariesThunk({
                search: search.trim(),
                page,
                limit
            })
        );

    }, [
        dispatch,
        search,
        page,
        limit
    ]);


    // =====================================================
    // SEARCH / PAGINATION LOAD
    // =====================================================

    useEffect(() => {

        const timer = setTimeout(() => {

            loadData();

        }, 400);


        return () => {

            clearTimeout(timer);

        };

    }, [loadData]);


    // =====================================================
    // SEARCH
    // =====================================================

    const handleSearch = (value) => {

        setSearch(value);

        setPage(1);

    };


    // =====================================================
    // ROW LIMIT
    // =====================================================

    const handleLimitChange = (value) => {

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

        loadData();

    };


    // =====================================================
    // EXPORT
    // =====================================================

    const handleExport = () => {

        console.log(
            "Export beneficiaries"
        );

        // Connect export service later.

    };


    // =====================================================
    // STATISTICS
    // =====================================================

    const totalBeneficiaries =
        Number(
            pagination?.totalRecords
        ) || 0;


    const currentRecords =
        beneficiaries.length;


    const activeCount =
        Number(
            pagination?.totalActive
        ) || 0;


    // =====================================================
    // RENDER
    // =====================================================

    return (

        <PageContainer>


            {/* =================================================
                HEADER
            ================================================= */}

            <PageHeader

                title="Beneficiaries"

                subtitle={
                    "Manage beneficiary registration and records"
                }

                action={() =>
                    navigate(
                        "/beneficiaries/create"
                    )
                }

                actionLabel="Add Beneficiary"

                actionIcon={
                    <Add />
                }

            />


            {/* =================================================
                PAGE ACTIONS
            ================================================= */}

            <PageCard>

                <ActionToolbar>

                    <AppButton
                        variant="outlined"
                        startIcon={
                            <UploadFile />
                        }
                        onClick={() =>
                            navigate(
                                "/beneficiaries/import"
                            )
                        }
                    >
                        Import Excel
                    </AppButton>


                    <AppButton
                        variant="outlined"
                        startIcon={
                            <Download />
                        }
                        onClick={
                            handleExport
                        }
                    >
                        Export
                    </AppButton>


                    <AppButton
                        variant="outlined"
                        startIcon={
                            <Refresh />
                        }
                        onClick={
                            handleRefresh
                        }
                        loading={
                            loading
                        }
                    >
                        Refresh
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
                            "Total Beneficiaries",

                        value:
                            totalBeneficiaries
                    },

                    {
                        label:
                            "Current Records",

                        value:
                            currentRecords
                    },

                    {
                        label:
                            "Active",

                        value:
                            activeCount
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
                    }
                />

            )}


            {/* =================================================
                TABLE
            ================================================= */}

            <PageCard>

                {loading ? (

                    <LoadingState
                        message={
                            "Loading beneficiaries..."
                        }
                    />

                ) : beneficiaries.length === 0 ? (

                    <EmptyState

                        title={
                            "No beneficiaries found"
                        }

                        message={
                            search
                                ? "No beneficiaries match your search."
                                : "Add your first beneficiary record."
                        }

                    />

                ) : (

                    <BeneficiaryTable

                        data={
                            beneficiaries
                        }

                        loading={
                            loading
                        }

                    />

                )}

            </PageCard>


            {/* =================================================
                PAGINATION
            ================================================= */}

            {Number(
                pagination?.totalPages
            ) > 1 && (

                <AppPagination

                    page={
                        page
                    }

                    count={
                        Number(
                            pagination?.totalPages
                        ) || 1
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


export default BeneficiaryListPage;
