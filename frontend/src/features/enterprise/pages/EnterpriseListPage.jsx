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
    Refresh
} from "@mui/icons-material";


import {
    getEnterprisesThunk,
    deleteEnterpriseThunk
} from "../store/enterpriseThunks";


import EnterpriseTable
    from "../components/EnterpriseTable";


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


// =====================================================
// ENTERPRISE LIST PAGE
// =====================================================

const EnterpriseListPage = () => {

    const dispatch =
        useDispatch();


    const navigate =
        useNavigate();


    // =====================================================
    // REDUX
    // =====================================================

    const {
        enterprises = [],
        pagination = {},
        loading = false,
        actionLoading = false,
        error = null
    } =
        useSelector(
            (state) =>
                state.enterprises
        );


    // =====================================================
    // LOCAL STATE
    // =====================================================

    const [
        search,
        setSearch
    ] = useState("");


    const [
        page,
        setPage
    ] = useState(1);


    const [
        limit,
        setLimit
    ] = useState(10);


    // =====================================================
    // LOAD DATA
    // =====================================================

    const loadData =
        useCallback(
            () => {

                dispatch(
                    getEnterprisesThunk({

                        search,

                        page,

                        limit

                    })
                );

            },
            [
                dispatch,
                search,
                page,
                limit
            ]
        );


    // =====================================================
    // SEARCH / PAGINATION LOAD
    // =====================================================

    useEffect(() => {

        const timer =
            setTimeout(
                () => {

                    loadData();

                },
                400
            );


        return () => {

            clearTimeout(
                timer
            );

        };

    }, [
        loadData
    ]);


    // =====================================================
    // SEARCH
    // =====================================================

    const handleSearch = (
        value
    ) => {

        setSearch(
            value
        );

        setPage(
            1
        );

    };


    // =====================================================
    // ROW LIMIT
    // =====================================================

    const handleLimitChange = (
        value
    ) => {

        setLimit(
            Number(value)
        );

        setPage(
            1
        );

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
    // DELETE
    // =====================================================

    const handleDelete = (
        id
    ) => {

        const confirmed =
            window.confirm(
                "Are you sure you want to delete this enterprise?"
            );


        if (!confirmed) {

            return;

        }


        dispatch(
            deleteEnterpriseThunk(
                id
            )
        );

    };


    // =====================================================
    // SAFE VALUES
    // =====================================================

    const enterpriseList =
        Array.isArray(
            enterprises
        )
            ? enterprises
            : [];


    // =====================================================
    // STATS
    // =====================================================

    const totalEnterprises =
        Number(
            pagination?.totalRecords
        ) || 0;


    const currentRecords =
        enterpriseList.length;


    const backendActiveCount =
        pagination?.totalActive ??
        pagination?.activeCount ??
        pagination?.activeRecords ??
        pagination?.active;


    const activeCount =
        backendActiveCount !== undefined &&
        backendActiveCount !== null

            ? Number(
                backendActiveCount
            ) || 0

            : enterpriseList.filter(
                (enterprise) =>
                    String(
                        enterprise?.status ??
                        ""
                    )
                        .trim()
                        .toLowerCase() ===
                    "active"
            ).length;


    const backendInactiveCount =
        pagination?.totalInactive ??
        pagination?.inactiveCount ??
        pagination?.inactiveRecords ??
        pagination?.inactive;


    const inactiveCount =
        backendInactiveCount !== undefined &&
        backendInactiveCount !== null

            ? Number(
                backendInactiveCount
            ) || 0

            : enterpriseList.filter(
                (enterprise) =>
                    String(
                        enterprise?.status ??
                        ""
                    )
                        .trim()
                        .toLowerCase() ===
                    "inactive"
            ).length;


    // =====================================================
    // PAGINATION
    // =====================================================

    const totalPages =
        Number(
            pagination?.totalPages
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

                title="Enterprises"

                subtitle={
                    "Manage beneficiary enterprises"
                }

                action={() =>
                    navigate(
                        "/enterprises/create"
                    )
                }

                actionLabel="Add Enterprise"

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
                            "Total Enterprises",

                        value:
                            totalEnterprises
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
                    },


                    {
                        label:
                            "Inactive",

                        value:
                            inactiveCount
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

            {
                error && (

                    <AppAlert

                        severity="error"

                        message={
                            typeof error === "object"
                                ? (
                                    error?.message ||
                                    "Failed to load enterprises"
                                )
                                : error
                        }

                    />

                )
            }


            {/* =================================================
                TABLE
            ================================================= */}

            <PageCard>

                {
                    loading ? (

                        <LoadingState
                            message={
                                "Loading enterprises..."
                            }
                        />

                    ) : enterpriseList.length === 0 ? (

                        <EmptyState

                            title={
                                "No enterprises found"
                            }

                            message={
                                search
                                    ? "No enterprises match your search."
                                    : "Add your first enterprise record."
                            }

                        />

                    ) : (

                        <EnterpriseTable

                            data={
                                enterpriseList
                            }

                            loading={
                                loading
                            }

                            onView={(id) =>
                                navigate(
                                    `/enterprises/${id}`
                                )
                            }

                            onEdit={(id) =>
                                navigate(
                                    `/enterprises/${id}/edit`
                                )
                            }

                            onDelete={
                                handleDelete
                            }

                            actionLoading={
                                actionLoading
                            }

                        />

                    )
                }

            </PageCard>


            {/* =================================================
                PAGINATION
            ================================================= */}

            {
                totalPages > 1 && (

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

                )
            }


        </PageContainer>

    );

};


export default EnterpriseListPage;