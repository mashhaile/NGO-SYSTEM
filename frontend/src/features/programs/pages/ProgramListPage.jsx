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
    getProgramsThunk
} from "../store";

import ProgramTable
    from "../components/ProgramTable";

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


// =====================================================
// PROGRAM LIST PAGE
// =====================================================

const ProgramListPage = () => {

    const dispatch = useDispatch();

    const navigate = useNavigate();


    // =====================================================
    // REDUX
    // =====================================================

    const {
        programs = [],
        pagination = {},
        loading,
        error
    } = useSelector(
        (state) => state.programs
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

    const loadData = useCallback(() => {

        dispatch(
            getProgramsThunk({

                search,

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

        const timer =
            setTimeout(() => {

                loadData();

            }, 400);


        return () => {

            clearTimeout(timer);

        };

    }, [
        loadData
    ]);


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
    // RESET SEARCH
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
            "Export programs"
        );

        // Connect export service later.

    };


    // =====================================================
    // STATISTICS
    // =====================================================

    const totalPrograms =
        pagination?.totalRecords ??
        pagination?.total ??
        0;


    const currentRecords =
        programs.length;


    /*
     * If backend provides totalActive,
     * use it. Otherwise calculate from
     * the currently loaded records.
     */

    const activePrograms =
        pagination?.totalActive ??
        programs.filter(
            (program) =>
                program.status === "Active"
        ).length;


    // =====================================================
    // RENDER
    // =====================================================

    return (

        <PageContainer>


            {/* =================================================
                HEADER
            ================================================= */}

            <PageHeader

                title="Programs"

                subtitle={
                    "Manage NGO programs and activities"
                }

                action={() =>
                    navigate(
                        "/programs/create"
                    )
                }

                actionLabel="Add Program"

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
                                "/programs/import"
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
                            "Total Programs",

                        value:
                            totalPrograms
                    },

                    {
                        label:
                            "Current Records",

                        value:
                            currentRecords
                    },

                    {
                        label:
                            "Active Programs",

                        value:
                            activePrograms
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
                PROGRAM TABLE
            ================================================= */}

            <PageCard>

                {loading ? (

                    <LoadingState
                        message={
                            "Loading programs..."
                        }
                    />

                ) : programs.length === 0 ? (

                    <EmptyState

                        title={
                            "No programs found"
                        }

                        message={
                            search
                                ? "No programs match your search."
                                : "Add your first program."
                        }

                    />

                ) : (

                    <ProgramTable

                        data={
                            programs
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

            {pagination?.totalPages > 1 && (

                <AppPagination

                    page={
                        page
                    }

                    count={
                        pagination.totalPages
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


export default ProgramListPage;