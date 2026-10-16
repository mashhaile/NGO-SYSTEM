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
    Add
} from "@mui/icons-material";


import {
    getProjectsThunk
} from "../store";


import ProjectTable
    from "../components/projectTable";


import {
    PageContainer,
    PageHeader,
    StatsCards,
    SearchToolbar,
    PageCard,
    EmptyState,
    LoadingState,
    AppAlert,
    AppPagination
} from "../../../components/ui";


// =====================================================
// PROJECT LIST PAGE
// =====================================================

const ProjectListPage = () => {

    const dispatch = useDispatch();

    const navigate = useNavigate();


    // =====================================================
    // REDUX
    // =====================================================

    const {
        projects: projectData,
        loading,
        error,
        pagination = {}
    } = useSelector(
        (state) => state.projects
    );


    const projects =
        Array.isArray(projectData)
            ? projectData
            : [];


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
    // PAGINATION
    // =====================================================

    const totalPages =
        pagination?.totalPages ??
        pagination?.pages ??
        0;


    const totalProjects =
        pagination?.totalRecords ??
        pagination?.total ??
        0;


    // =====================================================
    // LOAD DATA
    // =====================================================

    const loadData = useCallback(() => {

        dispatch(
            getProjectsThunk({
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
    // RESET SEARCH
    // =====================================================

    const resetSearch = () => {

        setSearch("");

        setPage(1);

    };


    // =====================================================
    // ACTIVE PROJECTS
    // =====================================================

    const activeCount =
        projects.filter(
            (item) =>
                item.status === "Active"
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

                title="Projects"

                subtitle="Manage NGO projects"

                action={() =>
                    navigate(
                        "/projects/create"
                    )
                }

                actionLabel="Add Project"

                actionIcon={
                    <Add />
                }

            />


            {/* =================================================
                STATISTICS
            ================================================= */}

            <StatsCards

                items={[

                    {
                        label:
                            "Total Projects",

                        value:
                            totalProjects
                    },


                    {
                        label:
                            "Current Records",

                        value:
                            projects.length
                    },


                    {
                        label:
                            "Active Projects",

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
                PROJECT TABLE
            ================================================= */}

            <PageCard>

                {loading ? (

                    <LoadingState
                        message="Loading projects..."
                    />

                ) : projects.length === 0 ? (

                    <EmptyState

                        title="No projects found"

                        message={
                            search
                                ? "No projects match your search."
                                : "Create your first project."
                        }

                    />

                ) : (

                    <ProjectTable

                        data={
                            projects
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


export default ProjectListPage;