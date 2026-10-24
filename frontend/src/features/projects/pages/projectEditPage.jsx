import {
    useEffect,
    useState
} from "react";


import {
    useParams,
    useNavigate
} from "react-router-dom";


import {
    useDispatch,
    useSelector
} from "react-redux";


import {
    ArrowBack
} from "@mui/icons-material";


import {
    PageContainer,
    PageHeader,
    PageCard,
    LoadingState,
    EmptyState,
    AppAlert
} from "../../../components/ui";


import ProjectForm
    from "../components/projectForm";


import {
    updateProjectThunk
} from "../store";


import {
    getProjectByIdService
} from "../services/projectService";


// =====================================================
// PROJECT EDIT PAGE
// =====================================================

const ProjectEditPage = () => {

    const {
        id
    } = useParams();


    const navigate =
        useNavigate();


    const dispatch =
        useDispatch();


    // =====================================================
    // REDUX
    // =====================================================

    const {
        loading,
        error
    } = useSelector(
        (state) =>
            state.projects
    );


    // the error shows above the form: bring it into view
    useEffect(() => {
        if (error) window.scrollTo({ top: 0, behavior: "smooth" });
    }, [error]);


    // =====================================================
    // LOCAL STATE
    // =====================================================

    const [
        project,
        setProject
    ] = useState(null);


    const [
        loadError,
        setLoadError
    ] = useState("");


    const [
        loadingProject,
        setLoadingProject
    ] = useState(true);


    // =====================================================
    // LOAD PROJECT
    // =====================================================

    useEffect(() => {

        let mounted = true;


        const loadProject = async () => {

            if (!id) {

                if (mounted) {

                    setLoadingProject(
                        false
                    );

                    setLoadError(
                        "Project ID is required."
                    );

                }

                return;

            }


            try {

                if (mounted) {

                    setLoadingProject(
                        true
                    );

                    setLoadError("");

                }


                const response =
                    await getProjectByIdService(
                        id
                    );


                const data =
                    response?.data?.data ??
                    response?.data ??
                    response ??
                    null;


                if (!mounted) {
                    return;
                }


                if (!data) {

                    setProject(null);

                    setLoadError(
                        "The project record does not exist."
                    );

                    return;

                }


                setProject(data);

            }
            catch (error) {

                console.error(
                    "LOAD PROJECT ERROR:",
                    error
                );


                if (!mounted) {
                    return;
                }


                setProject(null);


                setLoadError(
                    error?.response?.data?.message ||
                    error?.message ||
                    "Failed to load project."
                );

            }
            finally {

                if (mounted) {

                    setLoadingProject(
                        false
                    );

                }

            }

        };


        loadProject();


        return () => {

            mounted = false;

        };

    }, [id]);


    // =====================================================
    // UPDATE PROJECT
    // =====================================================

    const handleSubmit = async (
        data
    ) => {

        try {



            await dispatch(
                updateProjectThunk({
                    id,
                    data
                })
            ).unwrap();


            navigate(
                "/projects"
            );

        }
        catch (error) {

            console.error(
                "UPDATE PROJECT ERROR:",
                error
            );

        }

    };


    // =====================================================
    // LOADING
    // =====================================================

    if (loadingProject) {

        return (

            <PageContainer>

                <PageHeader

                    title="Edit Project"

                    subtitle={
                        "Loading project information"
                    }

                    action={() =>
                        navigate(
                            "/projects"
                        )
                    }

                    actionLabel="Back"

                    actionIcon={
                        <ArrowBack />
                    }

                />


                <PageCard>

                    <LoadingState
                        message="Loading project..."
                    />

                </PageCard>

            </PageContainer>

        );

    }


    // =====================================================
    // NOT FOUND / LOAD ERROR
    // =====================================================

    if (!project) {

        return (

            <PageContainer>

                <PageHeader

                    title="Edit Project"

                    subtitle={
                        "Update project information"
                    }

                    action={() =>
                        navigate(
                            "/projects"
                        )
                    }

                    actionLabel="Back"

                    actionIcon={
                        <ArrowBack />
                    }

                />


                {loadError && (

                    <AppAlert

                        severity="error"

                        message={
                            loadError
                        }

                    />

                )}


                <PageCard>

                    <EmptyState

                        title="Project not found"

                        message={
                            loadError ||
                            "The project record does not exist."
                        }

                    />

                </PageCard>

            </PageContainer>

        );

    }


    // =====================================================
    // RENDER
    // =====================================================

    return (

        <PageContainer>


            {/* =================================================
                HEADER
            ================================================= */}

            <PageHeader

                title="Edit Project"

                subtitle={
                    project.name ||
                    "Update project information"
                }

                action={() =>
                    navigate(
                        "/projects"
                    )
                }

                actionLabel="Back"

                actionIcon={
                    <ArrowBack />
                }

            />


            {/* =================================================
                REDUX ERROR
            ================================================= */}

            {error && (

                <AppAlert

                    severity="error"

                    message={
                        typeof error === "string"
                            ? error
                            : error?.message ||
                              "Failed to update project."
                    }

                />

            )}


            {/* =================================================
                FORM
            ================================================= */}

            <PageCard>

                <ProjectForm

                    initialData={
                        project
                    }

                    onSubmit={
                        handleSubmit
                    }

                    loading={
                        loading
                    }

                />

            </PageCard>


        </PageContainer>

    );

};


export default ProjectEditPage;