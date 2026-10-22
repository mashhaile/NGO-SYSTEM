import {
    useEffect,
    useState
} from "react";


import {
    useParams,
    useNavigate
} from "react-router-dom";


import {
    useDispatch
} from "react-redux";


import {
    Edit
} from "@mui/icons-material";


import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    InfoRow,
    AppButton,
    ConfirmDeleteDialog,
    LoadingState,
    StatusChip
} from "../../../components/ui";

import useAuth
    from "../../auth/hooks/useAuth";

import BudgetFigureCard
    from "../../budgets/components/BudgetFigureCard";


import {
    deleteProjectThunk
} from "../store";


import {
    getProjectByIdService
} from "../services/projectService";


const ProjectDetailsPage = () => {

    const {
        id
    } = useParams();


    const navigate = useNavigate();

    const { user } = useAuth();


    const dispatch = useDispatch();


    const [
        project,
        setProject
    ] = useState(null);


    const [
        loading,
        setLoading
    ] = useState(true);


    const [
        error,
        setError
    ] = useState("");


    const [
        openDelete,
        setOpenDelete
    ] = useState(false);


    // =====================================================
    // LOAD PROJECT
    // =====================================================

    useEffect(() => {

        if (!id) {
            return;
        }

        loadProject();

    }, [id]);


    const loadProject = async () => {

        try {

            setLoading(true);

            setError("");


            const response =
                await getProjectByIdService(id);


            const data =
                response?.data?.data ||
                response?.data ||
                response;


            setProject(data);

        }
        catch (error) {

            console.error(
                "Failed to load project:",
                error
            );


            setError(
                error?.response?.data?.message ||
                "Failed to load project"
            );

        }
        finally {

            setLoading(false);

        }

    };


    // =====================================================
    // DELETE PROJECT
    // =====================================================

    const remove = async () => {

        try {

            const result = await dispatch(
                deleteProjectThunk(id)
            );


            if (
                deleteProjectThunk.fulfilled?.match &&
                deleteProjectThunk.fulfilled.match(result)
            ) {

                navigate(
                    "/projects"
                );

                return;

            }


            navigate(
                "/projects"
            );

        }
        catch (error) {

            console.error(
                "DELETE PROJECT ERROR:",
                error
            );

        }

    };


    // =====================================================
    // FORMAT DATE
    // =====================================================

    const formatDate = (value) => {

        if (!value) {
            return "-";
        }


        return new Date(
            value
        ).toLocaleDateString();

    };


    // =====================================================
    // LOADING
    // =====================================================

    if (loading) {

        return (

            <PageContainer>

                <PageHeader
                    title="Project Details"
                    subtitle="Loading project information"
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
    // ERROR
    // =====================================================

    if (error) {

        return (

            <PageContainer>

                <PageHeader
                    title="Project Details"
                    subtitle="Unable to load project information"
                />

                <PageCard>

                    <FormSection
                        title="Error"
                    >

                        <InfoRow
                            label="Message"
                            value={error}
                        />

                    </FormSection>

                </PageCard>


                <AppButton
                    variant="outlined"
                    onClick={() =>
                        navigate(
                            "/projects"
                        )
                    }
                    sx={{
                        mt: 3,
                        mb: 5
                    }}
                >
                    Back to Projects
                </AppButton>

            </PageContainer>

        );

    }


    // =====================================================
    // NOT FOUND
    // =====================================================

    if (!project) {

        return (

            <PageContainer>

                <PageHeader
                    title="Project Details"
                    subtitle="Project record could not be found."
                />

                <PageCard>

                    <FormSection
                        title="Record Not Found"
                    >

                        <InfoRow
                            label="Project"
                            value="No project information available."
                        />

                    </FormSection>

                </PageCard>


                <AppButton
                    variant="outlined"
                    onClick={() =>
                        navigate(
                            "/projects"
                        )
                    }
                    sx={{
                        mt: 3,
                        mb: 5
                    }}
                >
                    Back to Projects
                </AppButton>

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

                title="Project Details"

                subtitle={
                    project.projectCode ||
                    project.name ||
                    "Project record"
                }

                action={() =>
                    navigate(
                        `/projects/${id}/edit`
                    )
                }

                actionLabel="Edit Project"

                actionIcon={
                    <Edit />
                }

            />


            {/* =================================================
                BASIC INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Basic Information"
                >

                    <InfoRow
                        label="Project Code"
                        value={
                            project.projectCode
                        }
                    />

                    <InfoRow
                        label="Project Name"
                        value={
                            project.name
                        }
                    />

                    <InfoRow
                        label="Program"
                        value={
                            project.program
                                ? (
                                    `${project.program.programCode || ""} - ${
                                        project.program.name || ""
                                    }`
                                )
                                : "-"
                        }
                    />

                    <InfoRow
                        label="Description"
                        value={
                            project.description
                        }
                    />

                </FormSection>

            </PageCard>


            {/* =================================================
                PROJECT STATUS
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Project Status"
                >

                    <InfoRow
                        label="Status"
                        value={
                            <StatusChip
                                status={
                                    project.status ||
                                    "Unknown"
                                }
                            />
                        }
                    />

                    <InfoRow
                        label="Start Date"
                        value={
                            formatDate(
                                project.startDate
                            )
                        }
                    />

                    <InfoRow
                        label="End Date"
                        value={
                            formatDate(
                                project.endDate
                            )
                        }
                    />

                </FormSection>

            </PageCard>


            {/* =================================================
                BUDGET (Budgets module)
            ================================================= */}

            <BudgetFigureCard
                figure={project.budget}
                level="project"
                entityId={project._id}
                user={user}
                navigate={navigate}
            />


            {/* =================================================
                RECORD INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Record Information"
                >

                    <InfoRow
                        label="Created At"
                        value={
                            project.createdAt
                                ? new Date(
                                    project.createdAt
                                ).toLocaleString()
                                : "-"
                        }
                    />

                    <InfoRow
                        label="Updated At"
                        value={
                            project.updatedAt
                                ? new Date(
                                    project.updatedAt
                                ).toLocaleString()
                                : "-"
                        }
                    />

                </FormSection>

            </PageCard>


            {/* =================================================
                ACTIONS
            ================================================= */}

            <PageCard>

                <FormSection>

                    <AppButton
                        variant="outlined"
                        onClick={() =>
                            navigate(
                                "/projects"
                            )
                        }
                    >
                        Back
                    </AppButton>


                    <AppButton
                        variant="contained"
                        startIcon={
                            <Edit />
                        }
                        onClick={() =>
                            navigate(
                                `/projects/${id}/edit`
                            )
                        }
                        sx={{
                            ml: 2
                        }}
                    >
                        Edit
                    </AppButton>


                    <AppButton
                        variant="contained"
                        color="error"
                        onClick={() =>
                            setOpenDelete(true)
                        }
                        sx={{
                            ml: 2
                        }}
                    >
                        Delete
                    </AppButton>

                </FormSection>

            </PageCard>


            {/* =================================================
                DELETE CONFIRMATION
            ================================================= */}

            <ConfirmDeleteDialog

                open={
                    openDelete
                }

                title="Delete Project"

                message={
                    `Are you sure you want to delete ${
                        project.name ||
                        project.projectCode ||
                        "this project"
                    }? This action cannot be undone.`
                }

                onClose={() =>
                    setOpenDelete(false)
                }

                onConfirm={
                    remove
                }

            />

        </PageContainer>

    );

};


export default ProjectDetailsPage;
