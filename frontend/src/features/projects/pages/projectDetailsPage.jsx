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
    Edit,
    Add
} from "@mui/icons-material";

import {
    Link
} from "@mui/material";

import TraceTable
    from "../../donations/components/TraceTable";

import { hasPermission } from "../../../utils/permissions";


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

                    {project.parentProject && (
                        <InfoRow
                            label="Phase of"
                            value={
                                <Link
                                    component="button"
                                    underline="hover"
                                    onClick={() => navigate(`/projects/${project.parentProject._id}`)}
                                >
                                    {`Phase ${project.phaseNumber || ""} of ${project.parentProject.projectCode || ""} - ${project.parentProject.name || ""}`}
                                </Link>
                            }
                        />
                    )}

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

            {(project.phases || []).length === 0 && (
                <BudgetFigureCard
                    figure={project.budget}
                    level="project"
                    entityId={project._id}
                    user={user}
                    navigate={navigate}
                />
            )}


            {/* =================================================
                PHASES (each one works like a project)
            ================================================= */}

            {!project.parentProject && (
                <PageCard>
                    <FormSection
                        title="Phases"
                        subtitle={
                            (project.phases || []).length
                                ? "This project runs in phases. Each phase has its own budget, activities, deliveries and reports; this project shows them together."
                                : "If this project runs in phases (Phase 1, Phase 2 ...), add them here. Each phase then works like a project of its own."
                        }
                    >
                        {(project.phases || []).length > 0 && (
                            <TraceTable
                                rows={project.phases}
                                getRowKey={row => row._id}
                                columns={[
                                    { key: "phase", label: "Phase", render: row => `Phase ${row.phaseNumber}` },
                                    {
                                        key: "name",
                                        label: "Name",
                                        render: row => (
                                            <Link component="button" underline="hover" onClick={() => navigate(`/projects/${row._id}`)}>
                                                {row.name}
                                            </Link>
                                        )
                                    },
                                    { key: "dates", label: "Dates", render: row => `${formatDate(row.startDate)} - ${formatDate(row.endDate)}` },
                                    { key: "status", label: "Status", render: row => <StatusChip status={row.status || "Draft"} /> },
                                    { key: "budget", label: "Approved budget", align: "right", render: row => row.budget ? `${row.budget.currency} ${Number(row.budget.approvedAmount || 0).toLocaleString("en-US", { minimumFractionDigits: 2 })}` : "No budget yet" },
                                    { key: "spent", label: "Spent", align: "right", render: row => row.budget ? `${row.budget.currency} ${Number(row.budget.spent || 0).toLocaleString("en-US", { minimumFractionDigits: 2 })}` : "-" },
                                    { key: "left", label: "Left", align: "right", render: row => row.budget ? `${row.budget.currency} ${Number(row.budget.remaining || 0).toLocaleString("en-US", { minimumFractionDigits: 2 })}` : "-" }
                                ]}
                            />
                        )}

                        {hasPermission(user, "project.create") && (
                            <AppButton
                                variant="outlined"
                                startIcon={<Add />}
                                onClick={() => navigate(`/projects/create?parent=${project._id}`)}
                                sx={{ mt: (project.phases || []).length ? 2 : 0 }}
                            >
                                Add Phase
                            </AppButton>
                        )}
                    </FormSection>
                </PageCard>
            )}


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
