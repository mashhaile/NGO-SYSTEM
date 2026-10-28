import {
    useEffect,
    useState
} from "react";


import {
    useParams,
    useNavigate
} from "react-router-dom";


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
    LoadingState,
    StatusChip
} from "../../../components/ui";

import useAuth
    from "../../auth/hooks/useAuth";

import IndicatorsCard
    from "../../indicators/components/IndicatorsCard";

import BudgetFigureCard
    from "../../budgets/components/BudgetFigureCard";


import {
    getProjectByIdService
} from "../services/projectService";
import { formatDate, formatDateTime } from "../../../utils/date";
import { useModuleOn } from "../../../utils/modules";


const ProjectDetailsPage = () => {

    const {
        id
    } = useParams();


    const navigate = useNavigate();

    const { user } = useAuth();

    // fields of other modules show only when those are on
    const fundingOn = useModuleOn("funding");
    const financeOn = useModuleOn("finance");


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
    // FORMAT DATE
    // =====================================================


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
    // RENDER (same layout as the other detail pages:
    // actions, information, dates, budget / phases,
    // record information, back)
    // =====================================================

    const phases =
        Array.isArray(project.phases) ? project.phases : [];

    const money = (figure, key) =>
        figure
            ? `${figure.currency} ${Number(figure[key] || 0).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`
            : "-";

    

    const backButton = (

        <AppButton
            variant="outlined"
            onClick={() =>
                navigate("/projects")
            }
            sx={{
                mt: 3,
                mb: 5
            }}
        >
            Back to Projects
        </AppButton>

    );

    return (

        <PageContainer>

            <PageHeader
                title="Project Details"
                subtitle={
                    project.projectCode ||
                    project.name ||
                    "Project record"
                }
            />

            {/* PAGE ACTIONS */}

            <PageCard>

                <FormSection>

                    <AppButton
                        variant="contained"
                        startIcon={<Edit />}
                        onClick={() =>
                            navigate(
                                `/projects/${id}/edit`
                            )
                        }
                    >
                        Edit Project
                    </AppButton>

                </FormSection>

            </PageCard>


            {/* PROJECT */}

            <PageCard>

                <FormSection
                    title="Project Information"
                >

                    <InfoRow
                        label="Project Code"
                        value={project.projectCode}
                    />

                    <InfoRow
                        label="Project Name"
                        value={project.name}
                    />

                    <InfoRow
                        label="Program"
                        value={
                            project.program
                                ? `${project.program.programCode || ""} - ${project.program.name || ""}`
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
                                    sx={{ fontWeight: 600, textAlign: "left" }}
                                    onClick={() =>
                                        navigate(`/projects/${project.parentProject._id}`)
                                    }
                                >
                                    {`Phase ${project.phaseNumber || ""} of ${project.parentProject.projectCode || ""} - ${project.parentProject.name || ""}`}
                                </Link>
                            }
                        />
                    )}

                    <InfoRow
                        label="Project Type"
                        value={project.projectType?.value || "-"}
                    />

                    {fundingOn && (
                    <InfoRow
                        label="Donor"
                        value={
                            project.donor?.name ||
                            project.donor?.organizationName ||
                            "-"
                        }
                    />
                    )}

                    <InfoRow
                        label="Project Manager"
                        value={
                            project.projectManager?.name ||
                            "-"
                        }
                    />

                    <InfoRow
                        label="Description"
                        value={project.description || "-"}
                    />

                </FormSection>

            </PageCard>

            {/* DATES */}

            <PageCard>

                <FormSection
                    title="Project Dates"
                >

                    <InfoRow
                        label="Start Date"
                        value={formatDate(project.startDate)}
                    />

                    <InfoRow
                        label="End Date"
                        value={formatDate(project.endDate)}
                    />

                </FormSection>

            </PageCard>

            {/* BUDGET: the project's own, or each phase's */}

            {phases.length === 0 && (
                <BudgetFigureCard
                    figure={project.budget}
                    level="project"
                    entityId={project._id}
                    user={user}
                    navigate={navigate}
                />
            )}

            {/* M&E indicators (when the module is on) */}
            <IndicatorsCard program={project.program?._id || project.program} project={project._id} />

            {/* PHASES (each one works like a project) */}

            {!project.parentProject && (phases.length > 0 || hasPermission(user, "project.create")) && (

                <PageCard>

                    <FormSection
                        title="Phases"
                        subtitle={
                            phases.length
                                ? "This project runs in phases. Each phase has its own budget, activities, deliveries and reports; this project shows them together."
                                : "If this project runs in phases (Phase 1, Phase 2 ...), add them here. Each phase then works like a project of its own."
                        }
                    >

                        {phases.length > 0 && (

                        <TraceTable
                            rows={phases}
                            getRowKey={row => row._id}
                            columns={[
                                { key: "phase", label: "Phase", render: row => `Phase ${row.phaseNumber}` },
                                {
                                    key: "name",
                                    label: "Name",
                                    render: row => (
                                        <Link
                                            component="button"
                                            underline="hover"
                                            sx={{ fontWeight: 600, textAlign: "left" }}
                                            onClick={() => navigate(`/projects/${row._id}`)}
                                        >
                                            {row.name}
                                        </Link>
                                    )
                                },
                                { key: "dates", label: "Dates", render: row => `${formatDate(row.startDate)} - ${formatDate(row.endDate)}` },
                                { key: "status", label: "Status", render: row => <StatusChip status={row.status || "Planned"} /> },
                                // budget columns: only with the finance module
                                ...(financeOn
                                    ? [
                                        { key: "budget", label: "Approved budget", align: "right", render: row => (row.budget ? money(row.budget, "approvedAmount") : "No budget yet") },
                                        { key: "spent", label: "Spent", align: "right", render: row => money(row.budget, "spent") },
                                        { key: "left", label: "Left", align: "right", render: row => money(row.budget, "remaining") }
                                    ]
                                    : [])
                            ]}
                        />
                        )}

                        {hasPermission(user, "project.create") && (
                            <AppButton
                                variant="outlined"
                                startIcon={<Add />}
                                onClick={() =>
                                    navigate(
                                        `/projects/create?parent=${project._id}`
                                    )
                                }
                                sx={{
                                    mt: phases.length ? 2 : 0
                                }}
                            >
                                Add Phase
                            </AppButton>
                        )}

                    </FormSection>

                </PageCard>

            )}

            {/* RECORD */}

            <PageCard>

                <FormSection
                    title="Record Information"
                >

                    <InfoRow
                        label="Status"
                        value={
                            <StatusChip
                                status={project.status || "Planned"}
                            />
                        }
                    />

                    <InfoRow
                        label="Created At"
                        value={formatDateTime(project.createdAt)}
                    />

                    <InfoRow
                        label="Updated At"
                        value={formatDateTime(project.updatedAt)}
                    />

                </FormSection>

            </PageCard>

            {backButton}

        </PageContainer>

    );

};


export default ProjectDetailsPage;
