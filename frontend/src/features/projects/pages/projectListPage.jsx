import {
    useEffect,
    useState
} from "react";

import {
    useNavigate
} from "react-router-dom";

import {
    Alert,
    Box,
    Link,
    Typography
} from "@mui/material";

import {
    Add,
    Delete,
    Edit,
    Visibility
} from "@mui/icons-material";

import {
    PageContainer,
    PageHeader,
    PageCard,
    SearchToolbar,
    DataTable,
    StatusChip,
    AppIconButton,
    ConfirmDeleteDialog
} from "../../../components/ui";

import useAuth
    from "../../auth/hooks/useAuth";

import {
    getProjectsApi,
    deleteProjectApi
} from "../api/projectApi";

import {
    getProgramsLookupApi
} from "../../programs/api/lookupApi";

import BudgetFigureCell
    from "../../budgets/components/BudgetFigureCell";

import { hasPermission } from "../../../utils/permissions";
import { getApiErrorMessage } from "../../../utils/apiError";


const STATUS_OPTIONS =
    ["Draft", "Active", "Completed", "Cancelled"]
        .map(value => ({ value, label: value }));

const formatDate = (value) =>
    value ? new Date(value).toLocaleDateString() : "";

const nameOf = (value) =>
    !value ? "-" : typeof value === "string" ? value : value.name || value.organizationName || value.fullName || "-";


// =====================================================
// PROJECT LIST PAGE
// =====================================================

const ProjectListPage = () => {

    const navigate = useNavigate();

    const { user } = useAuth();

    const [search, setSearch] = useState("");
    const [program, setProgram] = useState("");
    const [status, setStatus] = useState("");
    const [programOptions, setProgramOptions] = useState([]);

    const [paginationModel, setPaginationModel] =
        useState({ page: 0, pageSize: 10 });

    const [deleteTarget, setDeleteTarget] = useState(null);
    const [deleting, setDeleting] = useState(false);

    // Bumped to reload after a delete
    const [reloadKey, setReloadKey] = useState(0);

    const [result, setResult] =
        useState({ rows: [], total: 0, loading: true, error: "" });


    useEffect(() => {
        getProgramsLookupApi()
            .then(({ data }) => setProgramOptions(
                (data?.data || []).map(item => ({ value: item._id, label: item.name }))
            ))
            .catch(() => setProgramOptions([]));
    }, []);


    useEffect(() => {

        let cancelled = false;

        const timer =
            setTimeout(() => {

                getProjectsApi({
                    search: search.trim(),
                    program: program || undefined,
                    status: status || undefined,
                    page: paginationModel.page + 1,
                    limit: paginationModel.pageSize
                })
                    .then(({ data: response }) => {
                        if (!cancelled) {
                            setResult({
                                rows: response.data || [],
                                total: response.pagination?.total || 0,
                                loading: false,
                                error: ""
                            });
                        }
                    })
                    .catch(error => {
                        if (!cancelled) {
                            setResult(prev => ({
                                ...prev,
                                loading: false,
                                error: getApiErrorMessage(error, "Failed to load projects.")
                            }));
                        }
                    });

            }, 300);

        return () => {
            cancelled = true;
            clearTimeout(timer);
        };

    }, [search, program, status, paginationModel, reloadKey]);


    const handleDelete = async () => {

        setDeleting(true);

        try {
            await deleteProjectApi(deleteTarget._id);
            setDeleteTarget(null);
            setReloadKey(key => key + 1);
        }
        catch (error) {
            setDeleteTarget(null);
            setResult(prev => ({
                ...prev,
                error: getApiErrorMessage(error, "Failed to delete the project.")
            }));
        }
        finally {
            setDeleting(false);
        }

    };


    const resetPage = () =>
        setPaginationModel(prev => ({ ...prev, page: 0 }));

    const canUpdate = hasPermission(user, "project.update");
    const canDelete = hasPermission(user, "project.delete");


    const columns = [

        {
            field: "name",
            headerName: "Project",
            flex: 1.4,
            minWidth: 190,
            renderCell: (params) => (
                <Box sx={{ lineHeight: 1.3, py: 0.5, minWidth: 0 }}>
                    <Link
                        component="button"
                        underline="hover"
                        sx={{ fontWeight: 600, textAlign: "left" }}
                        onClick={() => navigate(`/projects/${params.row._id}`)}
                    >
                        {params.value}
                    </Link>
                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                        {params.row.projectCode}
                    </Typography>
                </Box>
            )
        },

        {
            field: "program",
            headerName: "Program",
            flex: 1.2,
            minWidth: 170,
            sortable: false,
            renderCell: (params) => {
                const item = params.row.program;
                return item
                    ? (
                        <Box sx={{ lineHeight: 1.3, py: 0.5, minWidth: 0 }}>
                            <Typography variant="body2">{nameOf(item)}</Typography>
                            {item.programCode && (
                                <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                                    {item.programCode}
                                </Typography>
                            )}
                        </Box>
                    )
                    : "-";
            }
        },

        {
            field: "donor",
            headerName: "Donor",
            flex: 0.8,
            minWidth: 100,
            sortable: false,
            valueGetter: (value) => nameOf(value)
        },

        {
            field: "startDate",
            headerName: "Period",
            minWidth: 160,
            valueGetter: (value, row) =>
                [formatDate(row.startDate), formatDate(row.endDate)].filter(Boolean).join(" – ") || "-"
        },

        {
            field: "budget",
            headerName: "Budget",
            minWidth: 150,
            align: "right",
            headerAlign: "right",
            sortable: false,
            renderCell: (params) => <BudgetFigureCell figure={params.value} />
        },

        {
            field: "status",
            headerName: "Status",
            minWidth: 100,
            renderCell: (params) => <StatusChip status={params.value || "Draft"} />
        },

        {
            field: "actions",
            headerName: "Actions",
            width: 140,
            sortable: false,
            filterable: false,
            disableColumnMenu: true,
            renderCell: (params) => (
                <>
                    <AppIconButton
                        icon={<Visibility fontSize="small" />}
                        tooltip="View project"
                        onClick={() => navigate(`/projects/${params.row._id}`)}
                    />
                    {canUpdate && (
                        <AppIconButton
                            icon={<Edit fontSize="small" />}
                            tooltip="Edit project"
                            onClick={() => navigate(`/projects/${params.row._id}/edit`)}
                        />
                    )}
                    {canDelete && (
                        <AppIconButton
                            icon={<Delete fontSize="small" />}
                            tooltip="Delete project"
                            color="error"
                            onClick={() => setDeleteTarget(params.row)}
                        />
                    )}
                </>
            )
        }

    ];


    return (

        <PageContainer>

            <PageHeader
                title="Projects"
                subtitle="Projects carried out under each program, with their donor and budget."
                {...(
                    hasPermission(user, "project.create")
                        ? {
                            action: () => navigate("/projects/create"),
                            actionLabel: "Add Project",
                            actionIcon: <Add />
                        }
                        : {}
                )}
            />

            <SearchToolbar
                search={search}
                onSearch={(value) => { setSearch(value); resetPage(); }}
                onReset={() => {
                    setSearch("");
                    setProgram("");
                    setStatus("");
                    resetPage();
                }}
                filters={[
                    { key: "program", label: "Program", value: program, onChange: (value) => { setProgram(value); resetPage(); }, options: programOptions },
                    { key: "status", label: "Status", value: status, onChange: (value) => { setStatus(value); resetPage(); }, options: STATUS_OPTIONS }
                ]}
            />

            {result.error && (
                <Alert severity="error" sx={{ mb: 3 }}>
                    {result.error}
                </Alert>
            )}

            <PageCard>
                <DataTable
                    rows={result.rows}
                    columns={columns}
                    loading={result.loading}
                    paginationMode="server"
                    rowCount={result.total}
                    paginationModel={paginationModel}
                    onPaginationModelChange={setPaginationModel}
                    getRowHeight={() => "auto"}
                    onRowDoubleClick={(params) => navigate(`/projects/${params.row._id}`)}
                />
            </PageCard>

            <ConfirmDeleteDialog
                open={Boolean(deleteTarget)}
                title="Delete Project"
                message={
                    deleteTarget
                        ? `Delete ${deleteTarget.projectCode} "${deleteTarget.name}"? This cannot be undone.`
                        : ""
                }
                loading={deleting}
                onClose={() => !deleting && setDeleteTarget(null)}
                onConfirm={handleDelete}
            />

        </PageContainer>

    );

};


export default ProjectListPage;
