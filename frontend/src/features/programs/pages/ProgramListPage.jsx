import { WORK_STATUSES } from "../../../constants/workStatus";
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
    getProgramsApi,
    deleteProgramApi
} from "../api/ProgramApi";

import BudgetFigureCell
    from "../../budgets/components/BudgetFigureCell";

import { hasPermission } from "../../../utils/permissions";
import { getApiErrorMessage } from "../../../utils/apiError";
import { formatDate } from "../../../utils/date";


const STATUS_OPTIONS =
    WORK_STATUSES
        .map(value => ({ value, label: value }));



const formatNumber = (value) =>
    value === null || value === undefined || value === "" ? "-" : Number(value).toLocaleString();


// =====================================================
// PROGRAM LIST PAGE
// =====================================================

const ProgramListPage = () => {

    const navigate = useNavigate();

    const { user } = useAuth();

    const [search, setSearch] = useState("");
    const [status, setStatus] = useState("");

    const [paginationModel, setPaginationModel] =
        useState({ page: 0, pageSize: 10 });

    const [deleteTarget, setDeleteTarget] = useState(null);
    const [deleting, setDeleting] = useState(false);

    // Bumped to reload after a delete
    const [reloadKey, setReloadKey] = useState(0);

    const [result, setResult] =
        useState({ rows: [], total: 0, loading: true, error: "" });


    useEffect(() => {

        let cancelled = false;

        const timer =
            setTimeout(() => {

                getProgramsApi({
                    search: search.trim(),
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
                                error: getApiErrorMessage(error, "Failed to load programs.")
                            }));
                        }
                    });

            }, 300);

        return () => {
            cancelled = true;
            clearTimeout(timer);
        };

    }, [search, status, paginationModel, reloadKey]);


    const handleDelete = async () => {

        setDeleting(true);

        try {
            await deleteProgramApi(deleteTarget._id);
            setDeleteTarget(null);
            setReloadKey(key => key + 1);
        }
        catch (error) {
            setDeleteTarget(null);
            setResult(prev => ({
                ...prev,
                error: getApiErrorMessage(error, "Failed to delete the program.")
            }));
        }
        finally {
            setDeleting(false);
        }

    };


    const resetPage = () =>
        setPaginationModel(prev => ({ ...prev, page: 0 }));

    const canUpdate = hasPermission(user, "program.update");
    const canDelete = hasPermission(user, "program.delete");


    const columns = [

        {
            field: "name",
            headerName: "Program",
            flex: 1.6,
            minWidth: 240,
            renderCell: (params) => (
                <Box sx={{ lineHeight: 1.3, py: 0.5, minWidth: 0 }}>
                    <Link
                        component="button"
                        underline="hover"
                        sx={{ fontWeight: 600, textAlign: "left" }}
                        onClick={() => navigate(`/programs/${params.row._id}`)}
                    >
                        {params.value}
                    </Link>
                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                        {params.row.programCode}
                    </Typography>
                </Box>
            )
        },

        {
            field: "category",
            headerName: "Category",
            flex: 1,
            minWidth: 160,
            valueGetter: (value) => value || "-"
        },

        {
            field: "startDate",
            headerName: "Period",
            minWidth: 190,
            valueGetter: (value, row) =>
                [formatDate(row.startDate), formatDate(row.endDate)].filter(Boolean).join(" – ") || "-"
        },

        {
            field: "budget",
            headerName: "Budget",
            minWidth: 160,
            align: "right",
            headerAlign: "right",
            sortable: false,
            renderCell: (params) => <BudgetFigureCell figure={params.value} />
        },

        {
            field: "targetBeneficiaries",
            headerName: "Target",
            minWidth: 100,
            align: "right",
            headerAlign: "right",
            valueGetter: (value) => formatNumber(value)
        },

        {
            field: "status",
            headerName: "Status",
            minWidth: 120,
            renderCell: (params) => <StatusChip status={params.value || "Planned"} />
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
                        tooltip="View program"
                        onClick={() => navigate(`/programs/${params.row._id}`)}
                    />
                    {canUpdate && (
                        <AppIconButton
                            icon={<Edit fontSize="small" />}
                            tooltip="Edit program"
                            onClick={() => navigate(`/programs/${params.row._id}/edit`)}
                        />
                    )}
                    {canDelete && (
                        <AppIconButton
                            icon={<Delete fontSize="small" />}
                            tooltip="Delete program"
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
                title="Programs"
                subtitle="The organization's programs. Projects, activities and budgets belong to a program."
                {...(
                    hasPermission(user, "program.create")
                        ? {
                            action: () => navigate("/programs/create"),
                            actionLabel: "Add Program",
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
                    setStatus("");
                    resetPage();
                }}
                filters={[
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
                    onRowDoubleClick={(params) => navigate(`/programs/${params.row._id}`)}
                />
            </PageCard>

            <ConfirmDeleteDialog
                open={Boolean(deleteTarget)}
                title="Delete Program"
                message={
                    deleteTarget
                        ? `Delete ${deleteTarget.programCode} "${deleteTarget.name}"? This cannot be undone.`
                        : ""
                }
                loading={deleting}
                onClose={() => !deleting && setDeleteTarget(null)}
                onConfirm={handleDelete}
            />

        </PageContainer>

    );

};


export default ProgramListPage;
