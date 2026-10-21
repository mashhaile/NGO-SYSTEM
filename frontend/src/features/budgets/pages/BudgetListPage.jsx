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
    getBudgetsApi,
    deleteBudgetApi,
    getApiErrorMessage
} from "../api/budgetApi";

import {
    BUDGET_STATUS,
    EDITABLE_STATUSES,
    formatMoney,
    levelLabel,
    hasPermission
} from "../utils/budgetUtils";

import {
    currentFiscalYear,
    fiscalYearLabel,
    fiscalYearRange
} from "../../../utils/fiscalYear";


const thisYear = currentFiscalYear();

const YEAR_OPTIONS =
    fiscalYearRange(thisYear - 3, thisYear + 5).map(year => ({
        value: year,
        label: fiscalYearLabel(year)
    }));

const LEVEL_OPTIONS = [
    { value: "program", label: "Program budgets" },
    { value: "project", label: "Project budgets" }
];

const STATUS_OPTIONS =
    Object.values(BUDGET_STATUS).map(value => ({ value, label: value }));


const period = (budget) =>
    budget.startYear === budget.endYear
        ? fiscalYearLabel(budget.startYear)
        : `${fiscalYearLabel(budget.startYear)} – ${fiscalYearLabel(budget.endYear)}`;


// =====================================================
// BUDGET LIST PAGE
// =====================================================

const BudgetListPage = () => {

    const navigate = useNavigate();

    const { user } = useAuth();

    const [search, setSearch] = useState("");
    const [level, setLevel] = useState("");
    const [status, setStatus] = useState("");
    const [fiscalYear, setFiscalYear] = useState("");

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

                getBudgetsApi({
                    search: search.trim(),
                    level: level || undefined,
                    status: status || undefined,
                    fiscalYear: fiscalYear || undefined,
                    page: paginationModel.page + 1,
                    limit: paginationModel.pageSize
                })
                    .then(response => {
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
                                error: getApiErrorMessage(error, "Failed to load budgets.")
                            }));
                        }
                    });

            }, 300);

        return () => {
            cancelled = true;
            clearTimeout(timer);
        };

    }, [search, level, status, fiscalYear, paginationModel, reloadKey]);


    const handleDelete = async () => {

        setDeleting(true);

        try {
            await deleteBudgetApi(deleteTarget._id);
            setDeleteTarget(null);
            setReloadKey(key => key + 1);
        }
        catch (error) {
            setDeleteTarget(null);
            setResult(prev => ({
                ...prev,
                error: getApiErrorMessage(error, "Failed to delete the budget.")
            }));
        }
        finally {
            setDeleting(false);
        }

    };


    const resetPage = () =>
        setPaginationModel(prev => ({ ...prev, page: 0 }));

    const canUpdate = hasPermission(user, "budget.update");
    const canDelete = hasPermission(user, "budget.delete");


    const columns = [

        {
            field: "name",
            headerName: "Budget",
            flex: 1.4,
            minWidth: 220,
            renderCell: (params) => (
                <Box sx={{ lineHeight: 1.3, py: 0.5 }}>
                    <Link
                        component="button"
                        underline="hover"
                        sx={{ fontWeight: 600, textAlign: "left" }}
                        onClick={() => navigate(`/budgets/${params.row._id}`)}
                    >
                        {params.value}
                    </Link>
                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                        {params.row.budgetCode}
                    </Typography>
                </Box>
            )
        },

        {
            field: "level",
            headerName: "Level",
            minWidth: 100,
            valueGetter: (value) => levelLabel(value)
        },

        {
            field: "project",
            headerName: "For",
            flex: 1.2,
            minWidth: 200,
            sortable: false,
            renderCell: (params) => {
                const target =
                    params.row.level === "project" ? params.row.project : params.row.program;
                return target
                    ? (
                        <Box sx={{ lineHeight: 1.3, py: 0.5, minWidth: 0 }}>
                            <Typography variant="body2" noWrap title={target.name}>
                                {target.name}
                            </Typography>
                            <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                                {params.row.level === "project"
                                    ? `${params.row.program?.name || ""}`
                                    : target.programCode}
                            </Typography>
                        </Box>
                    )
                    : "-";
            }
        },

        {
            field: "startYear",
            headerName: "Period",
            minWidth: 170,
            valueGetter: (value, row) => period(row)
        },

        {
            field: "totalAmount",
            headerName: "Total",
            minWidth: 160,
            align: "right",
            headerAlign: "right",
            valueGetter: (value, row) => formatMoney(value, row.currency)
        },

        {
            field: "status",
            headerName: "Status",
            minWidth: 120,
            renderCell: (params) => <StatusChip status={params.value} />
        },

        {
            field: "actions",
            headerName: "Actions",
            width: 140,
            sortable: false,
            filterable: false,
            disableColumnMenu: true,
            renderCell: (params) => {

                const editable = EDITABLE_STATUSES.includes(params.row.status);

                return (
                    <>
                        <AppIconButton
                            icon={<Visibility fontSize="small" />}
                            tooltip="View budget"
                            onClick={() => navigate(`/budgets/${params.row._id}`)}
                        />
                        {canUpdate && (
                            <AppIconButton
                                icon={<Edit fontSize="small" />}
                                tooltip={editable ? "Edit budget" : `Locked: ${params.row.status.toLowerCase()}`}
                                disabled={!editable}
                                onClick={() => navigate(`/budgets/${params.row._id}/edit`)}
                            />
                        )}
                        {canDelete && (
                            <AppIconButton
                                icon={<Delete fontSize="small" />}
                                tooltip={editable ? "Delete budget" : `Locked: ${params.row.status.toLowerCase()}`}
                                color="error"
                                disabled={!editable}
                                onClick={() => setDeleteTarget(params.row)}
                            />
                        )}
                    </>
                );

            }
        }

    ];


    return (

        <PageContainer>

            <PageHeader
                title="Budgets"
                subtitle="Multi-year program and project budgets. Project budgets draw on their program's budget."
                {...(
                    hasPermission(user, "budget.create")
                        ? {
                            action: () => navigate("/budgets/create"),
                            actionLabel: "New Budget",
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
                    setLevel("");
                    setStatus("");
                    setFiscalYear("");
                    resetPage();
                }}
                filters={[
                    { key: "level", label: "Level", value: level, onChange: (value) => { setLevel(value); resetPage(); }, options: LEVEL_OPTIONS },
                    { key: "fiscalYear", label: "Fiscal year", value: fiscalYear, onChange: (value) => { setFiscalYear(value); resetPage(); }, options: YEAR_OPTIONS },
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
                    onRowDoubleClick={(params) => navigate(`/budgets/${params.row._id}`)}
                />
            </PageCard>

            <ConfirmDeleteDialog
                open={Boolean(deleteTarget)}
                title="Delete Budget"
                message={
                    deleteTarget
                        ? `Delete ${deleteTarget.budgetCode} "${deleteTarget.name}"? This cannot be undone.`
                        : ""
                }
                loading={deleting}
                onClose={() => !deleting && setDeleteTarget(null)}
                onConfirm={handleDelete}
            />

        </PageContainer>

    );

};


export default BudgetListPage;
