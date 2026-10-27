import {
    useEffect,
    useState
} from "react";

import {
    useNavigate,
    useSearchParams
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
    getPurchaseRequestsApi,
    deletePurchaseRequestApi
} from "../api/procurementApi";

import {
    getApiErrorMessage
} from "../../budgets/api/budgetApi";

import {
    BUDGET_CATEGORIES,
    formatMoney,
    hasPermission
} from "../../budgets/utils/budgetUtils";

import {
    PURCHASE_REQUEST_STATUS,
    EDITABLE_STATUSES,
    formatDate
} from "../utils/procurementUtils";

import {
    currentFiscalYear,
    fiscalYearLabel,
    fiscalYearRange
} from "../../../utils/fiscalYear";


const thisYear = currentFiscalYear();

const YEAR_OPTIONS =
    fiscalYearRange(thisYear - 3, thisYear + 3).map(year => ({ value: year, label: fiscalYearLabel(year) }));

const STATUS_OPTIONS =
    Object.values(PURCHASE_REQUEST_STATUS).map(value => ({ value, label: value }));

const CATEGORY_OPTIONS =
    BUDGET_CATEGORIES.map(value => ({ value, label: value }));


// =====================================================
// PURCHASE REQUEST LIST
// =====================================================

const PurchaseRequestListPage = () => {

    const navigate = useNavigate();

    const { user } = useAuth();

    // ?budget=<id> from a budget page
    const [searchParams, setSearchParams] = useSearchParams();
    const budgetFilter = searchParams.get("budget") || "";

    const [search, setSearch] = useState("");
    const [status, setStatus] = useState("");
    const [category, setCategory] = useState("");
    const [fiscalYear, setFiscalYear] = useState("");

    const [paginationModel, setPaginationModel] = useState({ page: 0, pageSize: 10 });

    const [deleteTarget, setDeleteTarget] = useState(null);
    const [deleting, setDeleting] = useState(false);
    const [reloadKey, setReloadKey] = useState(0);

    const [result, setResult] = useState({ rows: [], total: 0, loading: true, error: "" });


    useEffect(() => {

        let cancelled = false;

        const timer =
            setTimeout(() => {
                getPurchaseRequestsApi({
                    search: search.trim(),
                    status: status || undefined,
                    category: category || undefined,
                    fiscalYear: fiscalYear || undefined,
                    budget: budgetFilter || undefined,
                    page: paginationModel.page + 1,
                    limit: paginationModel.pageSize
                })
                    .then(response => {
                        if (!cancelled) setResult({ rows: response.data || [], total: response.pagination?.total || 0, loading: false, error: "" });
                    })
                    .catch(error => {
                        if (!cancelled) setResult(prev => ({ ...prev, loading: false, error: getApiErrorMessage(error, "Failed to load purchase requests.") }));
                    });
            }, 300);

        return () => {
            cancelled = true;
            clearTimeout(timer);
        };

    }, [search, status, category, fiscalYear, budgetFilter, paginationModel, reloadKey]);


    const handleDelete = async () => {
        setDeleting(true);
        try {
            await deletePurchaseRequestApi(deleteTarget._id);
            setDeleteTarget(null);
            setReloadKey(key => key + 1);
        }
        catch (error) {
            setDeleteTarget(null);
            setResult(prev => ({ ...prev, error: getApiErrorMessage(error, "Failed to delete the purchase request.") }));
        }
        finally {
            setDeleting(false);
        }
    };

    const resetPage = () => setPaginationModel(prev => ({ ...prev, page: 0 }));

    const canUpdate = hasPermission(user, "purchase_request.update");
    const canDelete = hasPermission(user, "purchase_request.delete");


    const columns = [

        {
            field: "title",
            headerName: "Request",
            flex: 1.5,
            minWidth: 220,
            renderCell: (params) => (
                <Box sx={{ lineHeight: 1.3, py: 0.5, minWidth: 0 }}>
                    <Link
                        component="button"
                        underline="hover"
                        sx={{ fontWeight: 600, textAlign: "left" }}
                        onClick={() => navigate(`/purchase-requests/${params.row._id}`)}
                    >
                        {params.value}
                    </Link>
                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                        {params.row.requestCode} · {params.row.itemCount} item{params.row.itemCount === 1 ? "" : "s"}
                        {params.row.createdBy?.name ? ` · by ${params.row.createdBy.name}` : ""}
                    </Typography>
                </Box>
            )
        },

        {
            field: "requestDate",
            headerName: "Date",
            minWidth: 120,
            valueGetter: (value) => formatDate(value)
        },

        {
            field: "category",
            headerName: "Budget line",
            flex: 1.1,
            minWidth: 190,
            renderCell: (params) => (
                <Box sx={{ lineHeight: 1.3, py: 0.5 }}>
                    <Typography variant="body2">{params.value}</Typography>
                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                        {params.row.budget?.budgetCode} · {params.row.project?.name}
                    </Typography>
                </Box>
            )
        },

        {
            field: "budgetAmount",
            headerName: "Estimate",
            minWidth: 160,
            align: "right",
            headerAlign: "right",
            renderCell: (params) => (
                <Box sx={{ lineHeight: 1.3, py: 0.5, textAlign: "right" }}>
                    <Typography variant="body2" sx={{ fontWeight: 600, whiteSpace: "nowrap" }}>
                        {formatMoney(params.value, params.row.budgetCurrency)}
                    </Typography>
                    {params.row.currency !== params.row.budgetCurrency && (
                        <Typography variant="caption" sx={{ color: "text.secondary", display: "block", whiteSpace: "nowrap" }}>
                            {formatMoney(params.row.estimatedTotal, params.row.currency)}
                        </Typography>
                    )}
                </Box>
            )
        },

        {
            field: "status",
            headerName: "Status",
            minWidth: 130,
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
                            tooltip="View request"
                            onClick={() => navigate(`/purchase-requests/${params.row._id}`)}
                        />
                        {canUpdate && (
                            <AppIconButton
                                icon={<Edit fontSize="small" />}
                                tooltip={editable ? "Edit request" : `Locked: ${params.row.status.toLowerCase()}`}
                                disabled={!editable}
                                onClick={() => navigate(`/purchase-requests/${params.row._id}/edit`)}
                            />
                        )}
                        {canDelete && (
                            <AppIconButton
                                icon={<Delete fontSize="small" />}
                                tooltip={editable ? "Delete request" : `Locked: ${params.row.status.toLowerCase()}`}
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
                title="Purchase Requests"
                subtitle="Requests to buy goods and services, charged to approved project budget lines. Approved requests reserve their money as committed."
                {...(
                    hasPermission(user, "purchase_request.create")
                        ? { action: () => navigate("/purchase-requests/create"), actionLabel: "New Request", actionIcon: <Add /> }
                        : {}
                )}
            />

            <SearchToolbar
                search={search}
                onSearch={(value) => { setSearch(value); resetPage(); }}
                onReset={() => { setSearch(""); setStatus(""); setCategory(""); setFiscalYear(""); resetPage(); }}
                filters={[
                    { key: "fiscalYear", label: "Fiscal year", value: fiscalYear, onChange: (value) => { setFiscalYear(value); resetPage(); }, options: YEAR_OPTIONS },
                    { key: "category", label: "Category", value: category, onChange: (value) => { setCategory(value); resetPage(); }, options: CATEGORY_OPTIONS },
                    { key: "status", label: "Status", value: status, onChange: (value) => { setStatus(value); resetPage(); }, options: STATUS_OPTIONS }
                ]}
            />

            {budgetFilter && (
                <Alert
                    severity="info"
                    sx={{ mb: 3 }}
                    action={<Link component="button" onClick={() => setSearchParams({})}>Show all</Link>}
                >
                    Showing the purchase requests of one budget{result.rows[0]?.budget?.budgetCode ? ` (${result.rows[0].budget.budgetCode})` : ""}.
                </Alert>
            )}

            {result.error && <Alert severity="error" sx={{ mb: 3 }}>{result.error}</Alert>}

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
                    onRowDoubleClick={(params) => navigate(`/purchase-requests/${params.row._id}`)}
                />
            </PageCard>

            <ConfirmDeleteDialog
                open={Boolean(deleteTarget)}
                title="Delete Purchase Request"
                message={deleteTarget ? `Delete ${deleteTarget.requestCode} "${deleteTarget.title}"?` : ""}
                loading={deleting}
                onClose={() => !deleting && setDeleteTarget(null)}
                onConfirm={handleDelete}
            />

        </PageContainer>

    );

};


export default PurchaseRequestListPage;
