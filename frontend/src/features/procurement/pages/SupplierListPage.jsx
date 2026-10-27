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
    getSuppliersApi,
    deleteSupplierApi
} from "../api/procurementApi";

import {
    getApiErrorMessage
} from "../../budgets/api/budgetApi";

import {
    hasPermission
} from "../../budgets/utils/budgetUtils";

import {
    SUPPLIER_STATUS,
    SUPPLIER_CATEGORIES
} from "../utils/procurementUtils";


const STATUS_OPTIONS =
    Object.values(SUPPLIER_STATUS).map(value => ({ value, label: value }));

const CATEGORY_OPTIONS =
    SUPPLIER_CATEGORIES.map(value => ({ value, label: value }));


// =====================================================
// SUPPLIER LIST
// =====================================================

const SupplierListPage = () => {

    const navigate = useNavigate();

    const { user } = useAuth();

    const [search, setSearch] = useState("");
    const [status, setStatus] = useState("");
    const [category, setCategory] = useState("");

    const [paginationModel, setPaginationModel] = useState({ page: 0, pageSize: 10 });

    const [deleteTarget, setDeleteTarget] = useState(null);
    const [deleting, setDeleting] = useState(false);
    const [reloadKey, setReloadKey] = useState(0);

    const [result, setResult] = useState({ rows: [], total: 0, loading: true, error: "" });


    useEffect(() => {

        let cancelled = false;

        const timer =
            setTimeout(() => {
                getSuppliersApi({
                    search: search.trim(),
                    status: status || undefined,
                    category: category || undefined,
                    page: paginationModel.page + 1,
                    limit: paginationModel.pageSize
                })
                    .then(response => {
                        if (!cancelled) setResult({ rows: response.data || [], total: response.pagination?.total || 0, loading: false, error: "" });
                    })
                    .catch(error => {
                        if (!cancelled) setResult(prev => ({ ...prev, loading: false, error: getApiErrorMessage(error, "Failed to load suppliers.") }));
                    });
            }, 300);

        return () => {
            cancelled = true;
            clearTimeout(timer);
        };

    }, [search, status, category, paginationModel, reloadKey]);


    const handleDelete = async () => {
        setDeleting(true);
        try {
            await deleteSupplierApi(deleteTarget._id);
            setDeleteTarget(null);
            setReloadKey(key => key + 1);
        }
        catch (error) {
            setDeleteTarget(null);
            setResult(prev => ({ ...prev, error: getApiErrorMessage(error, "Failed to delete the supplier.") }));
        }
        finally {
            setDeleting(false);
        }
    };

    const resetPage = () => setPaginationModel(prev => ({ ...prev, page: 0 }));

    const canUpdate = hasPermission(user, "supplier.update");
    const canDelete = hasPermission(user, "supplier.delete");


    const columns = [

        {
            field: "name",
            headerName: "Supplier",
            flex: 1.4,
            minWidth: 220,
            renderCell: (params) => (
                <Box sx={{ lineHeight: 1.3, py: 0.5, minWidth: 0 }}>
                    <Link
                        component="button"
                        underline="hover"
                        sx={{ fontWeight: 600, textAlign: "left" }}
                        onClick={() => navigate(`/suppliers/${params.row._id}`)}
                    >
                        {params.value}
                    </Link>
                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                        {params.row.supplierCode}{params.row.supplies ? ` · ${params.row.supplies}` : ""}
                    </Typography>
                </Box>
            )
        },

        {
            field: "categories",
            headerName: "Category",
            flex: 0.8,
            minWidth: 140,
            valueGetter: (value) => (value || []).join(", ") || "-"
        },

        {
            field: "tin",
            headerName: "TIN",
            minWidth: 130,
            valueGetter: (value) => value || "-"
        },

        {
            field: "contactPerson",
            headerName: "Contact",
            flex: 1,
            minWidth: 170,
            renderCell: (params) => (
                <Box sx={{ lineHeight: 1.3, py: 0.5 }}>
                    <Typography variant="body2">{params.value || "-"}</Typography>
                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                        {[params.row.phone, params.row.email].filter(Boolean).join(" · ")}
                    </Typography>
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
            renderCell: (params) => (
                <>
                    <AppIconButton icon={<Visibility fontSize="small" />} tooltip="View supplier" onClick={() => navigate(`/suppliers/${params.row._id}`)} />
                    {canUpdate && (
                        <AppIconButton icon={<Edit fontSize="small" />} tooltip="Edit supplier" onClick={() => navigate(`/suppliers/${params.row._id}/edit`)} />
                    )}
                    {canDelete && (
                        <AppIconButton icon={<Delete fontSize="small" />} tooltip="Delete supplier" color="error" onClick={() => setDeleteTarget(params.row)} />
                    )}
                </>
            )
        }

    ];


    return (

        <PageContainer>

            <PageHeader
                title="Suppliers"
                subtitle="The organization's register of suppliers of goods, services, works and consultancy."
                {...(
                    hasPermission(user, "supplier.create")
                        ? { action: () => navigate("/suppliers/create"), actionLabel: "Add Supplier", actionIcon: <Add /> }
                        : {}
                )}
            />

            <SearchToolbar
                search={search}
                onSearch={(value) => { setSearch(value); resetPage(); }}
                onReset={() => { setSearch(""); setStatus(""); setCategory(""); resetPage(); }}
                filters={[
                    { key: "category", label: "Category", value: category, onChange: (value) => { setCategory(value); resetPage(); }, options: CATEGORY_OPTIONS },
                    { key: "status", label: "Status", value: status, onChange: (value) => { setStatus(value); resetPage(); }, options: STATUS_OPTIONS }
                ]}
            />

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
                    onRowDoubleClick={(params) => navigate(`/suppliers/${params.row._id}`)}
                />
            </PageCard>

            <ConfirmDeleteDialog
                open={Boolean(deleteTarget)}
                title="Delete Supplier"
                message={deleteTarget ? `Delete ${deleteTarget.supplierCode} "${deleteTarget.name}"? A supplier used by purchase requests cannot be deleted; set it Inactive instead.` : ""}
                loading={deleting}
                onClose={() => !deleting && setDeleteTarget(null)}
                onConfirm={handleDelete}
            />

        </PageContainer>

    );

};


export default SupplierListPage;
