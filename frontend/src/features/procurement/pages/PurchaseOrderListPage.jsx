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
    Visibility
} from "@mui/icons-material";

import {
    PageContainer,
    PageHeader,
    PageCard,
    SearchToolbar,
    DataTable,
    StatusChip,
    AppIconButton
} from "../../../components/ui";

import {
    getPurchaseOrdersApi
} from "../api/procurementApi";

import {
    getApiErrorMessage
} from "../../budgets/api/budgetApi";

import {
    formatMoney
} from "../../budgets/utils/budgetUtils";

import {
    PURCHASE_ORDER_STATUS,
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
    Object.values(PURCHASE_ORDER_STATUS).map(value => ({ value, label: value }));


// =====================================================
// PURCHASE ORDER LIST
// =====================================================
//
// Orders are issued from a purchase request's approved bid
// analysis, not created here.
//
// =====================================================

const PurchaseOrderListPage = () => {

    const navigate = useNavigate();

    const [search, setSearch] = useState("");
    const [status, setStatus] = useState("");
    const [fiscalYear, setFiscalYear] = useState("");

    const [paginationModel, setPaginationModel] = useState({ page: 0, pageSize: 10 });

    const [result, setResult] = useState({ rows: [], total: 0, loading: true, error: "" });


    useEffect(() => {

        let cancelled = false;

        const timer =
            setTimeout(() => {
                getPurchaseOrdersApi({
                    search: search.trim(),
                    status: status || undefined,
                    fiscalYear: fiscalYear || undefined,
                    page: paginationModel.page + 1,
                    limit: paginationModel.pageSize
                })
                    .then(response => {
                        if (!cancelled) setResult({ rows: response.data || [], total: response.pagination?.total || 0, loading: false, error: "" });
                    })
                    .catch(error => {
                        if (!cancelled) setResult(prev => ({ ...prev, loading: false, error: getApiErrorMessage(error, "Failed to load purchase orders.") }));
                    });
            }, 300);

        return () => {
            cancelled = true;
            clearTimeout(timer);
        };

    }, [search, status, fiscalYear, paginationModel]);

    const resetPage = () => setPaginationModel(prev => ({ ...prev, page: 0 }));


    const columns = [

        {
            field: "poCode",
            headerName: "Order",
            flex: 1.3,
            minWidth: 220,
            renderCell: (params) => (
                <Box sx={{ lineHeight: 1.3, py: 0.5, minWidth: 0 }}>
                    <Link component="button" underline="hover" sx={{ fontWeight: 600, textAlign: "left" }} onClick={() => navigate(`/purchase-orders/${params.row._id}`)}>
                        {params.value} · {params.row.supplier?.name}
                    </Link>
                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                        {params.row.purchaseRequest?.requestCode} · {params.row.purchaseRequest?.title}
                    </Typography>
                </Box>
            )
        },

        {
            field: "orderDate",
            headerName: "Ordered",
            minWidth: 110,
            valueGetter: (value) => formatDate(value)
        },

        {
            field: "deliveryDate",
            headerName: "Deliver by",
            minWidth: 110,
            valueGetter: (value) => (value ? formatDate(value) : "-")
        },

        {
            field: "category",
            headerName: "Budget line",
            flex: 1,
            minWidth: 180,
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
            field: "total",
            headerName: "Total",
            minWidth: 150,
            align: "right",
            headerAlign: "right",
            renderCell: (params) => (
                <Typography variant="body2" sx={{ fontWeight: 600, whiteSpace: "nowrap", py: 1 }}>
                    {formatMoney(params.value, params.row.currency)}
                </Typography>
            )
        },

        {
            field: "status",
            headerName: "Status",
            minWidth: 120,
            renderCell: (params) => <StatusChip status={params.value} />
        },

        {
            field: "actions",
            headerName: "",
            width: 70,
            sortable: false,
            filterable: false,
            disableColumnMenu: true,
            renderCell: (params) => (
                <AppIconButton icon={<Visibility fontSize="small" />} tooltip="View order" onClick={() => navigate(`/purchase-orders/${params.row._id}`)} />
            )
        }

    ];


    return (

        <PageContainer>

            <PageHeader
                title="Purchase Orders"
                subtitle="Orders placed with suppliers. They are issued from a purchase request once its bid analysis is approved."
            />

            <SearchToolbar
                search={search}
                onSearch={(value) => { setSearch(value); resetPage(); }}
                onReset={() => { setSearch(""); setStatus(""); setFiscalYear(""); resetPage(); }}
                filters={[
                    { key: "fiscalYear", label: "Fiscal year", value: fiscalYear, onChange: (value) => { setFiscalYear(value); resetPage(); }, options: YEAR_OPTIONS },
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
                    onRowDoubleClick={(params) => navigate(`/purchase-orders/${params.row._id}`)}
                />
            </PageCard>

        </PageContainer>

    );

};


export default PurchaseOrderListPage;
