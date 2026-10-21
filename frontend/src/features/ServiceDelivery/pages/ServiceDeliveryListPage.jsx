import {
    useEffect,
    useMemo,
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
    getServiceDeliveriesApi,
    deleteServiceDeliveryApi
} from "../api/serviceDeliveryApi";

import {
    getProgramsLookupApi
} from "../../programs/api/lookupApi";

import { hasPermission } from "../../../utils/permissions";
import { getApiErrorMessage } from "../../../utils/apiError";


const STATUS_OPTIONS =
    ["Delivered", "Cancelled"].map(value => ({ value, label: value }));

const formatMoney = (value) => {
    const amount = Number(value);
    return Number.isFinite(amount) && amount > 0
        ? `ETB ${amount.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`
        : "-";
};

const lookupName = (item) =>
    !item ? "" : typeof item === "string" ? item : item.value || item.name || item.label || "";

const personName = (person) => {
    if (!person || typeof person === "string") return person || "";
    const full = [person.firstName, person.lastName].filter(Boolean).join(" ");
    return person.fullName || full || person.name || person.beneficiaryNumber || "";
};

const beneficiaryNames = (row) => {
    const list = Array.isArray(row.beneficiaries) ? row.beneficiaries : [];
    const names = list.map(item => personName(item?.beneficiary || item)).filter(Boolean);
    if (names.length === 0 && row.beneficiary) names.push(personName(row.beneficiary));
    return names;
};

const serviceNames = (row) =>
    [...new Set((row.items || []).map(item => lookupName(item?.serviceType)).filter(Boolean))];

const idOf = (value) => (value && typeof value === "object" ? value._id : value);

const summarize = (names, shown = 2) =>
    names.length === 0
        ? "-"
        : names.length > shown
            ? `${names.slice(0, shown).join(", ")} +${names.length - shown} more`
            : names.join(", ");


// =====================================================
// SERVICE DELIVERY LIST PAGE
// =====================================================
// The API returns all deliveries, so search, filters and
// paging happen here.

const ServiceDeliveryListPage = () => {

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
        useState({ rows: [], loading: true, error: "" });


    useEffect(() => {
        getProgramsLookupApi()
            .then(({ data }) => setProgramOptions(
                (data?.data || []).map(item => ({ value: item._id, label: item.name }))
            ))
            .catch(() => setProgramOptions([]));
    }, []);


    useEffect(() => {

        let cancelled = false;

        getServiceDeliveriesApi()
            .then(({ data: response }) => {
                if (!cancelled) setResult({ rows: response.data || [], loading: false, error: "" });
            })
            .catch(error => {
                if (!cancelled) {
                    setResult(prev => ({
                        ...prev,
                        loading: false,
                        error: getApiErrorMessage(error, "Failed to load service deliveries.")
                    }));
                }
            });

        return () => {
            cancelled = true;
        };

    }, [reloadKey]);


    const rows = useMemo(() => {
        const term = search.trim().toLowerCase();
        return result.rows.filter(row =>
            (!program || idOf(row.program) === program) &&
            (!status || (row.status || "Delivered") === status) &&
            (!term || [
                row.deliveryNumber,
                lookupName(row.program),
                lookupName(row.project),
                lookupName(row.activity),
                ...beneficiaryNames(row),
                ...serviceNames(row)
            ].some(value => String(value || "").toLowerCase().includes(term)))
        );
    }, [result.rows, search, program, status]);


    const handleDelete = async () => {

        setDeleting(true);

        try {
            await deleteServiceDeliveryApi(deleteTarget._id);
            setDeleteTarget(null);
            setReloadKey(key => key + 1);
        }
        catch (error) {
            setDeleteTarget(null);
            setResult(prev => ({
                ...prev,
                error: getApiErrorMessage(error, "Failed to delete the service delivery.")
            }));
        }
        finally {
            setDeleting(false);
        }

    };


    const resetPage = () =>
        setPaginationModel(prev => ({ ...prev, page: 0 }));

    const filterChange = (setter) => (value) => { setter(value); resetPage(); };

    const canUpdate = hasPermission(user, "service.update");
    const canDelete = hasPermission(user, "service.delete");


    const columns = [

        {
            field: "deliveryNumber",
            headerName: "Delivery",
            minWidth: 140,
            renderCell: (params) => (
                <Box sx={{ lineHeight: 1.3, py: 0.5 }}>
                    <Link
                        component="button"
                        underline="hover"
                        sx={{ fontWeight: 600, textAlign: "left" }}
                        onClick={() => navigate(`/service-deliveries/${params.row._id}`)}
                    >
                        {params.value || "-"}
                    </Link>
                    {params.row.deliveryDate && (
                        <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                            {new Date(params.row.deliveryDate).toLocaleDateString()}
                        </Typography>
                    )}
                </Box>
            )
        },

        {
            field: "beneficiaries",
            headerName: "Beneficiaries",
            flex: 1.2,
            minWidth: 170,
            sortable: false,
            valueGetter: (value, row) => summarize(beneficiaryNames(row))
        },

        {
            field: "project",
            headerName: "Project / Activity",
            flex: 1.2,
            minWidth: 170,
            sortable: false,
            renderCell: (params) => (
                <Box sx={{ lineHeight: 1.3, py: 0.5, minWidth: 0 }}>
                    <Typography variant="body2">
                        {lookupName(params.row.activity) || lookupName(params.row.project) || "-"}
                    </Typography>
                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                        {params.row.activity
                            ? lookupName(params.row.project)
                            : lookupName(params.row.program)}
                    </Typography>
                </Box>
            )
        },

        {
            field: "items",
            headerName: "Services",
            flex: 1.1,
            minWidth: 150,
            sortable: false,
            valueGetter: (value, row) => summarize(serviceNames(row))
        },

        {
            field: "totalAmount",
            headerName: "Value",
            minWidth: 125,
            align: "right",
            headerAlign: "right",
            valueGetter: (value) => formatMoney(value)
        },

        {
            field: "status",
            headerName: "Status",
            minWidth: 110,
            renderCell: (params) => <StatusChip status={params.value || "Delivered"} />
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
                        tooltip="View delivery"
                        onClick={() => navigate(`/service-deliveries/${params.row._id}`)}
                    />
                    {canUpdate && (
                        <AppIconButton
                            icon={<Edit fontSize="small" />}
                            tooltip="Edit delivery"
                            onClick={() => navigate(`/service-deliveries/${params.row._id}/edit`)}
                        />
                    )}
                    {canDelete && (
                        <AppIconButton
                            icon={<Delete fontSize="small" />}
                            tooltip="Delete delivery"
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
                title="Service Deliveries"
                subtitle="Services and support given to beneficiaries, with their value."
                {...(
                    hasPermission(user, "service.create")
                        ? {
                            action: () => navigate("/service-deliveries/create"),
                            actionLabel: "Create Delivery",
                            actionIcon: <Add />
                        }
                        : {}
                )}
            />

            <SearchToolbar
                search={search}
                onSearch={filterChange(setSearch)}
                onReset={() => {
                    setSearch("");
                    setProgram("");
                    setStatus("");
                    resetPage();
                }}
                filters={[
                    { key: "program", label: "Program", value: program, onChange: filterChange(setProgram), options: programOptions },
                    { key: "status", label: "Status", value: status, onChange: filterChange(setStatus), options: STATUS_OPTIONS }
                ]}
            />

            {result.error && (
                <Alert severity="error" sx={{ mb: 3 }}>
                    {result.error}
                </Alert>
            )}

            <PageCard>
                <DataTable
                    rows={rows}
                    columns={columns}
                    loading={result.loading}
                    paginationModel={paginationModel}
                    onPaginationModelChange={setPaginationModel}
                    getRowHeight={() => "auto"}
                    onRowDoubleClick={(params) => navigate(`/service-deliveries/${params.row._id}`)}
                />
            </PageCard>

            <ConfirmDeleteDialog
                open={Boolean(deleteTarget)}
                title="Delete Service Delivery"
                message={
                    deleteTarget
                        ? `Delete delivery ${deleteTarget.deliveryNumber || ""}? This cannot be undone.`
                        : ""
                }
                loading={deleting}
                onClose={() => !deleting && setDeleteTarget(null)}
                onConfirm={handleDelete}
            />

        </PageContainer>

    );

};


export default ServiceDeliveryListPage;
