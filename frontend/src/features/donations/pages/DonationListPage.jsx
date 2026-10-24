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
    Button,
    Link,
    Typography
} from "@mui/material";

import {
    Add,
    Delete,
    Edit,
    Visibility,
    WarningAmber
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
    getDonationsApi,
    deleteDonationApi
} from "../api/donationApi";

import {
    getDonorsLookupApi
} from "../../donors/api/donorApi";

import { hasPermission } from "../../../utils/permissions";
import { getApiErrorMessage } from "../../../utils/apiError";

import {
    getDoubleCountingApi
} from "../../ServiceDelivery/api/serviceDeliveryApi";


const STATUS_OPTIONS =
    ["Pledged", "Received", "Cancelled"].map(value => ({ value, label: value }));

const formatAmount = (value, currency) =>
    value === null || value === undefined
        ? "-"
        : `${currency ? `${currency} ` : ""}${Number(value).toLocaleString(undefined, { maximumFractionDigits: 2 })}`;

// What the donation is earmarked for, most specific first
const allocationOf = (donation) => {
    if (donation.activityRun) return { label: "Activity run", name: donation.activityRun.name || donation.activityRun.runCode };
    if (donation.activity) return { label: "Activity", name: donation.activity.name || donation.activity.activityCode };
    if (donation.project) return { label: "Project", name: donation.project.name || donation.project.projectCode };
    if (donation.program) return { label: "Program", name: donation.program.name || donation.program.programCode };
    return { label: "", name: "General" };
};


// =====================================================
// DONATION LIST PAGE
// =====================================================
// The donations API returns the whole (filtered) list, so
// search and paging happen here.

// Items given out and expenses that look like the same money
const DoubleCountingNotice = ({ onOpen }) => {

    const [count, setCount] = useState(0);

    useEffect(() => {
        let cancelled = false;
        getDoubleCountingApi()
            .then(rows => { if (!cancelled) setCount(rows.length); })
            .catch(() => {});
        return () => { cancelled = true; };
    }, []);

    if (!count) return null;

    return (
        <Alert
            severity="warning"
            variant="outlined"
            sx={{ mb: 2 }}
            action={
                <Button color="warning" size="small" onClick={onOpen}>
                    Review
                </Button>
            }
        >
            {count} delivery item{count === 1 ? "" : "s"} may be counted twice with an expense on the same donation (bought with the expense, then given out).
        </Alert>
    );

};


const DonationListPage = () => {

    const navigate = useNavigate();

    const { user } = useAuth();

    const [search, setSearch] = useState("");
    const [donor, setDonor] = useState("");
    const [status, setStatus] = useState("");
    const [donorOptions, setDonorOptions] = useState([]);

    const [paginationModel, setPaginationModel] =
        useState({ page: 0, pageSize: 10 });

    const [deleteTarget, setDeleteTarget] = useState(null);
    const [deleting, setDeleting] = useState(false);

    // Bumped to reload after a delete
    const [reloadKey, setReloadKey] = useState(0);

    const [result, setResult] =
        useState({ rows: [], loading: true, error: "" });


    useEffect(() => {
        getDonorsLookupApi()
            .then(({ data }) => setDonorOptions(
                (data?.data || []).map(item => ({ value: item._id, label: item.name }))
            ))
            .catch(() => setDonorOptions([]));
    }, []);


    useEffect(() => {

        let cancelled = false;

        getDonationsApi({ donor: donor || undefined, status: status || undefined })
            .then(({ data: response }) => {
                if (!cancelled) setResult({ rows: response.data || [], loading: false, error: "" });
            })
            .catch(error => {
                if (!cancelled) {
                    setResult(prev => ({
                        ...prev,
                        loading: false,
                        error: getApiErrorMessage(error, "Failed to load donations.")
                    }));
                }
            });

        return () => {
            cancelled = true;
        };

    }, [donor, status, reloadKey]);


    const rows = useMemo(() => {
        const term = search.trim().toLowerCase();
        if (!term) return result.rows;
        return result.rows.filter(item =>
            [item.donationCode, item.title, item.donor?.name, allocationOf(item).name]
                .some(value => String(value || "").toLowerCase().includes(term))
        );
    }, [result.rows, search]);


    const handleDelete = async () => {

        setDeleting(true);

        try {
            await deleteDonationApi(deleteTarget._id);
            setDeleteTarget(null);
            setReloadKey(key => key + 1);
        }
        catch (error) {
            setDeleteTarget(null);
            setResult(prev => ({
                ...prev,
                error: getApiErrorMessage(error, "Failed to delete the donation.")
            }));
        }
        finally {
            setDeleting(false);
        }

    };


    const resetPage = () =>
        setPaginationModel(prev => ({ ...prev, page: 0 }));

    const filterChange = (setter) => (value) => { setter(value); resetPage(); };

    const canUpdate = hasPermission(user, "donation.update");
    const canDelete = hasPermission(user, "donation.delete");


    const columns = [

        {
            field: "title",
            headerName: "Donation",
            flex: 1.3,
            minWidth: 210,
            renderCell: (params) => (
                <Box sx={{ lineHeight: 1.3, py: 0.5, minWidth: 0 }}>
                    <Link
                        component="button"
                        underline="hover"
                        sx={{ fontWeight: 600, textAlign: "left" }}
                        onClick={() => navigate(`/donations/${params.row._id}`)}
                    >
                        {params.value || params.row.donationCode}
                    </Link>
                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                        {params.row.donationCode}
                    </Typography>
                </Box>
            )
        },

        {
            field: "donor",
            headerName: "Donor",
            flex: 1,
            minWidth: 150,
            valueGetter: (value, row) => value?.name || row.donorName || "-"
        },

        {
            field: "allocation",
            headerName: "Allocated to",
            flex: 1.3,
            minWidth: 200,
            sortable: false,
            renderCell: (params) => {
                const allocation = allocationOf(params.row);
                return (
                    <Box sx={{ lineHeight: 1.3, py: 0.5, minWidth: 0 }}>
                        <Typography variant="body2">{allocation.name}</Typography>
                        {allocation.label && (
                            <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                                {allocation.label}
                            </Typography>
                        )}
                    </Box>
                );
            }
        },

        {
            field: "amount",
            headerName: "Amount",
            minWidth: 150,
            align: "right",
            headerAlign: "right",
            valueGetter: (value, row) => formatAmount(value, row.currency)
        },

        {
            field: "donationDate",
            headerName: "Date",
            minWidth: 110,
            valueGetter: (value) => (value ? new Date(value).toLocaleDateString() : "-")
        },

        {
            field: "status",
            headerName: "Status",
            minWidth: 110,
            renderCell: (params) => <StatusChip status={params.value || "Pledged"} />
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
                        tooltip="View donation"
                        onClick={() => navigate(`/donations/${params.row._id}`)}
                    />
                    {canUpdate && (
                        <AppIconButton
                            icon={<Edit fontSize="small" />}
                            tooltip="Edit donation"
                            onClick={() => navigate(`/donations/${params.row._id}/edit`)}
                        />
                    )}
                    {canDelete && (
                        <AppIconButton
                            icon={<Delete fontSize="small" />}
                            tooltip="Delete donation"
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
                title="Donations"
                subtitle="Funds received or pledged by donors, and what each one is allocated to."
                {...(
                    hasPermission(user, "donation.create")
                        ? {
                            action: () => navigate("/donations/create"),
                            actionLabel: "Add Donation",
                            actionIcon: <Add />
                        }
                        : {}
                )}
                secondaryAction={() => navigate("/donations/untraced")}
                secondaryActionLabel="Untraced Spending"
                secondaryActionIcon={<WarningAmber />}
            />

            <DoubleCountingNotice
                onOpen={() => navigate("/donations/double-counting")}
            />

            <SearchToolbar
                search={search}
                onSearch={filterChange(setSearch)}
                onReset={() => {
                    setSearch("");
                    setDonor("");
                    setStatus("");
                    resetPage();
                }}
                filters={[
                    { key: "donor", label: "Donor", value: donor, onChange: filterChange(setDonor), options: donorOptions },
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
                    onRowDoubleClick={(params) => navigate(`/donations/${params.row._id}`)}
                />
            </PageCard>

            <ConfirmDeleteDialog
                open={Boolean(deleteTarget)}
                title="Delete Donation"
                message={
                    deleteTarget
                        ? `Delete ${deleteTarget.donationCode} "${deleteTarget.title || ""}"? This cannot be undone.`
                        : ""
                }
                loading={deleting}
                onClose={() => !deleting && setDeleteTarget(null)}
                onConfirm={handleDelete}
            />

        </PageContainer>

    );

};


export default DonationListPage;
