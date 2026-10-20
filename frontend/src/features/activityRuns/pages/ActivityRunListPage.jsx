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
    getActivityRunsApi,
    deleteActivityRunApi
} from "../api/activityRunApi";


import {
    hasPermission
} from "../../tor/utils/torPermissions";



const STATUS_OPTIONS = [
    "Planned",
    "Active",
    "Completed",
    "Cancelled"
].map(value => ({
    value,
    label: value
}));


const formatDate = (value) =>
    value
        ? new Date(value).toLocaleDateString()
        : "-";


const errorMessage = (error, fallback) =>
    error?.response?.data?.message ||
    error?.message ||
    fallback;



// =====================================================
// ACTIVITY RUN LIST PAGE
// =====================================================

const ActivityRunListPage = () => {

    const navigate =
        useNavigate();

    const {
        user
    } = useAuth();

    const [search, setSearch] =
        useState("");

    const [status, setStatus] =
        useState("");

    const [paginationModel, setPaginationModel] =
        useState({
            page: 0,
            pageSize: 10
        });

    const [deleteTarget, setDeleteTarget] =
        useState(null);

    const [deleting, setDeleting] =
        useState(false);

    // Bumped to reload the list after a delete.

    const [reloadKey, setReloadKey] =
        useState(0);

    const [result, setResult] =
        useState({
            rows: [],
            total: 0,
            loading: true,
            error: ""
        });


    // =================================================
    // LOAD
    // =================================================

    useEffect(() => {

        let cancelled = false;

        const timer =
            setTimeout(() => {

                getActivityRunsApi({
                    search: search.trim(),
                    status: status || undefined,
                    page: paginationModel.page + 1,
                    limit: paginationModel.pageSize
                })

                    .then(response => {

                        if (!cancelled) {
                            setResult({
                                rows: response.data?.data || [],
                                total: response.data?.pagination?.total || 0,
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
                                error: errorMessage(
                                    error,
                                    "Failed to load activity runs."
                                )
                            }));
                        }

                    });

            }, 300);

        return () => {
            cancelled = true;
            clearTimeout(timer);
        };

    }, [search, status, paginationModel, reloadKey]);


    // =================================================
    // DELETE
    // =================================================

    const handleDelete = async () => {

        setDeleting(true);

        try {

            await deleteActivityRunApi(deleteTarget._id);

            setDeleteTarget(null);

            setReloadKey(key => key + 1);

        }
        catch (error) {

            setDeleteTarget(null);

            setResult(prev => ({
                ...prev,
                error: errorMessage(
                    error,
                    "Failed to delete the activity run."
                )
            }));

        }
        finally {

            setDeleting(false);

        }

    };


    const resetPage = () =>
        setPaginationModel(prev => ({
            ...prev,
            page: 0
        }));


    const canUpdate =
        hasPermission(user, "activity_run.update");

    const canDelete =
        hasPermission(user, "activity_run.delete");


    const columns = [

        {
            field: "name",
            headerName: "Run",
            flex: 1.4,
            minWidth: 230,
            renderCell: (params) => (
                <Box sx={{ lineHeight: 1.3, py: 0.5 }}>
                    <Link
                        component="button"
                        underline="hover"
                        fontWeight={600}
                        sx={{ textAlign: "left" }}
                        onClick={() =>
                            navigate(`/activity-runs/${params.row._id}`)
                        }
                    >
                        {params.value || params.row.runCode || "-"}
                    </Link>
                    <Typography variant="caption" color="text.secondary" display="block">
                        {params.row.runCode}
                    </Typography>
                </Box>
            )
        },

        {
            field: "activity",
            headerName: "Activity",
            flex: 1.3,
            minWidth: 200,
            sortable: false,
            renderCell: (params) =>
                params.value
                    ? (
                        <Box sx={{ lineHeight: 1.3, py: 0.5 }}>
                            <Typography variant="body2">
                                {params.value.name}
                            </Typography>
                            <Typography variant="caption" color="text.secondary" display="block">
                                {params.value.activityCode}
                            </Typography>
                        </Box>
                    )
                    : "-"
        },

        {
            field: "startDate",
            headerName: "Dates",
            minWidth: 190,
            valueGetter: (value, row) =>
                row.startDate
                    ? `${formatDate(row.startDate)} – ${formatDate(row.endDate || row.startDate)}`
                    : "-"
        },

        {
            field: "region",
            headerName: "Location",
            flex: 1,
            minWidth: 170,
            valueGetter: (value, row) =>
                [row.location, row.woreda, row.zone, row.region]
                    .filter(Boolean)
                    .join(", ") || "-"
        },

        {
            field: "trainer",
            headerName: "Trainer",
            minWidth: 140,
            valueGetter: (value) =>
                value?.name || "-"
        },

        {
            field: "status",
            headerName: "Status",
            minWidth: 120,
            renderCell: (params) => (
                <StatusChip
                    status={params.value}
                />
            )
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
                        tooltip="View run"
                        onClick={() =>
                            navigate(`/activity-runs/${params.row._id}`)
                        }
                    />

                    {canUpdate && (
                        <AppIconButton
                            icon={<Edit fontSize="small" />}
                            tooltip="Edit run"
                            onClick={() =>
                                navigate(`/activity-runs/${params.row._id}/edit`)
                            }
                        />
                    )}

                    {canDelete && (
                        <AppIconButton
                            icon={<Delete fontSize="small" />}
                            tooltip="Delete run"
                            color="error"
                            onClick={() =>
                                setDeleteTarget(params.row)
                            }
                        />
                    )}

                </>

            )
        }

    ];


    return (

        <PageContainer>

            <PageHeader
                title="Activity Runs"
                subtitle="Sessions and batches of each activity, with attendance."
                {...(
                    hasPermission(user, "activity_run.create")
                        ? {
                            action: () =>
                                navigate("/activity-runs/create"),
                            actionLabel: "Create Activity Run",
                            actionIcon: <Add />
                        }
                        : {}
                )}
            />


            <SearchToolbar
                search={search}
                onSearch={(value) => {
                    setSearch(value);
                    resetPage();
                }}
                onReset={() => {
                    setSearch("");
                    setStatus("");
                    resetPage();
                }}
                filters={[
                    {
                        key: "status",
                        label: "Status",
                        value: status,
                        onChange: (value) => {
                            setStatus(value);
                            resetPage();
                        },
                        options: STATUS_OPTIONS
                    }
                ]}
            />


            {result.error && (

                <Alert
                    severity="error"
                    sx={{ mb: 3 }}
                >
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
                    onRowDoubleClick={(params) =>
                        navigate(`/activity-runs/${params.row._id}`)
                    }
                />

            </PageCard>


            <ConfirmDeleteDialog
                open={Boolean(deleteTarget)}
                title="Delete Activity Run"
                message={
                    deleteTarget
                        ? `Delete "${deleteTarget.name || deleteTarget.runCode}"? This cannot be undone.`
                        : ""
                }
                loading={deleting}
                onClose={() =>
                    !deleting && setDeleteTarget(null)
                }
                onConfirm={handleDelete}
            />

        </PageContainer>

    );

};


export default ActivityRunListPage;
