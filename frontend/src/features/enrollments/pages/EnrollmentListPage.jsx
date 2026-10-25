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
    getEnrollmentsApi,
    deleteEnrollmentApi
} from "../api/enrollmentApi";


import {
    hasPermission
} from "../../tor/utils/torPermissions";
import { formatDate } from "../../../utils/date";



const STATUS_OPTIONS = [
    "Pending",
    "Active",
    "Completed",
    "Dropped"
].map(value => ({
    value,
    label: value
}));


const errorMessage = (error, fallback) =>
    error?.response?.data?.message ||
    error?.message ||
    fallback;


const beneficiaryName = (beneficiary) =>
    beneficiary
        ? [beneficiary.firstName, beneficiary.lastName]
            .filter(Boolean)
            .join(" ")
        : "";



// =====================================================
// ENROLLMENT LIST PAGE
// =====================================================

const EnrollmentListPage = () => {

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

                getEnrollmentsApi({
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
                                    "Failed to load enrollments."
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

            await deleteEnrollmentApi(deleteTarget._id);

            setDeleteTarget(null);

            setReloadKey(key => key + 1);

        }
        catch (error) {

            setDeleteTarget(null);

            setResult(prev => ({
                ...prev,
                error: errorMessage(
                    error,
                    "Failed to delete the enrollment."
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
        hasPermission(user, "enrollment.update");

    const canDelete =
        hasPermission(user, "enrollment.delete");


    const columns = [

        {
            field: "beneficiary",
            headerName: "Beneficiary",
            flex: 1.3,
            minWidth: 200,
            sortable: false,
            renderCell: (params) => (
                <Box sx={{ lineHeight: 1.3, py: 0.5 }}>
                    <Link
                        component="button"
                        underline="hover"
                        sx={{ fontWeight: 600, textAlign: "left" }}
                        onClick={() =>
                            navigate(`/enrollments/${params.row._id}`)
                        }
                    >
                        {beneficiaryName(params.value) || "-"}
                    </Link>
                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                        {params.value?.beneficiaryNumber}
                    </Typography>
                </Box>
            )
        },

        {
            field: "program",
            headerName: "Program",
            flex: 1.5,
            minWidth: 220,
            sortable: false,
            renderCell: (params) =>
                params.value
                    ? (
                        <Box sx={{ lineHeight: 1.3, py: 0.5, minWidth: 0 }}>
                            <Typography variant="body2" noWrap title={params.value.name}>
                                {params.value.name}
                            </Typography>
                            <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                                {params.value.programCode}
                            </Typography>
                        </Box>
                    )
                    : "-"
        },

        {
            field: "enrollmentDate",
            headerName: "Enrolled",
            minWidth: 120,
            valueGetter: (value) =>
                formatDate(value)
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
            width: 124,
            sortable: false,
            filterable: false,
            disableColumnMenu: true,
            renderCell: (params) => (

                <>

                    <AppIconButton
                        icon={<Visibility fontSize="small" />}
                        tooltip="View enrollment"
                        onClick={() =>
                            navigate(`/enrollments/${params.row._id}`)
                        }
                    />

                    {canUpdate && (
                        <AppIconButton
                            icon={<Edit fontSize="small" />}
                            tooltip="Edit enrollment"
                            onClick={() =>
                                navigate(`/enrollments/${params.row._id}/edit`)
                            }
                        />
                    )}

                    {canDelete && (
                        <AppIconButton
                            icon={<Delete fontSize="small" />}
                            tooltip="Delete enrollment"
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
                title="Enrollments"
                subtitle="Beneficiaries enrolled in programs."
                {...(
                    hasPermission(user, "enrollment.create")
                        ? {
                            action: () =>
                                navigate("/enrollments/create"),
                            actionLabel: "Create Enrollment",
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
                        navigate(`/enrollments/${params.row._id}`)
                    }
                />

            </PageCard>


            <ConfirmDeleteDialog
                open={Boolean(deleteTarget)}
                title="Delete Enrollment"
                message={
                    deleteTarget
                        ? `Delete the enrollment of ${beneficiaryName(deleteTarget.beneficiary) || "this beneficiary"} in ${deleteTarget.program?.name || "this program"}? This cannot be undone.`
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


export default EnrollmentListPage;
