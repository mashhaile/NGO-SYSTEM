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
    UploadFile,
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

import useServerList
    from "../../../hooks/useServerList";

import {
    getBeneficiariesApi,
    deleteBeneficiaryApi
} from "../api/beneficiaryApi";

import {
    getLookupsByModuleAndCategoryService
} from "../../lookups/services/lookupService";

import { hasPermission } from "../../../utils/permissions";
import { getApiErrorMessage } from "../../../utils/apiError";


const STATUS_OPTIONS =
    ["Active", "Inactive"].map(value => ({ value, label: value }));

const listOf = (response) =>
    Array.isArray(response) ? response
        : Array.isArray(response?.data?.data) ? response.data.data
            : Array.isArray(response?.data) ? response.data
                : [];

const lookupName = (value) =>
    !value ? "-" : typeof value === "object" ? value.value || value.name || "-" : String(value);

const fullName = (row) =>
    [row.firstName, row.middleName, row.lastName].filter(Boolean).join(" ") || row.beneficiaryNumber;


// =====================================================
// BENEFICIARY LIST PAGE
// =====================================================

const BeneficiaryListPage = () => {

    const navigate = useNavigate();

    const { user } = useAuth();

    const [search, setSearch] = useState("");
    const [gender, setGender] = useState("");
    const [status, setStatus] = useState("");
    const [genderOptions, setGenderOptions] = useState([]);

    const [deleteTarget, setDeleteTarget] = useState(null);
    const [deleting, setDeleting] = useState(false);

    const list = useServerList(getBeneficiariesApi, { search, gender, status }, "Failed to load beneficiaries.");


    useEffect(() => {
        getLookupsByModuleAndCategoryService("Beneficiary", "Gender")
            .then(response => setGenderOptions(
                listOf(response).map(item => ({ value: item._id, label: item.value || item.name }))
            ))
            .catch(() => setGenderOptions([]));
    }, []);


    const handleDelete = async () => {

        setDeleting(true);

        try {
            await deleteBeneficiaryApi(deleteTarget._id);
            setDeleteTarget(null);
            list.reload();
        }
        catch (error) {
            setDeleteTarget(null);
            list.setError(getApiErrorMessage(error, "Failed to delete the beneficiary."));
        }
        finally {
            setDeleting(false);
        }

    };


    const canCreate = hasPermission(user, "beneficiary.create");
    const canUpdate = hasPermission(user, "beneficiary.update");
    const canDelete = hasPermission(user, "beneficiary.delete");

    const filterChange = (setter) => (value) => { setter(value); list.resetPage(); };


    const columns = [

        {
            field: "firstName",
            headerName: "Beneficiary",
            flex: 1.5,
            minWidth: 230,
            renderCell: (params) => (
                <Box sx={{ lineHeight: 1.3, py: 0.5, minWidth: 0 }}>
                    <Link
                        component="button"
                        underline="hover"
                        sx={{ fontWeight: 600, textAlign: "left" }}
                        onClick={() => navigate(`/beneficiaries/${params.row._id}`)}
                    >
                        {fullName(params.row)}
                    </Link>
                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                        {params.row.beneficiaryNumber}
                    </Typography>
                </Box>
            )
        },

        {
            field: "gender",
            headerName: "Gender",
            minWidth: 100,
            valueGetter: (value) => lookupName(value)
        },

        {
            field: "age",
            headerName: "Age",
            minWidth: 70,
            align: "right",
            headerAlign: "right",
            valueGetter: (value) => (value || value === 0 ? value : "-")
        },

        {
            field: "phone",
            headerName: "Phone",
            minWidth: 130,
            valueGetter: (value) => value || "-"
        },

        {
            field: "region",
            headerName: "Location",
            flex: 1.2,
            minWidth: 190,
            sortable: false,
            renderCell: (params) => {
                const place = [params.row.woreda, params.row.zone].filter(Boolean).join(", ");
                return (
                    <Box sx={{ lineHeight: 1.3, py: 0.5, minWidth: 0 }}>
                        <Typography variant="body2">{params.row.region || "-"}</Typography>
                        {place && (
                            <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                                {place}
                            </Typography>
                        )}
                    </Box>
                );
            }
        },

        {
            field: "status",
            headerName: "Status",
            minWidth: 110,
            renderCell: (params) => <StatusChip status={params.value || "Active"} />
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
                        tooltip="View beneficiary"
                        onClick={() => navigate(`/beneficiaries/${params.row._id}`)}
                    />
                    {canUpdate && (
                        <AppIconButton
                            icon={<Edit fontSize="small" />}
                            tooltip="Edit beneficiary"
                            onClick={() => navigate(`/beneficiaries/${params.row._id}/edit`)}
                        />
                    )}
                    {canDelete && (
                        <AppIconButton
                            icon={<Delete fontSize="small" />}
                            tooltip="Delete beneficiary"
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
                title="Beneficiaries"
                subtitle="People registered by the organization, with their contact and location."
                {...(
                    canCreate
                        ? {
                            action: () => navigate("/beneficiaries/create"),
                            actionLabel: "Add Beneficiary",
                            actionIcon: <Add />,
                            secondaryAction: () => navigate("/beneficiaries/import"),
                            secondaryActionLabel: "Import Excel",
                            secondaryActionIcon: <UploadFile />
                        }
                        : {}
                )}
            />

            <SearchToolbar
                search={search}
                onSearch={filterChange(setSearch)}
                onReset={() => {
                    setSearch("");
                    setGender("");
                    setStatus("");
                    list.resetPage();
                }}
                filters={[
                    { key: "gender", label: "Gender", value: gender, onChange: filterChange(setGender), options: genderOptions },
                    { key: "status", label: "Status", value: status, onChange: filterChange(setStatus), options: STATUS_OPTIONS }
                ]}
            />

            {list.error && (
                <Alert severity="error" sx={{ mb: 3 }}>
                    {list.error}
                </Alert>
            )}

            <PageCard>
                <DataTable
                    rows={list.rows}
                    columns={columns}
                    loading={list.loading}
                    paginationMode="server"
                    rowCount={list.total}
                    paginationModel={list.paginationModel}
                    onPaginationModelChange={list.setPaginationModel}
                    getRowHeight={() => "auto"}
                    onRowDoubleClick={(params) => navigate(`/beneficiaries/${params.row._id}`)}
                />
            </PageCard>

            <ConfirmDeleteDialog
                open={Boolean(deleteTarget)}
                title="Delete Beneficiary"
                message={
                    deleteTarget
                        ? `Delete ${deleteTarget.beneficiaryNumber} "${fullName(deleteTarget)}"? This cannot be undone.`
                        : ""
                }
                loading={deleting}
                onClose={() => !deleting && setDeleteTarget(null)}
                onConfirm={handleDelete}
            />

        </PageContainer>

    );

};


export default BeneficiaryListPage;
