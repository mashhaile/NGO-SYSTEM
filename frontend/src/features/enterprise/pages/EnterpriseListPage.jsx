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
    Groups,
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
    getEnterprisesApi,
    deleteEnterpriseApi
} from "../api/enterpriseApi";

import {
    getLookupsByModuleAndCategoryService
} from "../../lookups/services/lookupService";

import { hasPermission } from "../../../utils/permissions";
import { getApiErrorMessage } from "../../../utils/apiError";


const listOf = (response) =>
    Array.isArray(response) ? response
        : Array.isArray(response?.data?.data) ? response.data.data
            : Array.isArray(response?.data) ? response.data
                : [];

const toOptions = (response) =>
    listOf(response).map(item => ({ value: item._id, label: item.value || item.name }));

const lookupName = (value) =>
    !value ? "" : typeof value === "object" ? value.value || value.name || "" : String(value);


// =====================================================
// ENTERPRISE LIST PAGE
// =====================================================

const EnterpriseListPage = () => {

    const navigate = useNavigate();

    const { user } = useAuth();

    const [search, setSearch] = useState("");
    const [enterpriseType, setEnterpriseType] = useState("");
    const [businessSector, setBusinessSector] = useState("");
    const [options, setOptions] = useState({ types: [], sectors: [] });

    const [deleteTarget, setDeleteTarget] = useState(null);
    const [deleting, setDeleting] = useState(false);

    const list = useServerList(
        getEnterprisesApi,
        { search, enterpriseType, businessSector },
        "Failed to load enterprises."
    );


    useEffect(() => {
        Promise.all([
            getLookupsByModuleAndCategoryService("Enterprise", "EnterpriseType").catch(() => []),
            getLookupsByModuleAndCategoryService("Enterprise", "BusinessSector").catch(() => [])
        ]).then(([types, sectors]) => setOptions({ types: toOptions(types), sectors: toOptions(sectors) }));
    }, []);


    const handleDelete = async () => {

        setDeleting(true);

        try {
            await deleteEnterpriseApi(deleteTarget._id);
            setDeleteTarget(null);
            list.reload();
        }
        catch (error) {
            setDeleteTarget(null);
            list.setError(getApiErrorMessage(error, "Failed to delete the enterprise."));
        }
        finally {
            setDeleting(false);
        }

    };


    const canUpdate = hasPermission(user, "enterprise.update");
    const canDelete = hasPermission(user, "enterprise.delete");

    const filterChange = (setter) => (value) => { setter(value); list.resetPage(); };


    const columns = [

        {
            field: "name",
            headerName: "Enterprise",
            flex: 1.4,
            minWidth: 220,
            renderCell: (params) => (
                <Box sx={{ lineHeight: 1.3, py: 0.5, minWidth: 0 }}>
                    <Link
                        component="button"
                        underline="hover"
                        sx={{ fontWeight: 600, textAlign: "left" }}
                        onClick={() => navigate(`/enterprises/${params.row._id}`)}
                    >
                        {params.value}
                    </Link>
                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                        {params.row.enterpriseNumber}
                    </Typography>
                </Box>
            )
        },

        {
            field: "enterpriseType",
            headerName: "Type",
            flex: 1.2,
            minWidth: 190,
            sortable: false,
            renderCell: (params) => (
                <Box sx={{ lineHeight: 1.3, py: 0.5, minWidth: 0 }}>
                    <Typography variant="body2">{lookupName(params.row.enterpriseType) || "-"}</Typography>
                    {lookupName(params.row.ownershipType) && (
                        <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                            {lookupName(params.row.ownershipType)}
                        </Typography>
                    )}
                </Box>
            )
        },

        {
            field: "businessSector",
            headerName: "Sector",
            flex: 1,
            minWidth: 150,
            sortable: false,
            valueGetter: (value) => lookupName(value) || "-"
        },

        {
            field: "phone",
            headerName: "Phone",
            minWidth: 130,
            valueGetter: (value) => value || "-"
        },

        {
            field: "status",
            headerName: "Status",
            minWidth: 110,
            renderCell: (params) => <StatusChip status={lookupName(params.value) || "Active"} />
        },

        {
            field: "actions",
            headerName: "Actions",
            width: 170,
            sortable: false,
            filterable: false,
            disableColumnMenu: true,
            renderCell: (params) => (
                <>
                    <AppIconButton
                        icon={<Visibility fontSize="small" />}
                        tooltip="View enterprise"
                        onClick={() => navigate(`/enterprises/${params.row._id}`)}
                    />
                    <AppIconButton
                        icon={<Groups fontSize="small" />}
                        tooltip="Members"
                        onClick={() => navigate(`/enterprises/${params.row._id}/members`)}
                    />
                    {canUpdate && (
                        <AppIconButton
                            icon={<Edit fontSize="small" />}
                            tooltip="Edit enterprise"
                            onClick={() => navigate(`/enterprises/${params.row._id}/edit`)}
                        />
                    )}
                    {canDelete && (
                        <AppIconButton
                            icon={<Delete fontSize="small" />}
                            tooltip="Delete enterprise"
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
                title="Enterprises"
                subtitle="Businesses and cooperatives run by beneficiaries."
                {...(
                    hasPermission(user, "enterprise.create")
                        ? {
                            action: () => navigate("/enterprises/create"),
                            actionLabel: "Add Enterprise",
                            actionIcon: <Add />
                        }
                        : {}
                )}
                secondaryAction={() => navigate("/enterprise-members")}
                secondaryActionLabel="All Members"
                secondaryActionIcon={<Groups />}
            />

            <SearchToolbar
                search={search}
                onSearch={filterChange(setSearch)}
                onReset={() => {
                    setSearch("");
                    setEnterpriseType("");
                    setBusinessSector("");
                    list.resetPage();
                }}
                filters={[
                    { key: "enterpriseType", label: "Type", value: enterpriseType, onChange: filterChange(setEnterpriseType), options: options.types },
                    { key: "businessSector", label: "Sector", value: businessSector, onChange: filterChange(setBusinessSector), options: options.sectors }
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
                    onRowDoubleClick={(params) => navigate(`/enterprises/${params.row._id}`)}
                />
            </PageCard>

            <ConfirmDeleteDialog
                open={Boolean(deleteTarget)}
                title="Delete Enterprise"
                message={
                    deleteTarget
                        ? `Delete ${deleteTarget.enterpriseNumber} "${deleteTarget.name}"? This cannot be undone.`
                        : ""
                }
                loading={deleting}
                onClose={() => !deleting && setDeleteTarget(null)}
                onConfirm={handleDelete}
            />

        </PageContainer>

    );

};


export default EnterpriseListPage;
