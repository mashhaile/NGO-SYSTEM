import {
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

import useServerList
    from "../../../hooks/useServerList";

import {
    getDonorsApi,
    deleteDonorApi
} from "../api/donorApi";

import { hasPermission } from "../../../utils/permissions";
import { getApiErrorMessage } from "../../../utils/apiError";


const TYPE_OPTIONS =
    ["Individual", "Organization", "Government", "NGO", "Corporate", "Foundation"]
        .map(value => ({ value, label: value }));

const STATUS_OPTIONS =
    ["Active", "Inactive"].map(value => ({ value, label: value }));

const twoLine = (main, caption) => (
    <Box sx={{ lineHeight: 1.3, py: 0.5, minWidth: 0 }}>
        <Typography variant="body2">{main || "-"}</Typography>
        {caption && (
            <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                {caption}
            </Typography>
        )}
    </Box>
);


// =====================================================
// DONOR LIST PAGE
// =====================================================

const DonorListPage = () => {

    const navigate = useNavigate();

    const { user } = useAuth();

    const [search, setSearch] = useState("");
    const [donorType, setDonorType] = useState("");
    const [status, setStatus] = useState("");

    const [deleteTarget, setDeleteTarget] = useState(null);
    const [deleting, setDeleting] = useState(false);

    const list = useServerList(getDonorsApi, { search, donorType, status }, "Failed to load donors.");


    const handleDelete = async () => {

        setDeleting(true);

        try {
            await deleteDonorApi(deleteTarget._id);
            setDeleteTarget(null);
            list.reload();
        }
        catch (error) {
            setDeleteTarget(null);
            list.setError(getApiErrorMessage(error, "Failed to delete the donor."));
        }
        finally {
            setDeleting(false);
        }

    };


    const canUpdate = hasPermission(user, "donor.update");
    const canDelete = hasPermission(user, "donor.delete");

    const filterChange = (setter) => (value) => { setter(value); list.resetPage(); };


    const columns = [

        {
            field: "name",
            headerName: "Donor",
            flex: 1.4,
            minWidth: 220,
            renderCell: (params) => (
                <Box sx={{ lineHeight: 1.3, py: 0.5, minWidth: 0 }}>
                    <Link
                        component="button"
                        underline="hover"
                        sx={{ fontWeight: 600, textAlign: "left" }}
                        onClick={() => navigate(`/donors/${params.row._id}`)}
                    >
                        {params.value}
                    </Link>
                    {params.row.country && (
                        <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                            {params.row.country}
                        </Typography>
                    )}
                </Box>
            )
        },

        {
            field: "donorType",
            headerName: "Type",
            minWidth: 130,
            valueGetter: (value) => value || "-"
        },

        {
            field: "contactPerson",
            headerName: "Contact",
            flex: 1.3,
            minWidth: 220,
            sortable: false,
            renderCell: (params) => twoLine(params.row.contactPerson || params.row.email, params.row.contactPerson ? params.row.email : "")
        },

        {
            field: "phone",
            headerName: "Phone",
            minWidth: 150,
            valueGetter: (value) => value || "-"
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
                        tooltip="View donor"
                        onClick={() => navigate(`/donors/${params.row._id}`)}
                    />
                    {canUpdate && (
                        <AppIconButton
                            icon={<Edit fontSize="small" />}
                            tooltip="Edit donor"
                            onClick={() => navigate(`/donors/${params.row._id}/edit`)}
                        />
                    )}
                    {canDelete && (
                        <AppIconButton
                            icon={<Delete fontSize="small" />}
                            tooltip="Delete donor"
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
                title="Donors"
                subtitle="Donors and funding partners. Donations and projects are linked to a donor."
                {...(
                    hasPermission(user, "donor.create")
                        ? {
                            action: () => navigate("/donors/create"),
                            actionLabel: "Add Donor",
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
                    setDonorType("");
                    setStatus("");
                    list.resetPage();
                }}
                filters={[
                    { key: "donorType", label: "Type", value: donorType, onChange: filterChange(setDonorType), options: TYPE_OPTIONS },
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
                    onRowDoubleClick={(params) => navigate(`/donors/${params.row._id}`)}
                />
            </PageCard>

            <ConfirmDeleteDialog
                open={Boolean(deleteTarget)}
                title="Delete Donor"
                message={deleteTarget ? `Delete donor "${deleteTarget.name}"? This cannot be undone.` : ""}
                loading={deleting}
                onClose={() => !deleting && setDeleteTarget(null)}
                onConfirm={handleDelete}
            />

        </PageContainer>

    );

};


export default DonorListPage;
