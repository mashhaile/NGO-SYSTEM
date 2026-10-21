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
    ArrowBack,
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
    getEnterpriseMembersApi,
    deleteEnterpriseMemberApi
} from "../api/enterpriseMemberApi";

import {
    getEnterpriseLookupApi
} from "../api/enterpriseApi";

import { hasPermission } from "../../../utils/permissions";
import { getApiErrorMessage } from "../../../utils/apiError";


const STATUS_OPTIONS =
    ["Active", "Inactive"].map(value => ({ value, label: value }));

const lookupName = (value, fallback = "-") =>
    !value ? fallback : typeof value === "object" ? value.value || value.label || value.name || fallback : String(value);

const personName = (person) =>
    !person || typeof person !== "object"
        ? String(person || "-")
        : [person.firstName, person.middleName, person.lastName].filter(Boolean).join(" ") || person.beneficiaryNumber || "-";

const dateOf = (value) =>
    value ? new Date(value).toLocaleDateString() : "";

const enterpriseIdOf = (member) =>
    member.enterprise?._id || (typeof member.enterprise === "string" ? member.enterprise : member.enterpriseId);

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
// ENTERPRISE MEMBER LIST PAGE
// =====================================================
// Members of all enterprises. Each enterprise's own
// member list is at /enterprises/:id/members.

const EnterpriseMemberListPage = () => {

    const navigate = useNavigate();

    const { user } = useAuth();

    const [search, setSearch] = useState("");
    const [enterprise, setEnterprise] = useState("");
    const [status, setStatus] = useState("");
    const [enterpriseOptions, setEnterpriseOptions] = useState([]);

    const [deleteTarget, setDeleteTarget] = useState(null);
    const [deleting, setDeleting] = useState(false);

    const list = useServerList(
        getEnterpriseMembersApi,
        { search, enterprise, status },
        "Failed to load enterprise members."
    );


    useEffect(() => {
        getEnterpriseLookupApi()
            .then(response => setEnterpriseOptions(
                (Array.isArray(response?.data) ? response.data : []).map(item => ({
                    value: item._id,
                    label: item.name || item.enterpriseNumber
                }))
            ))
            .catch(() => setEnterpriseOptions([]));
    }, []);


    const handleDelete = async () => {

        setDeleting(true);

        try {
            await deleteEnterpriseMemberApi(deleteTarget._id);
            setDeleteTarget(null);
            list.reload();
        }
        catch (error) {
            setDeleteTarget(null);
            list.setError(getApiErrorMessage(error, "Failed to remove the member."));
        }
        finally {
            setDeleting(false);
        }

    };


    const canUpdate = hasPermission(user, "enterprise.update");

    const filterChange = (setter) => (value) => { setter(value); list.resetPage(); };

    const memberUrl = (row) => `/enterprises/${enterpriseIdOf(row)}/members/${row._id}`;


    const columns = [

        {
            field: "beneficiary",
            headerName: "Member",
            flex: 1.4,
            minWidth: 220,
            sortable: false,
            renderCell: (params) => (
                <Box sx={{ lineHeight: 1.3, py: 0.5, minWidth: 0 }}>
                    <Link
                        component="button"
                        underline="hover"
                        sx={{ fontWeight: 600, textAlign: "left" }}
                        onClick={() => navigate(memberUrl(params.row))}
                    >
                        {personName(params.row.beneficiary)}
                    </Link>
                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                        {params.row.beneficiary?.beneficiaryNumber}
                    </Typography>
                </Box>
            )
        },

        {
            field: "enterprise",
            headerName: "Enterprise",
            flex: 1.3,
            minWidth: 200,
            sortable: false,
            renderCell: (params) => twoLine(params.row.enterprise?.name, params.row.enterprise?.enterpriseNumber)
        },

        {
            field: "memberRole",
            headerName: "Role",
            minWidth: 120,
            valueGetter: (value) => lookupName(value, "Member")
        },

        {
            field: "joinedDate",
            headerName: "Membership",
            minWidth: 170,
            sortable: false,
            renderCell: (params) => twoLine(
                dateOf(params.row.joinedDate) ? `Joined ${dateOf(params.row.joinedDate)}` : "-",
                dateOf(params.row.leftDate) ? `Left ${dateOf(params.row.leftDate)}` : ""
            )
        },

        {
            field: "status",
            headerName: "Status",
            minWidth: 110,
            renderCell: (params) => <StatusChip status={lookupName(params.value, "Active")} />
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
                        tooltip="View member"
                        onClick={() => navigate(memberUrl(params.row))}
                    />
                    {canUpdate && (
                        <AppIconButton
                            icon={<Edit fontSize="small" />}
                            tooltip="Edit member"
                            onClick={() => navigate(`${memberUrl(params.row)}/edit`)}
                        />
                    )}
                    {canUpdate && (
                        <AppIconButton
                            icon={<Delete fontSize="small" />}
                            tooltip="Remove from enterprise"
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
                title="Enterprise Members"
                subtitle="Beneficiaries taking part in enterprises. Add members from an enterprise's page."
                action={() => navigate("/enterprises")}
                actionLabel="Enterprises"
                actionIcon={<ArrowBack />}
            />

            <SearchToolbar
                search={search}
                onSearch={filterChange(setSearch)}
                onReset={() => {
                    setSearch("");
                    setEnterprise("");
                    setStatus("");
                    list.resetPage();
                }}
                filters={[
                    { key: "enterprise", label: "Enterprise", value: enterprise, onChange: filterChange(setEnterprise), options: enterpriseOptions },
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
                    onRowDoubleClick={(params) => navigate(memberUrl(params.row))}
                />
            </PageCard>

            <ConfirmDeleteDialog
                open={Boolean(deleteTarget)}
                title="Remove Member"
                message={
                    deleteTarget
                        ? `Remove ${personName(deleteTarget.beneficiary)} from ${deleteTarget.enterprise?.name || "the enterprise"}?`
                        : ""
                }
                loading={deleting}
                onClose={() => !deleting && setDeleteTarget(null)}
                onConfirm={handleDelete}
            />

        </PageContainer>

    );

};


export default EnterpriseMemberListPage;
