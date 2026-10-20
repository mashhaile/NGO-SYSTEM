import {
    useEffect,
    useMemo,
    useState
} from "react";

import {
    Alert,
    Chip,
    Stack,
    Typography
} from "@mui/material";

import {
    Add,
    Edit,
    Delete,
    LockReset
} from "@mui/icons-material";

import {
    useNavigate
} from "react-router-dom";

import {
    toast
} from "react-toastify";

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

import {
    getUsersService,
    deleteUserService,
    resetUserPasswordService
} from "../services/userService";

import ResetPasswordDialog
    from "../components/ResetPasswordDialog";

import {
    useAuth
} from "../../auth";

import {
    hasPermission
} from "../../tor/utils/torPermissions";


const ROLE_OPTIONS = [
    {
        value: "organization_admin",
        label: "Organization Admin"
    },
    {
        value: "data_entry",
        label: "Data Entry"
    },
    {
        value: "viewer",
        label: "Viewer"
    }
];


const roleLabel = (role) =>
    role
        ? role
            .replace(/_/g, " ")
            .replace(/\b\w/g, char => char.toUpperCase())
        : "-";


const isLocked = (user) =>
    Boolean(user.lockUntil) &&
    new Date(user.lockUntil) > new Date();


// ==========================================
// USER LIST PAGE
// ==========================================

const UserListPage = () => {

    const navigate = useNavigate();

    const {
        user: currentUser
    } = useAuth();

    const currentUserId =
        String(currentUser?.id || currentUser?._id || "");

    const [users, setUsers] = useState([]);

    const [loading, setLoading] = useState(true);

    const [error, setError] = useState("");

    const [search, setSearch] = useState("");

    const [role, setRole] = useState("");

    const [resetUser, setResetUser] = useState(null);

    const [deleteTarget, setDeleteTarget] = useState(null);

    const [deleting, setDeleting] = useState(false);

    // Bumped to reload after a change.

    const [reloadKey, setReloadKey] = useState(0);


    // ==========================================
    // LOAD
    // ==========================================

    useEffect(() => {

        let cancelled = false;

        getUsersService()

            .then(response => {

                if (!cancelled) {
                    setUsers(response.data || []);
                    setError("");
                    setLoading(false);
                }

            })

            .catch(err => {

                if (!cancelled) {
                    setError(
                        err.response?.data?.message ||
                        "Failed to load users."
                    );
                    setLoading(false);
                }

            });

        return () => {
            cancelled = true;
        };

    }, [reloadKey]);


    const rows = useMemo(() => {

        const text =
            search.trim().toLowerCase();

        return users.filter(user =>
            (!role || user.role === role) &&
            (
                !text ||
                [user.name, user.email]
                    .some(value =>
                        String(value || "").toLowerCase().includes(text)
                    )
            )
        );

    }, [users, search, role]);


    // ==========================================
    // DEACTIVATE
    // ==========================================

    const handleDelete = async () => {

        setDeleting(true);

        try {

            await deleteUserService(
                deleteTarget._id || deleteTarget.id
            );

            toast.success("User deactivated");

            setDeleteTarget(null);

            setReloadKey(key => key + 1);

        }
        catch (err) {

            toast.error(
                err.response?.data?.message ||
                "Failed to deactivate the user."
            );

            setDeleteTarget(null);

        }
        finally {

            setDeleting(false);

        }

    };


    const canUpdate =
        hasPermission(currentUser, "user.update");

    const canDelete =
        hasPermission(currentUser, "user.delete");


    const columns = [

        {
            field: "name",
            headerName: "Name",
            flex: 1.2,
            minWidth: 180,
            renderCell: (params) => (
                <Typography
                    variant="body2"
                    sx={{
                        fontWeight: 600,
                        height: "100%",
                        display: "flex",
                        alignItems: "center"
                    }}
                >
                    {params.value}
                </Typography>
            )
        },

        {
            field: "email",
            headerName: "Email",
            flex: 1.4,
            minWidth: 220
        },

        {
            field: "role",
            headerName: "Role",
            minWidth: 160,
            valueGetter: (value) =>
                roleLabel(value)
        },

        {
            field: "status",
            headerName: "Status",
            minWidth: 170,
            renderCell: (params) => (
                <Stack direction="row" spacing={0.75} sx={{ alignItems: "center", height: "100%" }}>
                    <StatusChip status={params.value} />
                    {isLocked(params.row) && (
                        <Chip
                            size="small"
                            color="warning"
                            variant="outlined"
                            label="Locked"
                            title="Too many wrong passwords. Unlocks automatically, or reset the password."
                        />
                    )}
                    {params.row.mustChangePassword && (
                        <Chip
                            size="small"
                            variant="outlined"
                            label="Temp password"
                            title="Must choose a new password at next sign in"
                        />
                    )}
                </Stack>
            )
        },

        {
            field: "actions",
            headerName: "Actions",
            width: 140,
            sortable: false,
            filterable: false,
            disableColumnMenu: true,
            renderCell: (params) => {

                const row = params.row;

                const id =
                    String(row._id || row.id);

                const isSelf =
                    id === currentUserId;

                return (

                    <>

                        {canUpdate && (
                            <AppIconButton
                                icon={<Edit fontSize="small" />}
                                tooltip="Edit user"
                                onClick={() =>
                                    navigate(`/users/${id}/edit`)
                                }
                            />
                        )}

                        {canUpdate && !isSelf && (
                            <AppIconButton
                                icon={<LockReset fontSize="small" />}
                                tooltip="Reset password"
                                color="warning"
                                onClick={() =>
                                    setResetUser(row)
                                }
                            />
                        )}

                        {canDelete && !isSelf && (
                            <AppIconButton
                                icon={<Delete fontSize="small" />}
                                tooltip="Deactivate user"
                                color="error"
                                onClick={() =>
                                    setDeleteTarget(row)
                                }
                            />
                        )}

                    </>

                );

            }
        }

    ];


    return (

        <PageContainer>

            <PageHeader
                title="User Management"
                subtitle="Manage users and access within your organization."
                {...(
                    hasPermission(currentUser, "user.create")
                        ? {
                            action: () =>
                                navigate("/users/create"),
                            actionLabel: "Create User",
                            actionIcon: <Add />
                        }
                        : {}
                )}
            />


            <SearchToolbar
                search={search}
                onSearch={setSearch}
                onReset={() => {
                    setSearch("");
                    setRole("");
                }}
                filters={[
                    {
                        key: "role",
                        label: "Role",
                        value: role,
                        onChange: setRole,
                        options: ROLE_OPTIONS
                    }
                ]}
            />


            {error && (
                <Alert severity="error" sx={{ mb: 3 }}>
                    {error}
                </Alert>
            )}


            <PageCard>

                <DataTable
                    rows={rows}
                    columns={columns}
                    loading={loading}
                />

            </PageCard>


            <ResetPasswordDialog
                user={resetUser}
                resetFn={resetUserPasswordService}
                onClose={() => {
                    setResetUser(null);
                    setReloadKey(key => key + 1);
                }}
            />


            <ConfirmDeleteDialog
                open={Boolean(deleteTarget)}
                title="Deactivate User"
                message={
                    deleteTarget
                        ? `Deactivate "${deleteTarget.name}"? They will no longer be able to sign in.`
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


export default UserListPage;
