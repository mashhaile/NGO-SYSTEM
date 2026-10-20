import {
    useEffect,
    useState
} from "react";

import {
    Box,
    Button,
    Card,
    CardContent,
    Chip,
    CircularProgress,
    IconButton,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Tooltip,
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
    getUsersService,
    deleteUserService,
    resetUserPasswordService
} from "../services/userService";

import ResetPasswordDialog
    from "../components/ResetPasswordDialog";

import {
    useAuth
} from "../../auth";


// ==========================================
// USER LIST PAGE
// ==========================================

const UserListPage = () => {

    const navigate = useNavigate();

    const [users, setUsers] = useState([]);

    const [loading, setLoading] = useState(true);

    const [error, setError] = useState(null);

    const [resetUser, setResetUser] = useState(null);

    const {
        user: currentUser
    } = useAuth();

    const currentUserId =
        String(currentUser?.id || currentUser?._id || "");


    // ==========================================
    // LOAD USERS
    // ==========================================

    const loadUsers = async () => {

        try {

            setLoading(true);

            setError(null);

            const response =
                await getUsersService();

            if (response.success) {

                setUsers(
                    response.data || []
                );

            } else {

                setError(
                    response.message ||
                    "Failed to load users"
                );

            }

        }
        catch (error) {

            console.error(
                "Load users error:",
                error
            );

            setError(
                error.response?.data?.message ||
                error.message ||
                "Failed to load users"
            );

        }
        finally {

            setLoading(false);

        }

    };


    // ==========================================
    // INITIAL LOAD
    // ==========================================

    useEffect(() => {

        loadUsers();

    }, []);


    // ==========================================
    // DELETE / DEACTIVATE USER
    // ==========================================

    const handleDelete = async (user) => {

        const confirmed =
            window.confirm(
                `Are you sure you want to deactivate "${user.name}"?`
            );

        if (!confirmed) {

            return;

        }


        try {

            const response =
                await deleteUserService(
                    user._id || user.id
                );


            if (response.success) {

                toast.success(
                    "User deactivated successfully"
                );

                loadUsers();

            } else {

                toast.error(
                    response.message ||
                    "Failed to deactivate user"
                );

            }

        }
        catch (error) {

            console.error(
                "Deactivate user error:",
                error
            );

            toast.error(
                error.response?.data?.message ||
                error.message ||
                "Failed to deactivate user"
            );

        }

    };


    // ==========================================
    // ROLE LABEL
    // ==========================================

    const getRoleLabel = (role) => {

        if (!role) {

            return "-";

        }

        return role
            .replace(/_/g, " ")
            .replace(/\b\w/g, char =>
                char.toUpperCase()
            );

    };


    // ==========================================
    // STATUS COLOR
    // ==========================================

    const getStatusColor = (status) => {

        if (
            status === "active" ||
            status === "ACTIVE"
        ) {

            return "success";

        }

        return "default";

    };


    // ==========================================
    // LOADING
    // ==========================================

    if (loading) {

        return (

            <Box
                sx={{
                    display: "flex",
                    justifyContent: "center",
                    alignItems: "center",
                    minHeight: "300px"
                }}
            >

                <CircularProgress />

            </Box>

        );

    }


    // ==========================================
    // PAGE
    // ==========================================

    return (

        <Box>

            {/* ==================================
                HEADER
            ================================== */}

            <Box
                sx={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: {
                        xs: "flex-start",
                        sm: "center"
                    },
                    flexDirection: {
                        xs: "column",
                        sm: "row"
                    },
                    gap: 2,
                    mb: 3
                }}
            >

                <Box>

                    <Typography
                        variant="h5"
                        fontWeight={700}
                    >
                        User Management
                    </Typography>

                    <Typography
                        variant="body2"
                        color="text.secondary"
                    >
                        Manage users and access within your organization.
                    </Typography>

                </Box>


                <Button
                    variant="contained"
                    startIcon={<Add />}
                    onClick={() =>
                        navigate("/users/create")
                    }
                >
                    Create User
                </Button>

            </Box>


            {/* ==================================
                ERROR
            ================================== */}

            {error && (

                <Card
                    sx={{
                        mb: 3,
                        border: "1px solid",
                        borderColor: "error.light"
                    }}
                >

                    <CardContent>

                        <Typography
                            color="error"
                        >
                            {error}
                        </Typography>

                    </CardContent>

                </Card>

            )}


            {/* ==================================
                USER TABLE
            ================================== */}

            <Card>

                <TableContainer>

                    <Table>

                        <TableHead>

                            <TableRow>

                                <TableCell>
                                    Name
                                </TableCell>

                                <TableCell>
                                    Email
                                </TableCell>

                                <TableCell>
                                    Role
                                </TableCell>

                                <TableCell>
                                    Status
                                </TableCell>

                                <TableCell align="right">
                                    Actions
                                </TableCell>

                            </TableRow>

                        </TableHead>


                        <TableBody>

                            {users.length === 0 ? (

                                <TableRow>

                                    <TableCell
                                        colSpan={5}
                                        align="center"
                                    >

                                        <Typography
                                            color="text.secondary"
                                            sx={{
                                                py: 4
                                            }}
                                        >
                                            No users found.
                                        </Typography>

                                    </TableCell>

                                </TableRow>

                            ) : (

                                users.map((user) => (

                                    <TableRow
                                        key={
                                            user._id ||
                                            user.id
                                        }
                                        hover
                                    >

                                        <TableCell>

                                            <Typography
                                                fontWeight={600}
                                            >
                                                {user.name}
                                            </Typography>

                                        </TableCell>


                                        <TableCell>
                                            {user.email}
                                        </TableCell>


                                        <TableCell>

                                            {getRoleLabel(
                                                user.role
                                            )}

                                        </TableCell>


                                        <TableCell>

                                            <Chip
                                                label={
                                                    getRoleLabel(
                                                        user.status
                                                    )
                                                }
                                                color={
                                                    getStatusColor(
                                                        user.status
                                                    )
                                                }
                                                size="small"
                                            />

                                        </TableCell>


                                        <TableCell align="right">

                                            <IconButton
                                                color="primary"
                                                onClick={() =>
                                                    navigate(
                                                        `/users/${
                                                            user._id ||
                                                            user.id
                                                        }/edit`
                                                    )
                                                }
                                            >

                                                <Edit />

                                            </IconButton>


                                            {String(user._id || user.id) !== currentUserId && (

                                                <Tooltip title="Reset password">
                                                    <IconButton
                                                        color="warning"
                                                        onClick={() =>
                                                            setResetUser(user)
                                                        }
                                                    >
                                                        <LockReset />
                                                    </IconButton>
                                                </Tooltip>

                                            )}


                                            <IconButton
                                                color="error"
                                                onClick={() =>
                                                    handleDelete(
                                                        user
                                                    )
                                                }
                                            >

                                                <Delete />

                                            </IconButton>

                                        </TableCell>

                                    </TableRow>

                                ))

                            )}

                        </TableBody>

                    </Table>

                </TableContainer>

            </Card>


            <ResetPasswordDialog
                user={resetUser}
                resetFn={resetUserPasswordService}
                onClose={() => setResetUser(null)}
            />

        </Box>

    );

};


export default UserListPage;