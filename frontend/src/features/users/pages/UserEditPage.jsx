import {
    useRoleOptions,
    rolePayload,
    roleValueOf
} from "../../roles/rolesApi";

import {
    PageHeader
} from "../../../components/ui";

import {
    useEffect,
    useState
} from "react";

import {
    Box,
    Button,
    Card,
    CardContent,
    CircularProgress,
    FormControl,
    InputLabel,
    MenuItem,
    Select,
    TextField,
} from "@mui/material";

import {
    ArrowBack
} from "@mui/icons-material";

import {
    useNavigate,
    useParams
} from "react-router-dom";

import {
    toast
} from "react-toastify";

import {
    getUsersService,
    updateUserService
} from "../services/userService";


// ==========================================
// EDIT USER PAGE
// ==========================================

const UserEditPage = () => {

    const navigate = useNavigate();

    const { id } = useParams();


    const [loading, setLoading] = useState(true);

    const [saving, setSaving] = useState(false);


    const roleOptions =
        useRoleOptions();

    const [formData, setFormData] = useState({

        name: "",

        role: "data_entry",

        status: "active"

    });


    // ==========================================
    // LOAD USER
    // ==========================================

    const loadUser = async () => {

        try {

            setLoading(true);


            const response =
                await getUsersService();


            if (!response.success) {

                throw new Error(
                    response.message ||
                    "Failed to load users"
                );

            }


            const users =
                response.data || [];


            const user =
                users.find(
                    item =>
                        String(
                            item._id || item.id
                        ) === String(id)
                );


            if (!user) {

                toast.error(
                    "User not found"
                );


                navigate(
                    "/users",
                    {
                        replace: true
                    }
                );

                return;

            }


            setFormData({

                name:
                    user.name || "",

                role:
                    roleValueOf(user) || "data_entry",

                status:
                    user.status || "active"

            });

        }
        catch (error) {

            console.error(
                "Load user error:",
                error
            );


            toast.error(
                error.response?.data?.message ||
                error.message ||
                "Failed to load user"
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

        loadUser();

    }, [id]);


    // ==========================================
    // HANDLE CHANGE
    // ==========================================

    const handleChange = (event) => {

        const {
            name,
            value
        } = event.target;


        setFormData(
            previous => ({

                ...previous,

                [name]: value

            })
        );

    };


    // ==========================================
    // SUBMIT
    // ==========================================

    const handleSubmit = async (event) => {

        event.preventDefault();


        if (!formData.name.trim()) {

            toast.error(
                "Name is required"
            );

            return;

        }


        try {

            setSaving(true);


            const response =
                await updateUserService(
                    id,
                    { ...formData, ...rolePayload(formData.role) }
                );


            if (response.success) {

                toast.success(
                    "User updated successfully"
                );


                navigate(
                    "/users",
                    {
                        replace: true
                    }
                );

            }
            else {

                toast.error(
                    response.message ||
                    "Failed to update user"
                );

            }

        }
        catch (error) {

            console.error(
                "Update user error:",
                error
            );


            toast.error(
                error.response?.data?.message ||
                error.message ||
                "Failed to update user"
            );

        }
        finally {

            setSaving(false);

        }

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

            <PageHeader
                title="Edit User"
                subtitle="Update user information and access."
                action={() =>
                        navigate("/users")}
                actionLabel="Back"
                actionIcon={<ArrowBack />}
            />

            {/* ==================================
                FORM
            ================================== */}

            <Card
                sx={{
                    maxWidth: 700
                }}
            >

                <CardContent>

                    <Box
                        component="form"
                        onSubmit={handleSubmit}
                        sx={{
                            display: "flex",
                            flexDirection: "column",
                            gap: 3
                        }}
                    >

                        {/* NAME */}

                        <TextField
                            label="Full Name"
                            name="name"
                            value={formData.name}
                            onChange={handleChange}
                            fullWidth
                            required
                        />


                        {/* ROLE */}

                        <FormControl
                            fullWidth
                            required
                        >

                            <InputLabel>
                                Role
                            </InputLabel>


                            <Select
                                name="role"
                                value={formData.role}
                                label="Role"
                                onChange={handleChange}
                            >
                                {roleOptions.map(option => (
                                    <MenuItem key={option.value} value={option.value}>
                                        {option.label}
                                    </MenuItem>
                                ))}
                            </Select>

                        </FormControl>


                        {/* STATUS */}

                        <FormControl
                            fullWidth
                            required
                        >

                            <InputLabel>
                                Status
                            </InputLabel>


                            <Select
                                name="status"
                                value={formData.status}
                                label="Status"
                                onChange={handleChange}
                            >

                                <MenuItem value="active">
                                    Active
                                </MenuItem>


                                <MenuItem value="inactive">
                                    Inactive
                                </MenuItem>


                                <MenuItem value="suspended">
                                    Suspended
                                </MenuItem>

                            </Select>

                        </FormControl>


                        {/* ACTIONS */}

                        <Box
                            sx={{
                                display: "flex",
                                justifyContent: "flex-end",
                                gap: 2,
                                mt: 1
                            }}
                        >

                            <Button
                                variant="outlined"
                                onClick={() =>
                                    navigate("/users")
                                }
                                disabled={saving}
                            >
                                Cancel
                            </Button>


                            <Button
                                type="submit"
                                variant="contained"
                                disabled={saving}
                            >
                                {saving
                                    ? "Saving..."
                                    : "Save Changes"
                                }
                            </Button>

                        </Box>

                    </Box>

                </CardContent>

            </Card>

        </Box>
    );

};


export default UserEditPage;