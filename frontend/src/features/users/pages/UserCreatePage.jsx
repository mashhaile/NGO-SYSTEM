import {
    useRoleOptions,
    rolePayload
} from "../../roles/rolesApi";

import {
    PageHeader
} from "../../../components/ui";

import {
    PASSWORD_RULE_TEXT,
    getPasswordProblem
} from "../../../utils/passwordRule";

import {
    useState
} from "react";

import {
    Box,
    Button,
    Card,
    CardContent,
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
    useNavigate
} from "react-router-dom";

import {
    toast
} from "react-toastify";

import {
    createUserService
} from "../services/userService";


// ==========================================
// CREATE USER PAGE
// ==========================================

const UserCreatePage = () => {

    const navigate = useNavigate();


    const roleOptions =
        useRoleOptions();

    const [formData, setFormData] = useState({

        name: "",

        email: "",

        password: "",

        role: "data_entry"

    });


    const [loading, setLoading] = useState(false);


    // ==========================================
    // HANDLE INPUT
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


        if (!formData.email.trim()) {

            toast.error(
                "Email is required"
            );

            return;

        }


        if (!formData.password) {

            toast.error(
                "Password is required"
            );

            return;

        }


        const passwordProblem =
            getPasswordProblem(formData.password);

        if (passwordProblem) {

            toast.error(
                passwordProblem
            );

            return;

        }


        try {

            setLoading(true);


            const response =
                await createUserService(
                    { ...formData, ...rolePayload(formData.role) }
                );


            if (response.success) {

                toast.success(
                    "User created successfully"
                );


                navigate(
                    "/users",
                    {
                        replace: true
                    }
                );


            } else {

                toast.error(
                    response.message ||
                    "Failed to create user"
                );

            }

        }
        catch (error) {

            console.error(
                "Create user error:",
                error
            );


            toast.error(
                error.response?.data?.message ||
                error.message ||
                "Failed to create user"
            );

        }
        finally {

            setLoading(false);

        }

    };


    // ==========================================
    // PAGE
    // ==========================================

    return (
        <Box>

            {/* ==================================
                HEADER
            ================================== */}

            <PageHeader
                title="Create User"
                subtitle="Add a new organization user."
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


                        {/* EMAIL */}

                        <TextField
                            label="Email"
                            name="email"
                            type="email"
                            value={formData.email}
                            onChange={handleChange}
                            fullWidth
                            required
                        />


                        {/* PASSWORD */}

                        <TextField
                            label="Password"
                            name="password"
                            type="password"
                            value={formData.password}
                            onChange={handleChange}
                            fullWidth
                            required
                            helperText={PASSWORD_RULE_TEXT}
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
                                disabled={loading}
                            >
                                Cancel
                            </Button>


                            <Button
                                type="submit"
                                variant="contained"
                                disabled={loading}
                            >
                                {loading
                                    ? "Creating..."
                                    : "Create User"
                                }
                            </Button>

                        </Box>

                    </Box>

                </CardContent>

            </Card>

        </Box>
    );

};


export default UserCreatePage;