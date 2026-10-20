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
    Typography
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
                    formData
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

            <Box
                sx={{
                    display: "flex",
                    alignItems: "center",
                    gap: 2,
                    mb: 3
                }}
            >

                <Button
                    startIcon={<ArrowBack />}
                    onClick={() =>
                        navigate("/users")
                    }
                >
                    Back
                </Button>


                <Box>

                    <Typography
                        variant="h5"
                        sx={{
                            fontWeight: 700
                        }}
                    >
                        Create User
                    </Typography>


                    <Typography
                        variant="body2"
                        sx={{
                            color: "text.secondary"
                        }}
                    >
                        Add a new organization user.
                    </Typography>

                </Box>

            </Box>

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

                                <MenuItem value="data_entry">
                                    Data Entry
                                </MenuItem>


                                <MenuItem value="viewer">
                                    Viewer
                                </MenuItem>


                                <MenuItem value="organization_admin">
                                    Organization Admin
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