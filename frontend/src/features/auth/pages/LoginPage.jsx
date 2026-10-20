import {
    useState
} from "react";


import {
    useDispatch,
    useSelector
} from "react-redux";


import {
    useNavigate,
    useSearchParams
} from "react-router-dom";


import {
    Alert,
    Box,
    Button,
    IconButton,
    InputAdornment,
    Paper,
    TextField,
    Typography
} from "@mui/material";


import {
    Visibility,
    VisibilityOff
} from "@mui/icons-material";


import {
    loginThunk,
    selectAuth
} from "../store";



// Why the user was sent back to this page
// (set by the API client when a session ends).

const REASONS = {
    "password-changed":
        "Your password was changed. Please sign in again.",
    "session-ended":
        "Your session has ended. Please sign in again."
};



// =====================================================
// LOGIN PAGE
// =====================================================

const LoginPage = () => {

    const dispatch =
        useDispatch();

    const navigate =
        useNavigate();

    const [searchParams] =
        useSearchParams();

    const {
        loading,
        error
    } = useSelector(selectAuth);

    const [form, setForm] =
        useState({
            email: "",
            password: ""
        });

    const [showPassword, setShowPassword] =
        useState(false);

    const reasonMessage =
        REASONS[searchParams.get("reason")];


    const handleChange = (e) => {

        setForm(prev => ({
            ...prev,
            [e.target.name]: e.target.value
        }));

    };


    const handleSubmit = (e) => {

        e.preventDefault();

        dispatch(
            loginThunk(form)
        )
            .then((result) => {

                if (result.meta.requestStatus !== "fulfilled") {
                    return;
                }

                // Temporary password from an admin reset

                navigate(
                    result.payload?.user?.mustChangePassword
                        ? "/account/password"
                        : "/"
                );

            });

    };


    return (
        <Box
            sx={{
                minHeight: "100vh",
                display: "flex",
                justifyContent: "center",
                alignItems: "center",
                bgcolor: "background.default",
                px: 2
            }}
        >

            <Paper
                elevation={0}
                sx={{
                    p: {
                        xs: 3,
                        sm: 4
                    },
                    width: "100%",
                    maxWidth: 420,
                    borderRadius: 3,
                    border: "1px solid",
                    borderColor: "divider"
                }}
            >

                <Typography
                    variant="h5"
                    sx={{
                        fontWeight: 700
                    }}
                >
                    NGO Management System
                </Typography>

                <Typography
                    sx={{
                        color: "text.secondary",
                        mt: 0.5,
                        mb: 3
                    }}>
                    Sign in to continue
                </Typography>


                {reasonMessage && !error && (

                    <Alert
                        severity="info"
                        sx={{ mb: 2 }}
                    >
                        {reasonMessage}
                    </Alert>

                )}


                {error && (

                    <Alert
                        severity="error"
                        sx={{ mb: 2 }}
                    >
                        {error}
                    </Alert>

                )}


                <form onSubmit={handleSubmit}>

                    <TextField
                        fullWidth
                        label="Email"
                        name="email"
                        type="email"
                        autoComplete="username"
                        margin="normal"
                        value={form.email}
                        onChange={handleChange}
                        required
                    />

                    <TextField
                        fullWidth
                        label="Password"
                        name="password"
                        type={showPassword ? "text" : "password"}
                        autoComplete="current-password"
                        margin="normal"
                        value={form.password}
                        onChange={handleChange}
                        required
                        slotProps={{
                            input: {
                                endAdornment: (
                                    <InputAdornment position="end">
                                        <IconButton
                                            aria-label={showPassword ? "Hide password" : "Show password"}
                                            onClick={() =>
                                                setShowPassword(value => !value)
                                            }
                                            edge="end"
                                        >
                                            {showPassword
                                                ? <VisibilityOff />
                                                : <Visibility />}
                                        </IconButton>
                                    </InputAdornment>
                                )
                            }
                        }}
                    />

                    <Button
                        fullWidth
                        variant="contained"
                        type="submit"
                        size="large"
                        disabled={loading}
                        sx={{ mt: 2 }}
                    >
                        {loading ? "Signing in..." : "Sign in"}
                    </Button>

                </form>

                <Typography
                    variant="body2"
                    sx={{
                        color: "text.secondary",
                        mt: 3
                    }}>
                    Forgot your password? Ask your organization administrator to reset it.
                </Typography>

            </Paper>

        </Box>
    );

};


export default LoginPage;
