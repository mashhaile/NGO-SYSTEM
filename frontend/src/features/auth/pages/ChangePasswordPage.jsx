import {
    useState
} from "react";


import {
    useDispatch
} from "react-redux";


import {
    useNavigate
} from "react-router-dom";


import {
    Alert,
    Box,
    Button,
    IconButton,
    InputAdornment,
    Stack,
    TextField,
    Typography
} from "@mui/material";


import {
    Visibility,
    VisibilityOff
} from "@mui/icons-material";


import {
    PageCard,
    PageContainer,
    PageHeader
} from "../../../components/ui";


import useAuth
    from "../hooks/useAuth";

import {
    loadCurrentUserThunk
} from "../store";

import {
    changePasswordService
} from "../services/authService";



import {
    PASSWORD_RULE_TEXT as RULE_TEXT,
    getPasswordProblem as checkStrength
} from "../../../utils/passwordRule";



// =====================================================
// CHANGE PASSWORD PAGE
// =====================================================
//
// Every user can change their own password here. After
// an admin reset, the user is sent here and cannot use
// the rest of the system until the password is changed.
//
// =====================================================

const ChangePasswordPage = () => {

    const dispatch =
        useDispatch();

    const navigate =
        useNavigate();

    const {
        user
    } = useAuth();

    const forced =
        Boolean(user?.mustChangePassword);

    // the platform super admin (whom nobody resets) may
    // change theirs at any time; others only when asked
    const managed =
        !forced && user?.role !== "super_admin";

    const [form, setForm] =
        useState({
            currentPassword: "",
            newPassword: "",
            confirmPassword: ""
        });

    const [showPasswords, setShowPasswords] =
        useState(false);

    const [saving, setSaving] =
        useState(false);

    const [error, setError] =
        useState("");

    const [done, setDone] =
        useState(false);


    const handleChange = (e) => {

        setForm(prev => ({
            ...prev,
            [e.target.name]: e.target.value
        }));

    };


    const handleSubmit = async (e) => {

        e.preventDefault();

        setError("");

        const problem =
            checkStrength(form.newPassword);

        if (problem) {
            setError(problem);
            return;
        }

        if (form.newPassword !== form.confirmPassword) {
            setError("The new passwords do not match.");
            return;
        }

        if (form.newPassword === form.currentPassword) {
            setError("The new password must be different from the current one.");
            return;
        }

        setSaving(true);

        try {

            await changePasswordService({
                currentPassword: form.currentPassword,
                newPassword: form.newPassword
            });

            // Reload the user with the new token
            // (clears mustChangePassword)

            await dispatch(
                loadCurrentUserThunk()
            );

            setForm({
                currentPassword: "",
                newPassword: "",
                confirmPassword: ""
            });

            if (forced) {
                navigate("/dashboard", { replace: true });
                return;
            }

            setDone(true);

        }
        catch (err) {

            setError(
                err.response?.data?.message ||
                "Could not change the password."
            );

        }
        finally {

            setSaving(false);

        }

    };


    const passwordField = (name, label, autoComplete) => (

        <TextField
            fullWidth
            required
            name={name}
            label={label}
            type={showPasswords ? "text" : "password"}
            autoComplete={autoComplete}
            value={form[name]}
            onChange={handleChange}
            slotProps={{
                input: {
                    endAdornment: (
                        <InputAdornment position="end">
                            <IconButton
                                aria-label={showPasswords ? "Hide passwords" : "Show passwords"}
                                onClick={() =>
                                    setShowPasswords(value => !value)
                                }
                                edge="end"
                            >
                                {showPasswords
                                    ? <VisibilityOff />
                                    : <Visibility />}
                            </IconButton>
                        </InputAdornment>
                    )
                }
            }}
        />

    );


    return (
        <PageContainer>

            <PageHeader
                title="Change Password"
                subtitle={user?.email}
            />

            <Box sx={{ maxWidth: 520 }}>

                <PageCard>

                    {forced && (

                        <Alert
                            severity="warning"
                            sx={{ mb: 2 }}
                        >
                            You signed in with a password you were given.
                            Choose your own password to continue: only you
                            will know it. If you forget it later, your
                            organization administrator can reset it.
                        </Alert>

                    )}

                    {/* after the first sign-in the administrator manages passwords */}
                    {managed && !done && (

                        <Alert
                            severity="info"
                            sx={{ mb: 2 }}
                        >
                            Your password is managed by your organization
                            administrator. If you forget it, ask them to
                            reset it.
                        </Alert>

                    )}

                    {done && (

                        <Alert
                            severity="success"
                            sx={{ mb: 2 }}
                        >
                            Your password was changed. Other devices
                            signed in with this account are signed out.
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

                    {!managed && (
                    <form onSubmit={handleSubmit}>

                        <Stack spacing={2}>

                            {passwordField(
                                "currentPassword",
                                forced ? "Password you were given" : "Current password",
                                "current-password"
                            )}

                            {passwordField(
                                "newPassword",
                                "New password",
                                "new-password"
                            )}

                            {passwordField(
                                "confirmPassword",
                                "Confirm new password",
                                "new-password"
                            )}

                            <Typography
                                variant="body2"
                                sx={{
                                    color: "text.secondary"
                                }}
                            >
                                {RULE_TEXT}
                            </Typography>

                            <Box>
                                <Button
                                    type="submit"
                                    variant="contained"
                                    disabled={saving}
                                >
                                    {saving ? "Saving..." : "Change Password"}
                                </Button>
                            </Box>

                        </Stack>

                    </form>
                    )}

                </PageCard>

            </Box>

        </PageContainer>
    );

};


export default ChangePasswordPage;
