import {
    useState
} from "react";

import {
    Alert,
    Box,
    Button,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    IconButton,
    Tooltip,
    Typography
} from "@mui/material";

import {
    ContentCopy
} from "@mui/icons-material";

import {
    toast
} from "react-toastify";


// =====================================================
// RESET PASSWORD DIALOG
// =====================================================
//
// Step 1: confirm. Step 2: show the temporary password
// ONCE (it is not stored and cannot be shown again).
// The user must choose a new password at next sign in.
//
// resetFn(userId) must return the API body
// { data: { temporaryPassword } }.
//
// =====================================================

const ResetPasswordDialog = ({
    user,
    resetFn,
    onClose
}) => {

    const [saving, setSaving] =
        useState(false);

    const [error, setError] =
        useState("");

    const [temporaryPassword, setTemporaryPassword] =
        useState("");


    const handleClose = () => {

        if (saving) {
            return;
        }

        setError("");
        setTemporaryPassword("");
        onClose();

    };


    const handleReset = async () => {

        setSaving(true);
        setError("");

        try {

            const response =
                await resetFn(user._id || user.id);

            setTemporaryPassword(
                response.data?.temporaryPassword || ""
            );

        }
        catch (err) {

            setError(
                err.response?.data?.message ||
                "Could not reset the password."
            );

        }
        finally {

            setSaving(false);

        }

    };


    const handleCopy = async () => {

        try {
            await navigator.clipboard.writeText(temporaryPassword);
            toast.success("Temporary password copied");
        }
        catch {
            toast.error("Copy failed. Select the password and copy it.");
        }

    };


    return (

        <Dialog
            open={Boolean(user)}
            onClose={handleClose}
            maxWidth="xs"
            fullWidth
        >

            <DialogTitle>
                Reset Password
            </DialogTitle>

            <DialogContent>

                {error && (
                    <Alert severity="error" sx={{ mb: 2 }}>
                        {error}
                    </Alert>
                )}

                {!temporaryPassword ? (

                    <Typography>
                        Reset the password for{" "}
                        <strong>{user?.name}</strong> ({user?.email})?
                        They will be signed out and must choose a new
                        password when they next sign in.
                    </Typography>

                ) : (

                    <>
                        <Typography sx={{ mb: 1.5 }}>
                            Give this temporary password to{" "}
                            <strong>{user?.name}</strong>:
                        </Typography>

                        <Box
                            sx={{
                                display: "flex",
                                alignItems: "center",
                                gap: 1,
                                p: 1.5,
                                borderRadius: 2,
                                border: "1px solid",
                                borderColor: "divider",
                                bgcolor: "action.hover"
                            }}
                        >

                            <Typography
                                sx={{
                                    flex: 1,
                                    fontFamily: "monospace",
                                    fontSize: 18,
                                    letterSpacing: 1,
                                    userSelect: "all",
                                    wordBreak: "break-all"
                                }}
                            >
                                {temporaryPassword}
                            </Typography>

                            <Tooltip title="Copy">
                                <IconButton onClick={handleCopy}>
                                    <ContentCopy fontSize="small" />
                                </IconButton>
                            </Tooltip>

                        </Box>

                        <Alert severity="warning" sx={{ mt: 2 }}>
                            This password is shown only once.
                            Copy it before closing.
                        </Alert>
                    </>

                )}

            </DialogContent>

            <DialogActions>

                {!temporaryPassword ? (

                    <>
                        <Button
                            onClick={handleClose}
                            disabled={saving}
                        >
                            Cancel
                        </Button>

                        <Button
                            variant="contained"
                            color="warning"
                            onClick={handleReset}
                            disabled={saving}
                        >
                            {saving ? "Resetting..." : "Reset Password"}
                        </Button>
                    </>

                ) : (

                    <Button
                        variant="contained"
                        onClick={handleClose}
                    >
                        Done
                    </Button>

                )}

            </DialogActions>

        </Dialog>

    );

};


export default ResetPasswordDialog;
