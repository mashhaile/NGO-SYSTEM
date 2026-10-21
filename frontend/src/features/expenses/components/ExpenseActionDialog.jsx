import {
    useState
} from "react";

import {
    Alert,
    Checkbox,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    FormControlLabel,
    Typography
} from "@mui/material";

import {
    AppButton,
    AppTextField
} from "../../../components/ui";


// =====================================================
// EXPENSE ACTION DIALOG (approve / return / void)
// =====================================================
//
// overBudget: the approver must tick "approve over budget"
// and give a reason (same rule as the API).
//
// Mounted with a key per open so the fields reset.
//
// =====================================================

const ExpenseActionDialog = ({
    open,
    title,
    message,
    commentLabel = "Comment",
    requireComment = false,
    confirmLabel = "Confirm",
    confirmColor = "primary",
    overBudget = null,
    loading = false,
    error = "",
    onClose,
    onConfirm
}) => {

    const [comment, setComment] = useState("");
    const [allowOverBudget, setAllowOverBudget] = useState(false);

    const needsComment = requireComment || (overBudget && allowOverBudget);
    const commentMissing = needsComment && comment.trim().length < 3;
    const blocked = (overBudget && !allowOverBudget) || commentMissing;

    return (
        <Dialog open={open} onClose={loading ? undefined : onClose} fullWidth maxWidth="sm">

            <DialogTitle sx={{ fontWeight: 700 }}>{title}</DialogTitle>

            <DialogContent>

                {message && (
                    <Typography variant="body2" sx={{ color: "text.secondary", mb: 2 }}>
                        {message}
                    </Typography>
                )}

                {overBudget && (
                    <Alert severity="warning" sx={{ mb: 2 }}>
                        {overBudget}
                        <FormControlLabel
                            sx={{ display: "flex", mt: 1 }}
                            control={
                                <Checkbox
                                    checked={allowOverBudget}
                                    onChange={(e) => setAllowOverBudget(e.target.checked)}
                                />
                            }
                            label="Approve over budget"
                        />
                    </Alert>
                )}

                <AppTextField
                    label={needsComment ? `${commentLabel} (required)` : `${commentLabel} (optional)`}
                    multiline
                    rows={3}
                    value={comment}
                    onChange={(e) => setComment(e.target.value)}
                    error={Boolean(error)}
                    helperText={error || (overBudget && allowOverBudget ? "Why is approving over budget acceptable?" : "")}
                />

            </DialogContent>

            <DialogActions sx={{ px: 3, pb: 2 }}>
                <AppButton variant="outlined" onClick={onClose} disabled={loading}>Cancel</AppButton>
                <AppButton
                    variant="contained"
                    color={confirmColor}
                    loading={loading}
                    disabled={blocked}
                    onClick={() => onConfirm({ comment: comment.trim(), allowOverBudget })}
                >
                    {confirmLabel}
                </AppButton>
            </DialogActions>

        </Dialog>
    );

};


export default ExpenseActionDialog;
