import {
    useState
} from "react";


import {
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Typography
} from "@mui/material";


import {
    AppButton,
    AppTextField
} from "../../../components/ui";



// =====================================================
// TOR REVIEW DIALOG
// =====================================================
//
// mode = "approve": comment optional
// mode = "return":  comment required (min 3 chars)
//
// Mounted with a key per open so the comment resets.
//
// =====================================================

const TorReviewDialog = ({
    open,
    mode = "approve",
    loading = false,
    error = "",
    onClose,
    onConfirm
}) => {

    const [comment, setComment] =
        useState("");

    const isReturn =
        mode === "return";

    const commentMissing =
        isReturn &&
        comment.trim().length < 3;


    return (

        <Dialog
            open={open}
            onClose={loading ? undefined : onClose}
            fullWidth
            maxWidth="sm"
        >

            <DialogTitle fontWeight={700}>
                {isReturn
                    ? "Return TOR for Revision"
                    : "Approve TOR"}
            </DialogTitle>

            <DialogContent>

                <Typography
                    variant="body2"
                    color="text.secondary"
                    sx={{ mb: 2 }}
                >
                    {isReturn
                        ? "The author will see your comment and can edit and resubmit the TOR."
                        : "Approved TORs are locked and can no longer be edited."}
                </Typography>

                <AppTextField
                    label={isReturn ? "What needs to change?" : "Comment (optional)"}
                    required={isReturn}
                    multiline
                    rows={4}
                    autoFocus
                    value={comment}
                    error={Boolean(error)}
                    helperText={error}
                    onChange={(e) =>
                        setComment(e.target.value)
                    }
                />

            </DialogContent>

            <DialogActions sx={{ px: 3, pb: 2 }}>

                <AppButton
                    variant="outlined"
                    color="inherit"
                    onClick={onClose}
                    disabled={loading}
                >
                    Cancel
                </AppButton>

                <AppButton
                    variant="contained"
                    color={isReturn ? "warning" : "success"}
                    loading={loading}
                    loadingText={isReturn ? "Returning..." : "Approving..."}
                    disabled={commentMissing}
                    onClick={() =>
                        onConfirm(comment.trim())
                    }
                >
                    {isReturn ? "Return for Revision" : "Approve"}
                </AppButton>

            </DialogActions>

        </Dialog>

    );

};


export default TorReviewDialog;
