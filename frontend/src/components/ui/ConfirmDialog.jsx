import {
    Dialog,
    DialogTitle,
    DialogContent,
    DialogContentText,
    DialogActions,
    Button
} from "@mui/material";


const ConfirmDialog = ({
    open,

    title = "Confirm Action",

    message =
        "Are you sure you want to continue?",

    confirmLabel = "Confirm",
    cancelLabel = "Cancel",

    confirmColor = "primary",

    loading = false,

    onClose,
    onConfirm
}) => {

    return (
        <Dialog
            open={open}
            onClose={
                loading
                    ? undefined
                    : onClose
            }
            maxWidth="xs"
            fullWidth
        >

            <DialogTitle
                sx={{
                    fontWeight: 700
                }}
            >
                {title}
            </DialogTitle>


            <DialogContent>

                <DialogContentText
                    sx={{
                        lineHeight: 1.6
                    }}
                >
                    {message}
                </DialogContentText>

            </DialogContent>


            <DialogActions
                sx={{
                    px: 3,
                    pb: 2.5,
                    gap: 1
                }}
            >

                <Button
                    onClick={onClose}
                    disabled={loading}
                    variant="outlined"
                >
                    {cancelLabel}
                </Button>


                <Button
                    color={confirmColor}
                    variant="contained"
                    onClick={onConfirm}
                    disabled={loading}
                >
                    {loading
                        ? "Processing..."
                        : confirmLabel}
                </Button>

            </DialogActions>

        </Dialog>
    );
};


export default ConfirmDialog;