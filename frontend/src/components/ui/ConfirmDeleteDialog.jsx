import { useTerm } from "../../utils/terms";
import {
    WarningAmber
} from "@mui/icons-material";

import {
    Dialog,
    DialogTitle,
    DialogContent,
    DialogContentText,
    DialogActions,
    Button,
    Box
} from "@mui/material";


const ConfirmDeleteDialog = ({
    open,

    title = "Delete Record",

    message =
        "Are you sure you want to delete this record?",

    loading = false,

    onClose,
    onConfirm
}) => {

    // in the organization's own words (Settings > Wording)
    const term = useTerm();
    title = term(title);
    message = term(message);


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
                    display: "flex",
                    alignItems: "center",
                    gap: 1.5,
                    fontWeight: 700
                }}
            >

                <Box
                    sx={{
                        width: 40,
                        height: 40,
                        borderRadius: 2,

                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",

                        bgcolor: "error.lighter",
                        color: "error.main"
                    }}
                >
                    <WarningAmber fontSize="small" />
                </Box>

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
                    variant="outlined"
                    onClick={onClose}
                    disabled={loading}
                >
                    Cancel
                </Button>


                <Button
                    color="error"
                    variant="contained"
                    onClick={onConfirm}
                    disabled={loading}
                >
                    {loading
                        ? "Deleting..."
                        : "Delete"}
                </Button>

            </DialogActions>

        </Dialog>
    );
};


export default ConfirmDeleteDialog;