import {
    useState
} from "react";


import {
    Box,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Typography
} from "@mui/material";


import {
    AppButton,
    AppSelect,
    AppTextField
} from "../../../components/ui";



const ACTIVITY_TYPES = [
    "Training",
    "Workshop",
    "Seminar",
    "Meeting",
    "Conference",
    "Awareness Campaign",
    "Field Visit",
    "Monitoring Visit",
    "Assessment",
    "Distribution",
    "Community Dialogue",
    "Other"
].map(
    item => ({
        value: item,
        label: item
    })
);



// =====================================================
// EDIT LINKED ACTIVITY (name + type only)
// =====================================================
//
// Mounted with a key per open so the fields reset to
// the activity's current values.
//
// =====================================================

const TorEditActivityDialog = ({
    open,
    activity,
    loading = false,
    error = "",
    onClose,
    onConfirm
}) => {

    const [name, setName] =
        useState(activity?.name || "");

    const [activityType, setActivityType] =
        useState(activity?.activityType || "Training");

    const nameTooShort =
        name.trim().length < 3;


    return (

        <Dialog
            open={open}
            onClose={loading ? undefined : onClose}
            fullWidth
            maxWidth="sm"
        >

            <DialogTitle fontWeight={700}>
                Edit Activity Name and Type
            </DialogTitle>

            <DialogContent>

                <Typography
                    variant="body2"
                    color="text.secondary"
                    sx={{ mb: 2 }}
                >
                    Changes the activity {activity?.activityCode}. The approved TOR stays as it was approved; the change is recorded in its history.
                </Typography>

                <Box sx={{ display: "grid", gap: 2 }}>

                    <AppTextField
                        label="Activity Name"
                        required
                        autoFocus
                        value={name}
                        error={nameTooShort || Boolean(error)}
                        helperText={
                            nameTooShort
                                ? "At least 3 characters"
                                : error
                        }
                        onChange={(e) =>
                            setName(e.target.value)
                        }
                    />

                    <AppSelect
                        label="Activity Type"
                        required
                        value={activityType}
                        options={ACTIVITY_TYPES}
                        onChange={(e) =>
                            setActivityType(e.target.value)
                        }
                    />

                </Box>

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
                    loading={loading}
                    loadingText="Saving..."
                    disabled={nameTooShort}
                    onClick={() =>
                        onConfirm({
                            name: name.trim(),
                            activityType
                        })
                    }
                >
                    Save
                </AppButton>

            </DialogActions>

        </Dialog>

    );

};


export default TorEditActivityDialog;
