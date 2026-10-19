import {
    useEffect,
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
    AppAutoComplete,
    AppButton
} from "../../../components/ui";


import {
    getActivityLookupService
} from "../../activities/services/lookupService";



const getId = (value) =>
    value && typeof value === "object"
        ? value._id
        : value || "";



// =====================================================
// LINK EXISTING ACTIVITY
// =====================================================
//
// For when the activity was created by hand instead of
// from the TOR. Only activities of the TOR's project
// are offered (the backend enforces the same rule).
//
// Mounted with a key per open so the choice resets.
//
// =====================================================

const TorLinkActivityDialog = ({
    open,
    projectId,
    loading = false,
    error = "",
    onClose,
    onConfirm
}) => {

    const [activities, setActivities] =
        useState([]);

    const [selected, setSelected] =
        useState(null);


    useEffect(() => {

        if (!open) {
            return undefined;
        }

        let cancelled = false;

        getActivityLookupService()

            .then(response => {

                if (!cancelled) {
                    setActivities(
                        (response.data?.data || [])
                            .filter(item =>
                                getId(item.project) === projectId
                            )
                    );
                }

            })

            .catch(loadError =>
                console.error(
                    "Activity lookup error",
                    loadError
                )
            );

        return () => {
            cancelled = true;
        };

    }, [open, projectId]);


    return (

        <Dialog
            open={open}
            onClose={loading ? undefined : onClose}
            fullWidth
            maxWidth="sm"
        >

            <DialogTitle fontWeight={700}>
                Link Existing Activity
            </DialogTitle>

            <DialogContent>

                <Typography
                    variant="body2"
                    color="text.secondary"
                    sx={{ mb: 2 }}
                >
                    Use this when the activity was already created. Only activities of this TOR's project are listed.
                </Typography>

                <AppAutoComplete
                    label="Activity"
                    required
                    options={activities}
                    value={selected}
                    placeholder="Select Activity"
                    error={Boolean(error)}
                    helperText={error}
                    getOptionLabel={(option) =>
                        option
                            ? `${option.activityCode} - ${option.name}`
                            : ""
                    }
                    isOptionEqualToValue={(a, b) =>
                        a._id === b._id
                    }
                    onChange={(value) =>
                        setSelected(value)
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
                    loading={loading}
                    loadingText="Linking..."
                    disabled={!selected}
                    onClick={() =>
                        onConfirm(selected._id)
                    }
                >
                    Link Activity
                </AppButton>

            </DialogActions>

        </Dialog>

    );

};


export default TorLinkActivityDialog;
