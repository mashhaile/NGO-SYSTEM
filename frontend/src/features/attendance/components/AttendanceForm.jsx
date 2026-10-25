import {
    useEffect,
    useState
} from "react";

import {
    Box,
    Grid,
    TextField,
    Button,
    Stack,
    Autocomplete,
    Typography
} from "@mui/material";

import {
    Save
} from "@mui/icons-material";

import {
    getActivityRunLookupService
} from "../../activityRuns/services/lookupService";

import AppDatePicker from "../../../components/ui/AppDatePicker";

import { dayOf, rangeHint } from "../../../utils/date";

const initialState = {

    activityRun: null,

    sessionTitle: "",

    sessionNumber: "",

    sessionDate: "",

    notes: ""

};

const AttendanceForm = ({

    initialData = {},

    onSubmit,

    loading = false

}) => {

    const [formData, setFormData] = useState(initialState);

    const [activityRuns, setActivityRuns] = useState([]);

    useEffect(() => {

        loadActivityRuns();

    }, []);

    useEffect(() => {

        if (initialData && Object.keys(initialData).length) {

            setFormData({

                activityRun: initialData.activityRun || null,

                sessionTitle: initialData.sessionTitle || "",

                sessionNumber: initialData.sessionNumber || "",

                sessionDate: initialData.sessionDate
                    ? initialData.sessionDate.substring(0, 10)
                    : "",

                notes: initialData.notes || ""

            });

        }

    }, [initialData]);

    const loadActivityRuns = async () => {

        try {

            const data = await getActivityRunLookupService();

            setActivityRuns(data || []);

        }

        catch (error) {

            console.error(
                "Load Activity Runs Error:",
                error
            );

        }

    };

    const change = (field, value) => {

        setFormData(prev => ({

            ...prev,

            [field]: value

        }));

    };

    const submit = (e) => {

        e.preventDefault();

        onSubmit({

            activityRun: formData.activityRun?._id,

            sessionTitle: formData.sessionTitle,

            sessionNumber:
                formData.sessionNumber === ""
                    ? null
                    : Number(formData.sessionNumber),

            sessionDate: formData.sessionDate,

            notes: formData.notes

        });

    };

    // the chosen run, with its dates (from the run list)
    const runForDates =
        activityRuns.find(run => run._id === (formData.activityRun?._id || formData.activityRun)) ||
        (typeof formData.activityRun === "object" ? formData.activityRun : null);

    return (
        <Box
            component="form"
            onSubmit={submit}
        >

            <Grid
                container
                spacing={3}
            >

                <Grid size={{xs:12,md:6}}>
                

                    <Autocomplete

                        options={activityRuns}

                        value={formData.activityRun}

                        isOptionEqualToValue={(a, b) =>
                            a?._id === b?._id
                        }

                        getOptionLabel={(option) =>

                            option

                                ? `${option.runCode} • ${option.name}`

                                : ""

                        }

                        onChange={(e, value) =>

                            change(
                                "activityRun",
                                value
                            )

                        }

                        renderOption={(props, option) => (

                            <li {...props}>

                                <Box>

                                    <Typography
                                        sx={{
                                            fontWeight: 700
                                        }}
                                    >

                                        {option.runCode}

                                    </Typography>

                                    <Typography
                                        variant="body2"
                                    >

                                        {option.name}

                                    </Typography>

                                    <Typography
                                        variant="caption"
                                        sx={{
                                            color: "text.secondary"
                                        }}
                                    >

                                        {option.activity?.activityCode}
                                        {" • "}
                                        {option.activity?.name}

                                    </Typography>

                                </Box>

                            </li>

                        )}

                        renderInput={(params) => (

                            <TextField

                                {...params}

                                label="Activity Run"

                                required

                            />

                        )}

                    />

                </Grid>

                <Grid
                    size={{ xs: 12, md: 6 }}
                >

                    <TextField

                        fullWidth

                        required

                        label="Session Title"

                        value={formData.sessionTitle}

                        onChange={(e) =>

                            change(
                                "sessionTitle",
                                e.target.value
                            )

                        }

                    />

                </Grid>

                <Grid
                    size={{ xs: 12, md: 6 }}
                >

                    <TextField

                        fullWidth

                        type="number"

                        label="Session Number"

                        value={formData.sessionNumber}

                        onChange={(e) =>

                            change(
                                "sessionNumber",
                                e.target.value
                            )

                        }

                    />

                </Grid>

                <Grid
                    size={{ xs: 12, md: 6 }}
                >

                    {/* DD/MM/YYYY, like every date in the system */}
                    <AppDatePicker

                        required

                        label="Session Date"

                        // a session is dated inside its activity run
                        helperText={rangeHint("activity run", runForDates?.startDate, runForDates?.endDate)}

                        minDate={dayOf(runForDates?.startDate)}

                        maxDate={dayOf(runForDates?.endDate)}

                        value={formData.sessionDate || null}

                        onChange={(newValue) =>

                            change(
                                "sessionDate",
                                newValue ? newValue.format("YYYY-MM-DD") : ""
                            )

                        }

                    />

                </Grid>

                <Grid
                    size={{ xs: 12 }}
                >

                    <TextField

                        fullWidth

                        multiline

                        rows={4}

                        label="Notes"

                        value={formData.notes}

                        onChange={(e) =>

                            change(
                                "notes",
                                e.target.value
                            )

                        }

                    />

                </Grid>

            </Grid>

            <Stack sx={{ mt: 4, justifyContent: "flex-end" }}

                direction="row"

            >

                <Button

                    type="submit"

                    variant="contained"

                    startIcon={<Save />}

                    disabled={loading}

                >

                    {loading
                        ? "Saving..."
                        : "Save Attendance Session"}

                </Button>

            </Stack>

        </Box>
    );

};

export default AttendanceForm;