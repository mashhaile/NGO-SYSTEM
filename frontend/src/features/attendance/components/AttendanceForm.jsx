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
                                        fontWeight={700}
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
                                        color="text.secondary"
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
                    item
                    xs={12}
                    md={6}
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
                    item
                    xs={12}
                    md={6}
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
                    item
                    xs={12}
                    md={6}
                >

                    <TextField

                        fullWidth

                        required

                        type="date"

                        label="Session Date"

                        InputLabelProps={{
                            shrink: true
                        }}

                        value={formData.sessionDate}

                        onChange={(e) =>

                            change(
                                "sessionDate",
                                e.target.value
                            )

                        }

                    />

                </Grid>

                <Grid
                    item
                    xs={12}
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

            <Stack

                mt={4}

                direction="row"

                justifyContent="flex-end"

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