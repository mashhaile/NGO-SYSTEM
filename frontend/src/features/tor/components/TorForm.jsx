import {
    useCallback,
    useEffect,
    useState
} from "react";


import {
    Alert,
    Box
} from "@mui/material";


import {
    Save,
    Send
} from "@mui/icons-material";


import {
    PageCard,
    FormSection,
    FormGrid,
    FormActions,
    AppTextField,
    AppDatePicker,
    AppAutoComplete,
    AppButton
} from "../../../components/ui";


import {
    getActivityLookupService
} from "../../activities/services/lookupService";


import {
    getActivityRunsApi
} from "../../activityRuns/api/activityRunApi";


import LocationCascadeFields
    from "../../locations/components/LocationCascadeFields";


import TorBudgetLines
    from "./TorBudgetLines";



// =====================================================
// FORM STATE
// =====================================================

const initialState = {

    title: "",

    activity: "",

    activityRun: "",

    background: "",

    objectives: "",

    expectedOutputs: "",

    methodology: "",

    participants: "",

    expectedParticipants: "",

    facilitators: "",

    startDate: "",

    endDate: "",

    region: "",
    regionCode: "",
    zone: "",
    zoneCode: "",
    woreda: "",
    woredaCode: "",

    venue: "",

    currency: "ETB",

    budgetLines: [],

    logistics: "",

    reportingRequirements: ""

};


const getId = (value) =>
    value && typeof value === "object"
        ? value._id
        : value || "";


const toDateString = (value) =>
    value
        ? String(value).substring(0, 10)
        : "";


// The edit page mounts the form once the TOR has
// loaded (keyed by id), so this runs once per record.

const buildFormState = (initialData) => {

    if (
        !initialData ||
        !Object.keys(initialData).length
    ) {
        return initialState;
    }

    const state = {
        ...initialState
    };

    Object.keys(initialState).forEach(key => {

        if (
            initialData[key] !== undefined &&
            initialData[key] !== null
        ) {
            state[key] = initialData[key];
        }

    });

    return {
        ...state,
        activity: getId(initialData.activity),
        activityRun: getId(initialData.activityRun),
        startDate: toDateString(initialData.startDate),
        endDate: toDateString(initialData.endDate),
        expectedParticipants:
            initialData.expectedParticipants || "",
        budgetLines:
            (initialData.budgetLines || []).map(line => ({
                _id: line._id,
                description: line.description || "",
                unit: line.unit || "",
                quantity: line.quantity ?? 1,
                unitCost: line.unitCost ?? 0
            }))
    };

};


const textArea = (rows = 4) => ({
    multiline: true,
    rows
});



// =====================================================
// TOR FORM
// =====================================================

const TorForm = ({
    initialData = {},
    onSubmit,
    saving = false,
    error = "",
    allowSubmit = true
}) => {

    const [form, setForm] =
        useState(
            () => buildFormState(initialData)
        );

    const [errors, setErrors] =
        useState({});

    const [activities, setActivities] =
        useState([]);

    const [runsResult, setRunsResult] =
        useState({
            activity: null,
            runs: []
        });


    // =================================================
    // LOOKUPS
    // =================================================

    useEffect(() => {

        getActivityLookupService()

            .then(response =>
                setActivities(
                    response.data?.data || []
                )
            )

            .catch(loadError =>
                console.error(
                    "Activity lookup error",
                    loadError
                )
            );

    }, []);


    useEffect(() => {

        if (!form.activity) {
            return undefined;
        }

        let cancelled = false;

        getActivityRunsApi({
            activity: form.activity,
            limit: 100
        })

            .then(response => {

                if (!cancelled) {
                    setRunsResult({
                        activity: form.activity,
                        runs: response.data?.data || []
                    });
                }

            })

            .catch(loadError =>
                console.error(
                    "Activity run lookup error",
                    loadError
                )
            );

        return () => {
            cancelled = true;
        };

    }, [form.activity]);


    const runs =
        runsResult.activity === form.activity
            ? runsResult.runs
            : [];


    // =================================================
    // CHANGE
    // =================================================

    const changeField = (field, value) => {

        setErrors(prev => ({
            ...prev,
            [field]: ""
        }));

        setForm(prev => ({
            ...prev,
            [field]: value
        }));

    };


    const changeFields = useCallback(
        (patch) => {

            setForm(prev => ({
                ...prev,
                ...patch
            }));

        },
        []
    );


    const textProps = (field) => ({
        value: form[field] ?? "",
        error: Boolean(errors[field]),
        helperText: errors[field] || "",
        onChange: (e) =>
            changeField(field, e.target.value)
    });


    const dateChange = (field) => (date) =>
        changeField(
            field,
            date
                ? date.format("YYYY-MM-DD")
                : ""
        );


    // =================================================
    // SUBMIT
    // =================================================

    const validate = () => {

        const next = {};

        if (!form.title.trim()) {
            next.title = "Title is required";
        }

        if (!form.activity) {
            next.activity = "Activity is required";
        }

        if (
            form.startDate &&
            form.endDate &&
            form.endDate < form.startDate
        ) {
            next.endDate = "End date cannot be before start date";
        }

        if (
            form.budgetLines.some(
                line => !String(line.description || "").trim()
            )
        ) {
            next.budgetLines = "Every budget line needs a description.";
        }

        setErrors(next);

        return Object.keys(next).length === 0;

    };


    const buildPayload = () => ({

        ...form,

        title: form.title.trim(),

        activityRun: form.activityRun || null,

        startDate: form.startDate || null,

        endDate: form.endDate || null,

        expectedParticipants:
            form.expectedParticipants === ""
                ? 0
                : Number(form.expectedParticipants),

        currency:
            String(form.currency || "ETB").trim().toUpperCase(),

        budgetLines:
            form.budgetLines.map(line => ({
                ...(line._id ? { _id: line._id } : {}),
                description: String(line.description).trim(),
                unit: line.unit || "",
                quantity: Number(line.quantity) || 0,
                unitCost: Number(line.unitCost) || 0
            }))

    });


    const handleSave = (submit) => (e) => {

        e?.preventDefault?.();

        if (!validate()) {
            return;
        }

        onSubmit(
            buildPayload(),
            {
                submit
            }
        );

    };


    const selectedActivity =
        activities.find(
            item => item._id === form.activity
        ) || null;

    const selectedRun =
        runs.find(
            item => item._id === form.activityRun
        ) || null;



    // =================================================
    // RENDER
    // =================================================

    return (

        <Box
            component="form"
            onSubmit={handleSave(false)}
            sx={{
                width: "100%"
            }}
        >

            {error && (

                <Alert
                    severity="error"
                    sx={{ mb: 3 }}
                >
                    {error}
                </Alert>

            )}


            {/* =================================================
                TOR INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="TOR Information"
                    subtitle="Which activity this terms of reference is for."
                >

                    <Box sx={{ mb: 2 }}>

                        <AppTextField
                            label="Title"
                            required
                            placeholder="e.g. Community Health Workers Refresher Training"
                            {...textProps("title")}
                        />

                    </Box>

                    <FormGrid columns={2}>

                        <AppAutoComplete
                            label="Activity"
                            required
                            options={activities}
                            value={selectedActivity}
                            placeholder="Select Activity"
                            error={Boolean(errors.activity)}
                            helperText={errors.activity || ""}
                            getOptionLabel={(option) =>
                                option
                                    ? `${option.activityCode} - ${option.name}`
                                    : ""
                            }
                            isOptionEqualToValue={(a, b) =>
                                a._id === b._id
                            }
                            onChange={(value) => {
                                changeField("activity", value?._id || "");
                                changeField("activityRun", "");
                            }}
                        />

                        <AppAutoComplete
                            label="Activity Run (optional)"
                            options={runs}
                            value={selectedRun}
                            disabled={!form.activity}
                            placeholder={
                                form.activity
                                    ? "Select Activity Run"
                                    : "Select an activity first"
                            }
                            getOptionLabel={(option) =>
                                option
                                    ? `${option.runCode} - ${option.name}`
                                    : ""
                            }
                            isOptionEqualToValue={(a, b) =>
                                a._id === b._id
                            }
                            onChange={(value) =>
                                changeField("activityRun", value?._id || "")
                            }
                        />

                    </FormGrid>

                </FormSection>

            </PageCard>



            {/* =================================================
                PURPOSE
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Purpose"
                    subtitle="Background, Objectives and Expected Outputs are required before submitting."
                >

                    <Box sx={{ display: "grid", gap: 2 }}>

                        <AppTextField
                            label="Background"
                            placeholder="Why is this activity needed?"
                            {...textArea(4)}
                            {...textProps("background")}
                        />

                        <AppTextField
                            label="Objectives"
                            placeholder="What will the activity achieve?"
                            {...textArea(4)}
                            {...textProps("objectives")}
                        />

                        <AppTextField
                            label="Expected Outputs"
                            placeholder="Concrete results, e.g. 40 health workers trained"
                            {...textArea(3)}
                            {...textProps("expectedOutputs")}
                        />

                        <AppTextField
                            label="Methodology"
                            placeholder="How it will be delivered (sessions, approach, materials)"
                            {...textArea(3)}
                            {...textProps("methodology")}
                        />

                    </Box>

                </FormSection>

            </PageCard>



            {/* =================================================
                PARTICIPANTS
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Participants and Facilitators"
                >

                    <FormGrid columns={2}>

                        <AppTextField
                            label="Participants"
                            placeholder="Who will attend and how they are selected"
                            {...textArea(3)}
                            {...textProps("participants")}
                        />

                        <AppTextField
                            label="Facilitators / Resource Persons"
                            placeholder="Who will facilitate"
                            {...textArea(3)}
                            {...textProps("facilitators")}
                        />

                        <AppTextField
                            label="Expected Number of Participants"
                            type="number"
                            inputProps={{
                                min: 0
                            }}
                            {...textProps("expectedParticipants")}
                        />

                    </FormGrid>

                </FormSection>

            </PageCard>



            {/* =================================================
                DATE AND VENUE
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Date and Venue"
                >

                    <FormGrid>

                        <AppDatePicker
                            label="Start Date"
                            value={form.startDate || null}
                            maxDate={form.endDate || undefined}
                            onChange={dateChange("startDate")}
                        />

                        <AppDatePicker
                            label="End Date"
                            value={form.endDate || null}
                            minDate={form.startDate || undefined}
                            error={Boolean(errors.endDate)}
                            helperText={errors.endDate || ""}
                            onChange={dateChange("endDate")}
                        />

                        <AppTextField
                            label="Venue"
                            placeholder="e.g. Woreda health office hall"
                            {...textProps("venue")}
                        />

                        <LocationCascadeFields
                            value={form}
                            onChange={changeFields}
                        />

                    </FormGrid>

                </FormSection>

            </PageCard>



            {/* =================================================
                BUDGET
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Budget"
                >

                    <Box sx={{ maxWidth: 200, mb: 2 }}>

                        <AppTextField
                            label="Currency"
                            {...textProps("currency")}
                        />

                    </Box>

                    {errors.budgetLines && (

                        <Alert
                            severity="error"
                            sx={{ mb: 2 }}
                        >
                            {errors.budgetLines}
                        </Alert>

                    )}

                    <TorBudgetLines
                        lines={form.budgetLines}
                        currency={form.currency}
                        onChange={(lines) =>
                            changeField("budgetLines", lines)
                        }
                    />

                </FormSection>

            </PageCard>



            {/* =================================================
                LOGISTICS AND REPORTING
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Logistics and Reporting"
                >

                    <FormGrid columns={2}>

                        <AppTextField
                            label="Logistics"
                            placeholder="Transport, accommodation, materials"
                            {...textArea(3)}
                            {...textProps("logistics")}
                        />

                        <AppTextField
                            label="Reporting Requirements"
                            placeholder="Reports due after the activity and their deadline"
                            {...textArea(3)}
                            {...textProps("reportingRequirements")}
                        />

                    </FormGrid>

                </FormSection>

            </PageCard>



            {/* =================================================
                ACTIONS
            ================================================= */}

            <FormActions>

                <AppButton
                    type="submit"
                    variant="outlined"
                    size="large"
                    startIcon={<Save />}
                    loading={saving}
                    loadingText="Saving..."
                >
                    Save Draft
                </AppButton>

                {allowSubmit && (

                    <AppButton
                        variant="contained"
                        size="large"
                        startIcon={<Send />}
                        disabled={saving}
                        onClick={handleSave(true)}
                    >
                        Save and Submit for Approval
                    </AppButton>

                )}

            </FormActions>

        </Box>

    );

};


export default TorForm;
