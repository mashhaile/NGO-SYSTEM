import { WORK_STATUSES } from "../../../constants/workStatus";
import {
    useCallback,
    useEffect,
    useState
} from "react";


import {
    Box
} from "@mui/material";


import {
    Save
} from "@mui/icons-material";


import {
    PageCard,
    FormSection,
    FormGrid,
    FormActions,
    AppTextField,
    AppSelect,
    AppDatePicker,
    AppAutoComplete,
    AppButton
} from "../../../components/ui";


import {
    getActivityLookupService
} from "../../activities/services/lookupService";


import LocationCascadeFields
    from "../../locations/components/LocationCascadeFields";

import { dayOf, rangeHint } from "../../../utils/date";



// =====================================================
// OPTIONS
// =====================================================

const STATUSES = WORK_STATUSES.map(
    item => ({
        value: item,
        label: item
    })
);



// =====================================================
// INITIAL STATE
// =====================================================

const initialState = {

    activity: null,

    name: "",

    startDate: "",

    endDate: "",

    region: "",
    regionCode: "",
    zone: "",
    zoneCode: "",
    woreda: "",
    woredaCode: "",

    location: "",

    status: "Planned",

    notes: ""

};


// Dates are kept as "YYYY-MM-DD" strings.

const toDateString = (value) =>
    value
        ? new Date(value)
            .toISOString()
            .substring(0, 10)
        : "";


const getId = (value) =>
    value && typeof value === "object"
        ? value._id
        : value || null;



// =====================================================
// FORM STATE FROM EXISTING RECORD (edit mode)
// =====================================================
//
// The edit page mounts the form once the record has
// loaded (keyed by id), so this runs once per record.
//
// =====================================================

const buildFormState = (initialData) => {

    if (
        !initialData ||
        !Object.keys(initialData).length
    ) {
        return initialState;
    }

    return {

        activity:
            initialData.activity || null,

        name:
            initialData.name || "",

        startDate:
            toDateString(
                initialData.startDate
            ),

        endDate:
            toDateString(
                initialData.endDate
            ),

        region:
            initialData.region || "",

        regionCode:
            initialData.regionCode || "",

        zone:
            initialData.zone || "",

        zoneCode:
            initialData.zoneCode || "",

        woreda:
            initialData.woreda || "",

        woredaCode:
            initialData.woredaCode || "",

        location:
            initialData.location || "",

        status:
            initialData.status || "Planned",

        notes:
            initialData.notes || ""

    };

};



// =====================================================
// ACTIVITY RUN FORM
// =====================================================

const ActivityRunForm = ({
    initialData = {},
    onSubmit,
    loading = false
}) => {

    const [formData, setFormData] =
        useState(
            () => buildFormState(initialData)
        );

    const [activities, setActivities] =
        useState([]);

    const [errors, setErrors] =
        useState({});


    // =================================================
    // LOAD ACTIVITIES
    // =================================================

    useEffect(() => {

        getActivityLookupService()

            .then(response =>
                setActivities(
                    response.data.data || []
                )
            )

            .catch(error =>
                console.error(
                    "Activity lookup error",
                    error
                )
            );

    }, []);




    // =================================================
    // CHANGE FIELD
    // =================================================

    const changeField = (field, value) => {

        setErrors(prev => ({
            ...prev,
            [field]: ""
        }));

        setFormData(prev => ({
            ...prev,
            [field]: value
        }));

    };


    // Location cascade: several fields at once.

    const changeFields = useCallback(
        (patch) => {

            setFormData(prev => ({
                ...prev,
                ...patch
            }));

        },
        []
    );


    const changeDate = (field) => (date) =>
        changeField(
            field,
            date
                ? date.format("YYYY-MM-DD")
                : ""
        );


    // =================================================
    // SUBMIT
    // =================================================

    const submit = (e) => {

        e.preventDefault();

        const nextErrors = {};

        if (!formData.startDate) {
            nextErrors.startDate =
                "Start date is required";
        }

        if (
            formData.startDate &&
            formData.endDate &&
            formData.endDate < formData.startDate
        ) {
            nextErrors.endDate =
                "End date cannot be before start date";
        }

        if (Object.keys(nextErrors).length) {
            setErrors(nextErrors);
            return;
        }

        onSubmit({

            activity:
                getId(formData.activity),

            name:
                formData.name.trim(),

            startDate:
                formData.startDate,

            endDate:
                formData.endDate || null,

            region:
                formData.region,

            regionCode:
                formData.regionCode,

            zone:
                formData.zone,

            zoneCode:
                formData.zoneCode,

            woreda:
                formData.woreda,

            woredaCode:
                formData.woredaCode,

            location:
                formData.location || null,

            status:
                formData.status,

            notes:
                formData.notes || null

        });

    };


    const selectedActivity =
        activities.find(
            item =>
                item._id === getId(formData.activity)
        ) || null;

    // a run is dated inside its project: the range under the dates
    const projectStart = selectedActivity?.projectStartDate;
    const projectEnd = selectedActivity?.projectEndDate;
    const datesHint = rangeHint("project", projectStart, projectEnd);



    // =================================================
    // RENDER
    // =================================================

    return (

        <Box
            component="form"
            onSubmit={submit}
            sx={{
                width: "100%"
            }}
        >


            {/* =================================================
                RUN INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Run Information"
                >

                    <FormGrid>

                        <AppAutoComplete
                            label="Activity"
                            required
                            options={activities}
                            value={selectedActivity}
                            placeholder="Select Activity"
                            getOptionLabel={(option) =>
                                option
                                    ? `${option.activityCode} - ${option.name}`
                                    : ""
                            }
                            isOptionEqualToValue={(a, b) =>
                                a._id === b._id
                            }
                            onChange={(value) =>
                                changeField(
                                    "activity",
                                    value
                                )
                            }
                        />


                        <AppTextField
                            label="Run Name"
                            required
                            value={formData.name}
                            onChange={(e) =>
                                changeField(
                                    "name",
                                    e.target.value
                                )
                            }
                        />


                        <AppSelect
                            label="Status"
                            required
                            value={formData.status}
                            options={STATUSES}
                            onChange={(e) =>
                                changeField(
                                    "status",
                                    e.target.value
                                )
                            }
                        />

                    </FormGrid>

                </FormSection>

            </PageCard>



            {/* =================================================
                SCHEDULE AND LOCATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Schedule and Location"
                >

                    <FormGrid>

                        <AppDatePicker
                            label="Start Date"
                            required
                            value={
                                formData.startDate || null
                            }
                            minDate={dayOf(projectStart)}
                            maxDate={
                                formData.endDate || dayOf(projectEnd)
                            }
                            error={Boolean(errors.startDate)}
                            helperText={errors.startDate || datesHint}
                            onChange={changeDate("startDate")}
                        />


                        <AppDatePicker
                            label="End Date"
                            value={
                                formData.endDate || null
                            }
                            minDate={
                                formData.startDate || dayOf(projectStart)
                            }
                            maxDate={dayOf(projectEnd)}
                            error={Boolean(errors.endDate)}
                            helperText={errors.endDate || datesHint}
                            onChange={changeDate("endDate")}
                        />


                        <AppTextField
                            label="Venue / Site"
                            placeholder="e.g. Kebele 05 community hall"
                            value={formData.location}
                            onChange={(e) =>
                                changeField(
                                    "location",
                                    e.target.value
                                )
                            }
                        />


                        <LocationCascadeFields
                            value={formData}
                            onChange={changeFields}
                        />

                    </FormGrid>

                </FormSection>

            </PageCard>



            {/* =================================================
                NOTES
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Notes"
                >

                    <AppTextField
                        label="Notes"
                        multiline
                        rows={3}
                        value={formData.notes}
                        onChange={(e) =>
                            changeField(
                                "notes",
                                e.target.value
                            )
                        }
                    />

                </FormSection>

            </PageCard>



            {/* =================================================
                ACTIONS
            ================================================= */}

            <FormActions>

                <AppButton
                    type="submit"
                    variant="contained"
                    size="large"
                    startIcon={<Save />}
                    loading={loading}
                    loadingText="Saving..."
                >
                    Save Activity Run
                </AppButton>

            </FormActions>

        </Box>

    );

};


export default ActivityRunForm;
