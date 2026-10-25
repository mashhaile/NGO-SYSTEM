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
    getProjectLookupService
} from "../../projects/services/projectService";


import { formatDate } from "../../../utils/date";
import LocationCascadeFields
    from "../../locations/components/LocationCascadeFields";



// =====================================================
// OPTIONS
// =====================================================

const toOptions = (items) =>
    items.map(
        item => ({
            value: item,
            label: item
        })
    );


const ACTIVITY_TYPES = toOptions([
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
]);


const PARTICIPANT_SOURCES = toOptions([
    "Enrolled Beneficiaries",
    "Staff",
    "Board Members",
    "Volunteers",
    "Partners",
    "External Participants",
    "Mixed"
]);


const TARGET_GROUPS = [
    "Women",
    "Men",
    "Youth",
    "Children",
    "Persons with Disabilities",
    "Farmers",
    "Entrepreneurs",
    "Students",
    "Teachers",
    "Health Workers",
    "Community Leaders",
    "Staff",
    "Board Members",
    "Partners",
    "Government Officials",
    "General Public"
];


const STATUSES = toOptions(WORK_STATUSES);



// =====================================================
// INITIAL STATE
// =====================================================

const initialState = {

    project: null,

    name: "",

    activityType: "Training",

    participantSource: "Enrolled Beneficiaries",

    targetGroups: [],

    description: "",

    activityDate: "",

    region: "",
    regionCode: "",
    zone: "",
    zoneCode: "",
    woreda: "",
    woredaCode: "",

    location: "",

    facilitator: "",

    targetParticipants: 0,

    status: "Planned",

    remarks: ""

};


// Dates are kept as "YYYY-MM-DD" strings.

const toDateString = (value) =>
    value
        ? String(value).substring(0, 10)
        : "";



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

        project:
            initialData.project || null,

        name:
            initialData.name || "",

        activityType:
            initialData.activityType || "Training",

        participantSource:
            initialData.participantSource ||
            "Enrolled Beneficiaries",

        targetGroups:
            initialData.targetGroups || [],

        description:
            initialData.description || "",

        activityDate:
            toDateString(
                initialData.activityDate
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

        facilitator:
            initialData.facilitator || "",

        targetParticipants:
            initialData.targetParticipants ?? 0,

        status:
            initialData.status || "Planned",

        remarks:
            initialData.remarks || ""

    };

};



// =====================================================
// ACTIVITY FORM
// =====================================================

const ActivityForm = ({
    initialData = {},
    onSubmit,
    loading = false
}) => {

    const [formData, setFormData] =
        useState(
            () => buildFormState(initialData)
        );

    const [projects, setProjects] =
        useState([]);

    const [dateError, setDateError] =
        useState("");


    // =================================================
    // LOAD PROJECTS
    // =================================================

    useEffect(() => {

        getProjectLookupService()

            .then(response =>
                setProjects(
                    response.data.data || []
                )
            )

            .catch(error =>
                console.error(
                    "PROJECT LOOKUP ERROR",
                    error
                )
            );

    }, []);




    // =================================================
    // CHANGE FIELD
    // =================================================

    // the chosen project's start and end (YYYY-MM-DD)
    const projectRange = (project) => {
        const full = projects.find(item => item._id === (project?._id || project));
        if (!full?.startDate || !full?.endDate) return null;
        return { start: String(full.startDate).slice(0, 10), end: String(full.endDate).slice(0, 10) };
    };


    const changeField = (field, value) => {

        if (field === "activityDate") {
            setDateError("");
        }

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


    // =================================================
    // SUBMIT
    // =================================================

    const handleSubmit = (e) => {

        e.preventDefault();

        if (!formData.activityDate) {
            setDateError("Activity date is required");
            return;
        }

        // inside the project's dates (the server checks it too)
        const range = projectRange(formData.project);
        if (range && (formData.activityDate < range.start || formData.activityDate > range.end)) {
            setDateError(`The date must be inside the project's dates (${formatDate(range.start)} to ${formatDate(range.end)}).`);
            return;
        }

        onSubmit({

            project:
                formData.project?._id || null,

            name:
                formData.name,

            activityType:
                formData.activityType,

            participantSource:
                formData.participantSource,

            targetGroups:
                formData.targetGroups,

            description:
                formData.description,

            activityDate:
                formData.activityDate,

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
                formData.location,

            facilitator:
                formData.facilitator,

            targetParticipants:
                Number(formData.targetParticipants),

            status:
                formData.status,

            remarks:
                formData.remarks

        });

    };


    const selectedProject =
        projects.find(
            item =>
                item._id === formData.project?._id
        ) || null;



    // =================================================
    // RENDER
    // =================================================

    return (

        <Box
            component="form"
            onSubmit={handleSubmit}
            sx={{
                width: "100%"
            }}
        >


            {/* =================================================
                ACTIVITY INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Activity Information"
                >

                    <FormGrid>

                        <AppAutoComplete
                            label="Project"
                            required
                            options={projects}
                            value={selectedProject}
                            placeholder="Select Project"
                            getOptionLabel={(option) =>
                                option
                                    ? `${option.projectCode} - ${option.name}`
                                    : ""
                            }
                            isOptionEqualToValue={(a, b) =>
                                a._id === b._id
                            }
                            onChange={(value) =>
                                changeField(
                                    "project",
                                    value
                                )
                            }
                        />


                        <AppTextField
                            label="Activity Name"
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
                            label="Activity Type"
                            required
                            value={formData.activityType}
                            options={ACTIVITY_TYPES}
                            onChange={(e) =>
                                changeField(
                                    "activityType",
                                    e.target.value
                                )
                            }
                        />


                        <AppSelect
                            label="Participant Source"
                            required
                            value={formData.participantSource}
                            options={PARTICIPANT_SOURCES}
                            onChange={(e) =>
                                changeField(
                                    "participantSource",
                                    e.target.value
                                )
                            }
                        />


                        <AppTextField
                            label="Facilitator"
                            value={formData.facilitator}
                            onChange={(e) =>
                                changeField(
                                    "facilitator",
                                    e.target.value
                                )
                            }
                        />


                        <AppTextField
                            label="Target Participants"
                            type="number"
                            inputProps={{
                                min: 0
                            }}
                            value={formData.targetParticipants}
                            onChange={(e) =>
                                changeField(
                                    "targetParticipants",
                                    e.target.value
                                )
                            }
                        />

                    </FormGrid>


                    <Box
                        sx={{
                            mt: 2
                        }}
                    >

                        <AppAutoComplete
                            label="Target Groups"
                            multiple
                            options={TARGET_GROUPS}
                            value={formData.targetGroups}
                            placeholder="Select Target Groups"
                            getOptionLabel={(option) =>
                                option || ""
                            }
                            isOptionEqualToValue={(a, b) =>
                                a === b
                            }
                            onChange={(value) =>
                                changeField(
                                    "targetGroups",
                                    value || []
                                )
                            }
                        />

                    </Box>


                    <Box
                        sx={{
                            mt: 2
                        }}
                    >

                        <AppTextField
                            label="Description"
                            multiline
                            rows={3}
                            value={formData.description}
                            onChange={(e) =>
                                changeField(
                                    "description",
                                    e.target.value
                                )
                            }
                        />

                    </Box>

                </FormSection>

            </PageCard>



            {/* =================================================
                DATE AND LOCATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Date and Location"
                >

                    <FormGrid>

                        <AppDatePicker
                            label="Activity Date"
                            required
                            error={Boolean(dateError)}
                            helperText={
                                dateError ||
                                (projectRange(formData.project)
                                    ? `Inside the project's dates: ${formatDate(projectRange(formData.project).start)} to ${formatDate(projectRange(formData.project).end)}`
                                    : "")
                            }
                            minDate={projectRange(formData.project)?.start}
                            maxDate={projectRange(formData.project)?.end}
                            value={
                                formData.activityDate || null
                            }
                            onChange={(date) =>
                                changeField(
                                    "activityDate",
                                    date
                                        ? date.format("YYYY-MM-DD")
                                        : ""
                                )
                            }
                        />


                        <LocationCascadeFields
                            value={formData}
                            onChange={changeFields}
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

                    </FormGrid>

                </FormSection>

            </PageCard>



            {/* =================================================
                STATUS
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Status"
                >

                    <FormGrid>

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


                    <Box
                        sx={{
                            mt: 2
                        }}
                    >

                        <AppTextField
                            label="Remarks"
                            multiline
                            rows={3}
                            value={formData.remarks}
                            onChange={(e) =>
                                changeField(
                                    "remarks",
                                    e.target.value
                                )
                            }
                        />

                    </Box>

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
                    Save Activity
                </AppButton>

            </FormActions>

        </Box>

    );

};


export default ActivityForm;
