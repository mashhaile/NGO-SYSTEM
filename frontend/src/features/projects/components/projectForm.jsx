import { WORK_STATUS_OPTIONS, WORK_STATUS_HELP } from "../../../constants/workStatus";
import { formatDate } from "../../../utils/date";
import {
    useEffect,
    useState
} from "react";

import {
    useSearchParams
} from "react-router-dom";

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
    AppButton
} from "../../../components/ui";

import {
    getProgramsService
} from "../../programs/services/programService";

import {
    getDonorsLookupService
} from "../../donors/services/DonorService";

import {
    getStaffLookupService
} from "../../users/services/userService";

import {
    getProjectsService
} from "../services/projectService";


const initialState = {
    program: "",
    // a phase of this main project (Phase 1, Phase 2 ...)
    parentProject: "",
    name: "",
    description: "",
    donor: "",
    projectManager: "",
    startDate: "",
    endDate: "",
    status: "Planned"
};


// =====================================================
// ENTITY ID HELPER
// =====================================================

const getEntityId = (value) => {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return "";
    }

    if (
        typeof value === "object" &&
        value !== null
    ) {

        return String(
            value._id ??
            value.id ??
            ""
        );

    }

    return String(value);
};


// =====================================================
// PROJECT FORM
// =====================================================

const ProjectForm = ({
    initialData = null,
    onSubmit,
    loading = false
}) => {

    const [
        form,
        setForm
    ] = useState(initialState);


    const [
        programs,
        setPrograms
    ] = useState([]);

    // projects that may have phases (not phases themselves)
    const [
        mainProjects,
        setMainProjects
    ] = useState([]);

    // "Add phase" opens this form with ?parent=<main project>
    const [searchParams] =
        useSearchParams();

    const parentFromUrl =
        searchParams.get("parent") || "";

    useEffect(() => {

        let cancelled = false;

        getProjectsService({ limit: 1000 })
            .then(response => {
                const data = response?.data?.data ?? response?.data ?? [];
                const list = Array.isArray(data) ? data : data?.items || [];
                if (!cancelled) setMainProjects(list.filter(project => !project.parentProject));
            })
            .catch(() => {
                if (!cancelled) setMainProjects([]);
            });

        return () => {
            cancelled = true;
        };

    }, []);


    const [
        donors,
        setDonors
    ] = useState([]);


    const [
        staff,
        setStaff
    ] = useState([]);


    const [
        formError,
        setFormError
    ] = useState("");


    // a check failed: its message shows above the form
    useEffect(() => {
        if (formError) window.scrollTo({ top: 0, behavior: "smooth" });
    }, [formError]);


    // =====================================================
    // LOAD PROGRAMS
    // =====================================================

    useEffect(() => {

        const loadPrograms = async () => {

            try {

                const response =
                    await getProgramsService({
                        limit: 1000
                    });

                const data =
                    response?.data?.data ??
                    response?.data ??
                    [];

                setPrograms(
                    Array.isArray(data)
                        ? data
                        : []
                );

            }
            catch (error) {

                console.error(
                    "LOAD PROGRAMS ERROR:",
                    error
                );

                setPrograms([]);

            }

        };


        loadPrograms();

    }, []);


    // =====================================================
    // LOAD DONORS
    // =====================================================

    useEffect(() => {

        const loadDonors = async () => {

            try {

                const response =
                    await getDonorsLookupService();

                const data =
                    response?.data ??
                    response ??
                    [];

                setDonors(
                    Array.isArray(data)
                        ? data
                        : []
                );

            }
            catch (error) {

                console.error(
                    "LOAD DONORS ERROR:",
                    error
                );

                setDonors([]);

            }

        };


        loadDonors();

    }, []);


    // =====================================================
    // LOAD STAFF / USERS
    // =====================================================

    useEffect(() => {

        const loadStaff = async () => {

            try {

                const response =
                    await getStaffLookupService();

                const data =
                    response?.data ??
                    response ??
                    [];

                setStaff(
                    Array.isArray(data)
                        ? data
                        : []
                );

            }
            catch (error) {

                console.error(
                    "LOAD STAFF ERROR:",
                    error
                );

                setStaff([]);

            }

        };


        loadStaff();

    }, []);


    // =====================================================
    // INITIAL DATA
    // =====================================================

    useEffect(() => {

        if (!initialData) {
            setForm({
                ...initialState,
                parentProject: parentFromUrl
            });
            return;
        }


        const projectManagerId =
            getEntityId(
                initialData.projectManager
            );


        const donorId =
            getEntityId(
                initialData.donor
            );


        const programId =
            getEntityId(
                initialData.program
            );




        setForm({
            program:
                programId,
            parentProject:
                getEntityId(
                    initialData.parentProject
                ),

            name:
                initialData.name ??
                "",

            description:
                initialData.description ??
                "",

            donor:
                donorId,

            projectManager:
                projectManagerId,

            startDate:
                initialData.startDate
                    ? String(
                        initialData.startDate
                    ).substring(0, 10)
                    : "",

            endDate:
                initialData.endDate
                    ? String(
                        initialData.endDate
                    ).substring(0, 10)
                    : "",

            status:
                initialData.status ??
                "Planned"

        });

    }, [
        initialData,
        parentFromUrl
    ]);


    // =====================================================
    // KEEP CURRENT PROJECT MANAGER IN OPTIONS
    // =====================================================

    useEffect(() => {

        if (
            !initialData?.projectManager
        ) {
            return;
        }


        const currentManager =
            initialData.projectManager;


        const currentManagerId =
            getEntityId(
                currentManager
            );


        if (!currentManagerId) {
            return;
        }


        setStaff((previousStaff) => {

            const alreadyExists =
                previousStaff.some(
                    (user) =>
                        getEntityId(
                            user
                        ) === currentManagerId
                );


            if (alreadyExists) {
                return previousStaff;
            }


            if (
                typeof currentManager !==
                "object"
            ) {
                return previousStaff;
            }


            return [
                currentManager,
                ...previousStaff
            ];

        });

    }, [
        initialData
    ]);


    // =====================================================
    // CHANGE FIELD
    // =====================================================

    const changeField = (
        key,
        value
    ) => {

        setFormError("");

        setForm((prev) => ({
            ...prev,
            [key]: value
        }));

    };


    // =====================================================
    // SUBMIT
    // =====================================================

    const submitHandler = async (
        event
    ) => {

        event.preventDefault();

        setFormError("");


        // -------------------------------------------------
        // BASIC VALIDATION
        // -------------------------------------------------

        if (!form.program && !form.parentProject) {

            setFormError(
                "Please select a program."
            );

            return;

        }


        if (!form.name?.trim()) {

            setFormError(
                "Project name is required."
            );

            return;

        }


        if (form.name.trim().length < 3) {

            setFormError(
                "The project name needs at least 3 letters."
            );

            return;

        }


        const isDate = (value) =>
            Boolean(value) && !Number.isNaN(new Date(value).getTime());

        if (!form.startDate || !form.endDate) {

            setFormError(
                "Start date and end date are required."
            );

            return;

        }


        if (!isDate(form.startDate) || !isDate(form.endDate)) {

            setFormError(
                "A date is not complete. Enter it as day/month/year (for example 01/06/2027), or pick it from the calendar."
            );

            return;

        }


        if (new Date(form.endDate) < new Date(form.startDate)) {

            setFormError(
                "The end date cannot be before the start date."
            );

            return;

        }


        // a phase: inside its main project's dates
        if (
            selectedMainProject &&
            (String(form.startDate).slice(0, 10) < String(selectedMainProject.startDate || "").slice(0, 10) ||
                String(form.endDate).slice(0, 10) > String(selectedMainProject.endDate || "").slice(0, 10))
        ) {

            setFormError(
                `A phase must lie inside its main project's dates (${formatDate(selectedMainProject.startDate)} to ${formatDate(selectedMainProject.endDate)}).`
            );

            return;

        }


        // -------------------------------------------------
        // BUILD PAYLOAD
        // -------------------------------------------------

        const payload = {
            program:
                getEntityId(
                    form.program || selectedMainProject?.program
                ),
            // a phase of a main project (empty: a project on its own)
            parentProject:
                form.parentProject || null,

            name:
                form.name.trim(),

            description:
                form.description?.trim() ||
                "",

            status:
                form.status ||
                "Planned"

        };


        // -------------------------------------------------
        // OPTIONAL DONOR
        // -------------------------------------------------

        const donorId =
            getEntityId(
                form.donor
            );


        if (donorId) {

            payload.donor =
                donorId;

        }


        // -------------------------------------------------
        // OPTIONAL PROJECT MANAGER
        // -------------------------------------------------

        const projectManagerId =
            getEntityId(
                form.projectManager
            );


        if (projectManagerId) {

            payload.projectManager =
                projectManagerId;

        }


        // -------------------------------------------------
        // START DATE
        // -------------------------------------------------

        if (form.startDate) {

            payload.startDate =
                form.startDate;

        }


        // -------------------------------------------------
        // END DATE
        // -------------------------------------------------

        if (form.endDate) {

            payload.endDate =
                form.endDate;

        }


        // -------------------------------------------------
        // DATE VALIDATION
        // -------------------------------------------------

        if (
            payload.startDate &&
            payload.endDate &&
            payload.endDate <
                payload.startDate
        ) {

            setFormError(
                "End date cannot be before start date."
            );

            return;

        }


        // -------------------------------------------------
        // DEBUG
        // -------------------------------------------------



        // -------------------------------------------------
        // SUBMIT
        // -------------------------------------------------

        try {

            await onSubmit(
                payload
            );

        }
        catch (error) {

            console.error(
                "PROJECT FORM SUBMIT ERROR:",
                error
            );

        }

    };


    // =====================================================
    // MAIN PROJECT OPTIONS (phases)
    // =====================================================

    const selfId =
        getEntityId(initialData?._id);

    const hasPhases =
        Array.isArray(initialData?.phases) && initialData.phases.length > 0;

    const selectedMainProject =
        mainProjects.find(project => getEntityId(project) === form.parentProject) || null;

    const mainProjectOptions = [
        { value: "", label: "Not a phase (a project on its own)" },
        ...mainProjects
            .filter(project => getEntityId(project) !== selfId)
            .filter(project => !form.program || selectedMainProject || getEntityId(project.program) === form.program)
            .map(project => ({
                value: getEntityId(project),
                label: project.projectCode ? `${project.projectCode} - ${project.name}` : project.name
            }))
    ];

    // =====================================================
    // PROGRAM OPTIONS
    // =====================================================

    const programOptions =
        programs
            .map((program) => ({

                value:
                    getEntityId(
                        program
                    ),

                label:
                    program.programCode
                        ? `${program.programCode} - ${program.name}`
                        : program.name

            }))
            .filter(
                (item) =>
                    item.value
            );


    // =====================================================
    // DONOR OPTIONS
    // =====================================================

    const donorOptions =
        donors
            .map((donor) => ({

                value:
                    getEntityId(
                        donor
                    ),

                label:
                    donor.organizationName
                        ? `${donor.name} - ${donor.organizationName}`
                        : donor.name

            }))
            .filter(
                (item) =>
                    item.value
            );


    // =====================================================
    // STAFF OPTIONS
    // =====================================================

    const staffOptions =
        staff
            .map((user) => ({

                value:
                    getEntityId(
                        user
                    ),

                label:
                    user.name
                        ? (
                            user.email
                                ? `${user.name} - ${user.email}`
                                : user.name
                        )
                        : user.email ||
                          "Unknown User"

            }))
            .filter(
                (item) =>
                    item.value
            );


    // =====================================================
    // RENDER
    // =====================================================

    return (

        <Box
            component="form"
            onSubmit={
                submitHandler
            }
            sx={{
                width: "100%"
            }}
        >

            {/* =================================================
                FORM ERROR
            ================================================= */}

            {formError && (

                <Box
                    sx={{
                        mb: 2,
                        p: 2,
                        borderRadius: 1,
                        bgcolor: "error.lighter",
                        color: "error.main"
                    }}
                >

                    {formError}

                </Box>

            )}


            {/* =================================================
                PROJECT INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Project Information"
                >

                    <FormGrid>

                        <AppSelect
                            label="Program"
                            required
                            value={
                                form.program || getEntityId(selectedMainProject?.program)
                            }
                            placeholder="Select Program"
                            options={
                                programOptions
                            }
                            onChange={(e) =>
                                changeField(
                                    "program",
                                    e.target.value
                                )
                            }
                            disabled={
                                Boolean(selectedMainProject)
                            }
                            helperText={
                                selectedMainProject
                                    ? "A phase is in its main project's program"
                                    : undefined
                            }
                        />


                        <AppSelect
                            label="Phase of (main project)"
                            value={
                                form.parentProject
                            }
                            options={
                                mainProjectOptions
                            }
                            onChange={(e) => {
                                const value = e.target.value;
                                const main = mainProjects.find(project => getEntityId(project) === value);
                                changeField("parentProject", value);
                                if (main) changeField("program", getEntityId(main.program));
                            }}
                            disabled={
                                hasPhases
                            }
                            helperText={
                                hasPhases
                                    ? "This project has phases of its own"
                                    : selectedMainProject
                                        ? `Dates must lie inside ${formatDate(selectedMainProject.startDate)} to ${formatDate(selectedMainProject.endDate)} and not overlap another phase`
                                        : "Leave empty for a project on its own. A phase has its own budget, activities and reports."
                            }
                        />


                        <AppTextField
                            label="Project Name"
                            required
                            value={
                                form.name
                            }
                            onChange={(e) =>
                                changeField(
                                    "name",
                                    e.target.value
                                )
                            }
                        />


                        <AppSelect
                            label="Donor"
                            value={
                                form.donor
                            }
                            placeholder="Select Donor"
                            options={
                                donorOptions
                            }
                            onChange={(e) =>
                                changeField(
                                    "donor",
                                    e.target.value
                                )
                            }
                        />


                        <AppSelect
                            label="Project Manager"
                            value={
                                form.projectManager
                            }
                            placeholder="Select Project Manager"
                            options={
                                staffOptions
                            }
                            onChange={(e) =>
                                changeField(
                                    "projectManager",
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
                            fullWidth
                            multiline
                            rows={4}
                            label="Description"
                            value={
                                form.description
                            }
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
                BUDGET (Budgets module only)
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Budget"
                    subtitle="The project's budget is not entered here. Create it in Budgets (budget lines per year, with approval); it then shows on the project page."
                />

            </PageCard>


            {/* =================================================
                PROJECT DATES
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Project Dates"
                >

                    <FormGrid>

                        <AppDatePicker
                            label="Start Date"
                            required
                            name="startDate"
                            value={
                                form.startDate
                            }
                            onChange={(newValue) => {

                                changeField(
                                    "startDate",
                                    newValue
                                        ? newValue.format(
                                            "YYYY-MM-DD"
                                        )
                                        : ""
                                );

                            }}
                        />


                        <AppDatePicker
                            label="End Date"
                            required
                            name="endDate"
                            value={
                                form.endDate
                            }
                            onChange={(newValue) => {

                                changeField(
                                    "endDate",
                                    newValue
                                        ? newValue.format(
                                            "YYYY-MM-DD"
                                        )
                                        : ""
                                );

                            }}
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

                    <FormGrid
                        columns={1}
                    >

                        <AppSelect
                            label="Status"
                            value={
                                form.status
                            }
                            placeholder="Select Status"
                            options={WORK_STATUS_OPTIONS}
                            helperText={WORK_STATUS_HELP}
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
                ACTIONS
            ================================================= */}

            <FormActions>

                <AppButton
                    type="submit"
                    variant="contained"
                    size="large"
                    startIcon={
                        <Save />
                    }
                    loading={
                        loading
                    }
                    disabled={
                        loading
                    }
                >
                    Save Project
                </AppButton>

            </FormActions>

        </Box>

    );

};


export default ProjectForm;
