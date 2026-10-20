import {
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


const initialState = {
    program: "",
    name: "",
    description: "",
    donor: "",
    projectManager: "",
    approvedBudget: "",
    startDate: "",
    endDate: "",
    status: "Draft"
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
                ...initialState
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

            approvedBudget:
                initialData.approvedBudget ??
                "",

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
                "Draft"

        });

    }, [
        initialData
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

        if (!form.program) {

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


        // -------------------------------------------------
        // BUILD PAYLOAD
        // -------------------------------------------------

        const payload = {

            program:
                getEntityId(
                    form.program
                ),

            name:
                form.name.trim(),

            description:
                form.description?.trim() ||
                "",

            status:
                form.status ||
                "Draft"

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
        // APPROVED BUDGET
        // -------------------------------------------------

        if (
            form.approvedBudget !== null &&
            form.approvedBudget !== undefined &&
            String(
                form.approvedBudget
            ).trim() !== ""
        ) {

            const budget =
                Number(
                    form.approvedBudget
                );


            if (
                Number.isNaN(budget) ||
                budget < 0
            ) {

                setFormError(
                    "Approved budget must be a valid positive number."
                );

                return;

            }


            payload.approvedBudget =
                budget;

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
                                form.program
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
                FINANCIAL INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Financial Information"
                >

                    <FormGrid
                        columns={1}
                    >

                        <AppTextField
                            type="number"
                            label="Approved Budget"
                            value={
                                form.approvedBudget
                            }
                            onChange={(e) =>
                                changeField(
                                    "approvedBudget",
                                    e.target.value
                                )
                            }
                        />

                    </FormGrid>

                </FormSection>

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
                            options={[

                                {
                                    value: "Draft",
                                    label: "Draft"
                                },

                                {
                                    value: "Active",
                                    label: "Active"
                                },

                                {
                                    value: "Completed",
                                    label: "Completed"
                                },

                                {
                                    value: "Cancelled",
                                    label: "Cancelled"
                                }

                            ]}
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
