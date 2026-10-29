import { useEffect, useState } from "react";

import {
    Box,
    Grid,
    TextField,
    MenuItem,
    Button,
    Stack,
    Autocomplete
} from "@mui/material";

import { Save } from "@mui/icons-material";

import {
    AppDatePicker
} from "../../../components/ui";

import {
    getBeneficiariesLookupService
} from "../services/lookupService";

import {
    getProjectsService
} from "../../projects/services/projectService";

import { dayOf, rangeHint } from "../../../utils/date";


// =====================================================
// ENROLLMENT FORM
// =====================================================
//
// A person is enrolled in a project, or in a phase of a
// project (each phase has its own people, the same or new);
// the program comes from the project. A main project that
// has phases is not offered: its phases are.
//
// Editing: the person and the project stay; an older
// enrollment without a project can be given one (of the
// same program).
//
// =====================================================

const initialState = {
    project: null,
    beneficiary: null,
    enrollmentDate: "",
    status: "Pending",
    completionDate: "",
    exitReason: "",
    remarks: ""
};

const idOf = (value) => String(value?._id || value || "");

const projectLabel = (project) =>
    project
        ? `${project.projectCode ? `${project.projectCode} – ` : ""}${project.name}${project.program?.name ? `  (${project.program.name})` : ""}`
        : "";


const EnrollmentForm = ({
    initialData = {},
    onSubmit,
    loading = false
}) => {

    const isEdit = Boolean(initialData && initialData._id);

    const [formData, setFormData] = useState(initialState);

    const [projects, setProjects] = useState([]);

    const [beneficiaries, setBeneficiaries] = useState([]);

    useEffect(() => {

        let cancelled = false;

        Promise.all([
            getProjectsService({ limit: 1000 }).catch(() => null),
            getBeneficiariesLookupService().catch(() => [])
        ])
            .then(([projectResponse, beneficiaryData]) => {
                if (cancelled) return;
                const data = projectResponse?.data?.data ?? projectResponse?.data ?? [];
                const list = Array.isArray(data) ? data : data?.items || [];
                // a main project with phases enrolls through its phases
                const mains = new Set(list.filter(project => project.parentProject).map(project => idOf(project.parentProject)));
                setProjects(list.filter(project => !mains.has(idOf(project._id)) && !["Cancelled", "Completed"].includes(project.status)));
                setBeneficiaries(beneficiaryData || []);
            });

        return () => {
            cancelled = true;
        };

    }, []);

    useEffect(() => {

        if (initialData && Object.keys(initialData).length) {

            setFormData({

                project: initialData.project || null,

                beneficiary: initialData.beneficiary || null,

                enrollmentDate: initialData.enrollmentDate
                    ? initialData.enrollmentDate.substring(0, 10)
                    : "",

                status: initialData.status || "Pending",

                completionDate: initialData.completionDate
                    ? initialData.completionDate.substring(0, 10)
                    : "",

                exitReason: initialData.exitReason || "",

                remarks: initialData.remarks || ""

            });

        }

    }, [initialData]);

    const changeField = (field, value) => {

        setFormData(prev => ({
            ...prev,
            [field]: value
        }));

    };

    // editing: the project can only be chosen when it is not set yet,
    // and then only in the enrollment's program
    const projectLocked = isEdit && Boolean(initialData.project);
    const projectChoices =
        isEdit && !initialData.project
            ? projects.filter(project => idOf(project.program) === idOf(initialData.program))
            : projects;

    const submitHandler = (e) => {

        e.preventDefault();

        const payload = {

            ...(projectLocked ? {} : { project: idOf(formData.project) }),

            ...(isEdit ? {} : { beneficiary: idOf(formData.beneficiary) }),

            enrollmentDate: formData.enrollmentDate,

            status: formData.status,

            completionDate: formData.completionDate || null,

            exitReason: formData.exitReason || "",

            remarks: formData.remarks || ""

        };

        onSubmit(payload);

    };


    // the chosen project, with its dates and program (from the list)
    const chosen =
        projects.find(project => idOf(project._id) === idOf(formData.project)) ||
        (typeof formData.project === "object" ? formData.project : null);

    return (
        <Box
            component="form"
            onSubmit={submitHandler}
        >

            <Grid container spacing={3}>

                <Grid size={{ xs: 12, md: 6 }}>

                    <Autocomplete
                        options={projectChoices}
                        value={chosen}
                        disabled={projectLocked}
                        getOptionLabel={projectLabel}
                        isOptionEqualToValue={(option, value) => idOf(option) === idOf(value)}
                        onChange={(e, value) => changeField("project", value)}
                        renderInput={(params) => (
                            <TextField
                                {...params}
                                label="Project (or phase)"
                                required={!projectLocked}
                                helperText={
                                    chosen?.program?.name
                                        ? `Program: ${chosen.program.name}`
                                        : isEdit && !initialData.project
                                            ? `This enrollment has no project yet. Choose one of ${initialData.program?.name || "its program"}.`
                                            : "A project in phases: choose the phase."
                                }
                            />
                        )}
                    />

                </Grid>

                <Grid size={{ xs: 12, md: 6 }}>

                    <Autocomplete
                        options={beneficiaries}
                        value={formData.beneficiary}
                        disabled={isEdit}
                        getOptionLabel={(option) =>
                            option
                                ? `${option.beneficiaryNumber} - ${option.fullName || [option.firstName, option.lastName].filter(Boolean).join(" ")}`
                                : ""
                        }
                        isOptionEqualToValue={(option, value) => idOf(option) === idOf(value)}
                        onChange={(e, value) => changeField("beneficiary", value)}
                        renderInput={(params) => (
                            <TextField
                                {...params}
                                label="Beneficiary"
                                required={!isEdit}
                            />
                        )}
                    />

                </Grid>

                <Grid size={{ xs: 12, md: 6 }}>

                    <AppDatePicker
                        label="Enrollment Date"
                        // an enrollment is dated inside its project
                        helperText={rangeHint("project", chosen?.startDate, chosen?.endDate)}
                        minDate={dayOf(chosen?.startDate)}
                        maxDate={dayOf(chosen?.endDate)}
                        value={formData.enrollmentDate || null}
                        onChange={(date) =>
                            changeField(
                                "enrollmentDate",
                                date
                                    ? date.format("YYYY-MM-DD")
                                    : ""
                            )
                        }
                    />

                </Grid>

                <Grid size={{ xs: 12, md: 6 }}>

                    <TextField
                        select
                        fullWidth
                        label="Status"
                        value={formData.status}
                        onChange={(e) => changeField("status", e.target.value)}
                    >
                        {["Pending", "Active", "Completed", "Dropped"].map(status => (
                            <MenuItem key={status} value={status}>
                                {status}
                            </MenuItem>
                        ))}
                    </TextField>

                </Grid>

                <Grid size={{ xs: 12 }}>

                    <TextField
                        fullWidth
                        multiline
                        rows={3}
                        label="Remarks"
                        value={formData.remarks}
                        onChange={(e) => changeField("remarks", e.target.value)}
                    />

                </Grid>

            </Grid>

            <Stack sx={{ justifyContent: "flex-end", mt: 3 }} direction="row">

                <Button
                    variant="contained"
                    type="submit"
                    startIcon={<Save />}
                    disabled={loading}
                >
                    {loading ? "Saving..." : "Save Enrollment"}
                </Button>

            </Stack>

        </Box>
    );

};

export default EnrollmentForm;
