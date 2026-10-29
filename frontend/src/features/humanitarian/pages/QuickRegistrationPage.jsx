import {
    useEffect,
    useRef,
    useState
} from "react";

import {
    useNavigate
} from "react-router-dom";

import {
    Alert,
    Autocomplete,
    Box,
    TextField,
    Link,
    Stack,
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableRow,
    Typography
} from "@mui/material";

import {
    LocalShipping,
    PersonAdd
} from "@mui/icons-material";

import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    FormGrid,
    AppTextField,
    AppSelect,
    AppButton
} from "../../../components/ui";

import LocationCascadeFields
    from "../../locations/components/LocationCascadeFields";

import axiosClient
    from "../../../services/axiosClient";

import { getApiErrorMessage } from "../../../utils/apiError";
import { useModuleOn } from "../../../utils/modules";
import { getProjectsService } from "../../projects/services/projectService";
import { hasPermission } from "../../../utils/permissions";
import useAuth from "../../auth/hooks/useAuth";


// =====================================================
// QUICK REGISTRATION (humanitarian module)
// =====================================================
//
// For a distribution site: the project (or phase) and the
// place are set once, then
// each person takes a few seconds: name, father's name,
// sex, age, phone (optional), household size. Age gives an
// estimated date of birth (1 July of that year). Enter
// saves and clears for the next person.
//
// Each person is enrolled in the project at once (when the
// Enrollments module is on). The people registered here can
// then receive a delivery
// together (the delivery form opens with them, the project
// and the place filled in). Details can be completed later on each
// person's page.
//
// =====================================================

const emptyPerson = { firstName: "", lastName: "", gender: "", age: "", phone: "", householdSize: "" };

const THIS_YEAR = new Date().getFullYear();


const QuickRegistrationPage = () => {

    const navigate = useNavigate();

    const { user } = useAuth();

    const [site, setSite] = useState({ region: "", regionCode: "", zone: "", zoneCode: "", woreda: "", woredaCode: "", kebele: "" });
    const [person, setPerson] = useState(emptyPerson);
    const [genders, setGenders] = useState([]);
    const [registered, setRegistered] = useState([]);
    const [projects, setProjects] = useState([]);
    const [project, setProject] = useState(null);
    const [warning, setWarning] = useState("");

    const enrollmentsOn = useModuleOn("enrollments");
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState("");

    const firstField = useRef(null);

    // projects people can be enrolled in: a project on its own or a phase
    useEffect(() => {
        getProjectsService({ limit: 1000 })
            .then(response => {
                const data = response?.data?.data ?? response?.data ?? [];
                const list = Array.isArray(data) ? data : data?.items || [];
                const mains = new Set(list.filter(item => item.parentProject).map(item => String(item.parentProject?._id || item.parentProject)));
                setProjects(list.filter(item => !mains.has(String(item._id)) && !["Cancelled", "Completed"].includes(item.status)));
            })
            .catch(() => setProjects([]));
    }, []);

    useEffect(() => {
        axiosClient.get("/lookups/module/Beneficiary/category/Gender")
            .then(response => setGenders((response.data?.data || []).filter(item => item.isActive !== false)))
            .catch(() => setGenders([]));
    }, []);

    const change = (patch) => setPerson(prev => ({ ...prev, ...patch }));

    const save = async (event) => {

        event?.preventDefault?.();
        setError("");
        setWarning("");

        if (!project) return setError("Choose the project (or phase) of this distribution first.");

        const age = Number(person.age);

        if (person.firstName.trim().length < 2 || person.lastName.trim().length < 2) return setError("Enter the name and the father's name.");
        if (!person.gender) return setError("Choose the sex.");
        if (person.age === "" || !Number.isInteger(age) || age < 0 || age > 120) return setError("Enter the age in years (0 to 120).");
        if (person.householdSize !== "" && !(Number.isInteger(Number(person.householdSize)) && Number(person.householdSize) >= 1)) {
            return setError("Household size is a whole number of people.");
        }

        setSaving(true);

        try {
            const response = await axiosClient.post("/beneficiaries", {
                firstName: person.firstName.trim(),
                lastName: person.lastName.trim(),
                gender: person.gender,
                // estimated from the age
                dateOfBirth: `${THIS_YEAR - age}-07-01`,
                ...(person.phone.trim() ? { phone: person.phone.trim() } : {}),
                ...(person.householdSize !== "" ? { householdSize: Number(person.householdSize) } : {}),
                region: site.region,
                regionCode: site.regionCode,
                zone: site.zone,
                zoneCode: site.zoneCode,
                woreda: site.woreda,
                woredaCode: site.woredaCode,
                kebele: site.kebele
            });
            const saved = response.data?.data;

            // enrolled in the project at once
            let enrolled = false;
            if (enrollmentsOn) {
                try {
                    await axiosClient.post("/enrollments", {
                        project: project._id,
                        beneficiary: saved._id,
                        status: "Active",
                        enrollmentDate: new Date(Date.now() + 3 * 3600 * 1000).toISOString().slice(0, 10)
                    });
                    enrolled = true;
                }
                catch (enrollError) {
                    setWarning(`${person.firstName} was registered but not enrolled: ${getApiErrorMessage(enrollError, "the enrollment failed")}`);
                }
            }

            setRegistered(prev => [{
                enrolled,
                _id: saved._id,
                number: saved.beneficiaryNumber,
                name: `${person.firstName.trim()} ${person.lastName.trim()}`,
                sex: genders.find(item => item._id === person.gender)?.value || "",
                age,
                householdSize: person.householdSize
            }, ...prev]);
            setPerson(prev => ({ ...emptyPerson, gender: prev.gender }));
            firstField.current?.focus();
        }
        catch (err) {
            setError(getApiErrorMessage(err, "The person could not be registered."));
        }
        finally {
            setSaving(false);
        }

    };

    const deliveryLink = () => {
        const params = new URLSearchParams({
            beneficiaries: registered.map(item => item._id).join(","),
            ...(project ? { program: String(project.program?._id || project.program), project: project._id } : {}),
            ...Object.fromEntries(["region", "regionCode", "zone", "zoneCode", "woreda", "woredaCode"].filter(key => site[key]).map(key => [key, site[key]]))
        });
        return `/service-deliveries/create?${params}`;
    };

    const canDeliver = hasPermission(user, "service.create");

    return (

        <PageContainer>

            <PageHeader
                title="Quick Registration"
                subtitle="Register people fast at a distribution site. The place stays filled in from one person to the next; details can be completed later."
            />

            <PageCard>
                <FormSection title="Project and distribution site" subtitle={`Set once for the session.${enrollmentsOn ? " Everyone registered is enrolled in the project." : ""}`}>
                    <Box sx={{ mb: 2 }}>
                        <Autocomplete
                            options={projects}
                            value={project}
                            disabled={registered.length > 0}
                            getOptionLabel={(option) => option ? `${option.projectCode ? `${option.projectCode} – ` : ""}${option.name}${option.program?.name ? `  (${option.program.name})` : ""}` : ""}
                            isOptionEqualToValue={(a, b) => a._id === b._id}
                            onChange={(e, value) => setProject(value)}
                            renderInput={(params) => (
                                <TextField
                                    {...params}
                                    size="small"
                                    label="Project (or phase)"
                                    required
                                    helperText={registered.length ? "Fixed for this session (people are already registered in it)" : "A project in phases: choose the phase"}
                                />
                            )}
                        />
                    </Box>
                    <FormGrid columns={4}>
                        <LocationCascadeFields value={site} onChange={(patch) => setSite(prev => ({ ...prev, ...patch }))} />
                        <AppTextField label="Kebele" value={site.kebele} onChange={(e) => setSite(prev => ({ ...prev, kebele: e.target.value }))} />
                    </FormGrid>
                </FormSection>
            </PageCard>

            <PageCard>
                <FormSection title="Person" subtitle="Press Enter to save and go to the next person.">
                    {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
                    {warning && <Alert severity="warning" sx={{ mb: 2 }} onClose={() => setWarning("")}>{warning}</Alert>}
                    <Box component="form" onSubmit={save}>
                        <FormGrid columns={3}>
                            <AppTextField label="Name" required inputRef={firstField} autoFocus value={person.firstName} onChange={(e) => change({ firstName: e.target.value })} />
                            <AppTextField label="Father's name" required value={person.lastName} onChange={(e) => change({ lastName: e.target.value })} />
                            <AppSelect label="Sex" required value={person.gender} onChange={(e) => change({ gender: e.target.value })} options={genders.map(item => ({ value: item._id, label: item.value }))} />
                            <AppTextField label="Age (years)" required type="number" value={person.age} onChange={(e) => change({ age: e.target.value })} inputProps={{ min: 0, max: 120, step: 1 }} helperText="An estimate is fine" />
                            <AppTextField label="Phone" value={person.phone} onChange={(e) => change({ phone: e.target.value })} />
                            <AppTextField label="Household size" type="number" value={person.householdSize} onChange={(e) => change({ householdSize: e.target.value })} inputProps={{ min: 1, max: 50, step: 1 }} helperText="People in the household" />
                        </FormGrid>
                        <Stack direction="row" sx={{ justifyContent: "flex-end", mt: 2 }}>
                            <AppButton type="submit" variant="contained" startIcon={<PersonAdd />} loading={saving}>
                                Save &amp; Next
                            </AppButton>
                        </Stack>
                    </Box>
                </FormSection>
            </PageCard>

            <PageCard>
                <FormSection title={`Registered in this session (${registered.length})`}>
                    {registered.length === 0
                        ? <Typography variant="body2" color="text.secondary">Nobody yet.</Typography>
                        : (
                            <>
                                <Table size="small">
                                    <TableHead>
                                        <TableRow>
                                            <TableCell>Number</TableCell>
                                            <TableCell>Name</TableCell>
                                            <TableCell>Sex</TableCell>
                                            <TableCell align="right">Age</TableCell>
                                            <TableCell align="right">Household</TableCell>
                                            {enrollmentsOn && <TableCell>Enrolled</TableCell>}
                                        </TableRow>
                                    </TableHead>
                                    <TableBody>
                                        {registered.map(item => (
                                            <TableRow key={item._id}>
                                                <TableCell>
                                                    <Link component="button" underline="hover" onClick={() => navigate(`/beneficiaries/${item._id}`)}>{item.number}</Link>
                                                </TableCell>
                                                <TableCell>{item.name}</TableCell>
                                                <TableCell>{item.sex}</TableCell>
                                                <TableCell align="right">{item.age}</TableCell>
                                                <TableCell align="right">{item.householdSize || "-"}</TableCell>
                                                {enrollmentsOn && <TableCell>{item.enrolled ? "Yes" : "No"}</TableCell>}
                                            </TableRow>
                                        ))}
                                    </TableBody>
                                </Table>
                                {canDeliver && (
                                    <Stack direction="row" sx={{ justifyContent: "flex-end", mt: 2 }}>
                                        <AppButton variant="contained" color="success" startIcon={<LocalShipping />} onClick={() => navigate(deliveryLink())}>
                                            Record a Delivery to These {registered.length}
                                        </AppButton>
                                    </Stack>
                                )}
                            </>
                        )}
                </FormSection>
            </PageCard>

        </PageContainer>

    );

};


export default QuickRegistrationPage;
