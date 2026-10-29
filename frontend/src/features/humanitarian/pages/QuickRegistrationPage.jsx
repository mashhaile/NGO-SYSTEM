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
    Box,
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
import { hasPermission } from "../../../utils/permissions";
import useAuth from "../../auth/hooks/useAuth";


// =====================================================
// QUICK REGISTRATION (humanitarian module)
// =====================================================
//
// For a distribution site: the place is set once, then
// each person takes a few seconds: name, father's name,
// sex, age, phone (optional), household size. Age gives an
// estimated date of birth (1 July of that year). Enter
// saves and clears for the next person.
//
// The people registered here can then receive a delivery
// together (the delivery form opens with them and the
// place filled in). Details can be completed later on each
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
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState("");

    const firstField = useRef(null);

    useEffect(() => {
        axiosClient.get("/lookups/module/Beneficiary/category/Gender")
            .then(response => setGenders((response.data?.data || []).filter(item => item.isActive !== false)))
            .catch(() => setGenders([]));
    }, []);

    const change = (patch) => setPerson(prev => ({ ...prev, ...patch }));

    const save = async (event) => {

        event?.preventDefault?.();
        setError("");

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
            setRegistered(prev => [{
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
                <FormSection title="Distribution site" subtitle="Set once for the session.">
                    <FormGrid columns={4}>
                        <LocationCascadeFields value={site} onChange={(patch) => setSite(prev => ({ ...prev, ...patch }))} />
                        <AppTextField label="Kebele" value={site.kebele} onChange={(e) => setSite(prev => ({ ...prev, kebele: e.target.value }))} />
                    </FormGrid>
                </FormSection>
            </PageCard>

            <PageCard>
                <FormSection title="Person" subtitle="Press Enter to save and go to the next person.">
                    {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
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
