import {
    useEffect,
    useState
} from "react";


import {
    Box,
    Button,
    Grid,
    TextField,
    Typography,
    Stack,
    CircularProgress,
    Alert
} from "@mui/material";


import {
    PageCard,
    FormSection
} from "../../../components/ui";


import {
    getMyOrganizationService,
    updateMyOrganizationService
} from "../services/organizationService";


// ==========================================
// INITIAL FORM
// ==========================================

const initialForm = {

    name: "",
    legalName: "",
    organizationType: "",
    description: "",
    foundedYear: "",

    registrationNumber: "",
    taxIdentificationNumber: "",

    email: "",
    phone: "",
    alternativePhone: "",
    website: "",

    primaryContactName: "",
    primaryContactPosition: "",
    primaryContactEmail: "",
    primaryContactPhone: "",

    address: "",
    addressLine2: "",
    city: "",
    stateRegion: "",
    postalCode: "",
    country: "",

    logo: ""

};


// ==========================================
// ORGANIZATION SETTINGS PAGE
// ==========================================

const OrganizationSettingsPage = () => {

    const [form, setForm] =
        useState(initialForm);


    const [loading, setLoading] =
        useState(true);


    const [saving, setSaving] =
        useState(false);


    const [error, setError] =
        useState("");


    const [success, setSuccess] =
        useState("");


    // ==========================================
    // LOAD ORGANIZATION
    // ==========================================

    useEffect(() => {

        const loadOrganization = async () => {

            try {

                setLoading(true);

                setError("");


                const response =
                    await getMyOrganizationService();


                const organization =
                    response?.data || {};


                setForm({

                    name:
                        organization?.name || "",

                    legalName:
                        organization?.legalName || "",

                    organizationType:
                        organization?.organizationType || "",

                    description:
                        organization?.description || "",

                    foundedYear:
                        organization?.foundedYear || "",


                    registrationNumber:
                        organization?.registrationNumber || "",

                    taxIdentificationNumber:
                        organization?.taxIdentificationNumber || "",


                    email:
                        organization?.email || "",

                    phone:
                        organization?.phone || "",

                    alternativePhone:
                        organization?.alternativePhone || "",

                    website:
                        organization?.website || "",


                    primaryContactName:
                        organization?.primaryContact?.name || "",

                    primaryContactPosition:
                        organization?.primaryContact?.position || "",

                    primaryContactEmail:
                        organization?.primaryContact?.email || "",

                    primaryContactPhone:
                        organization?.primaryContact?.phone || "",


                    address:
                        organization?.address || "",

                    addressLine2:
                        organization?.addressLine2 || "",

                    city:
                        organization?.city || "",

                    stateRegion:
                        organization?.stateRegion || "",

                    postalCode:
                        organization?.postalCode || "",

                    country:
                        organization?.country || "",


                    logo:
                        organization?.logo || ""

                });

            }
            catch (err) {

                console.error(
                    "Failed to load organization:",
                    err
                );


                setError(
                    err?.response?.data?.message ||
                    "Failed to load organization information."
                );

            }
            finally {

                setLoading(false);

            }

        };


        loadOrganization();

    }, []);


    // ==========================================
    // CHANGE FIELD
    // ==========================================

    const handleChange =
        (field) =>
            (event) => {

                setForm(
                    previous => ({

                        ...previous,

                        [field]:
                            event.target.value

                    })
                );

            };


    // ==========================================
    // SAVE ORGANIZATION
    // ==========================================

    const handleSubmit =
        async (event) => {

            event.preventDefault();


            try {

                setSaving(true);

                setError("");

                setSuccess("");


                await updateMyOrganizationService({

                    name:
                        form.name,

                    legalName:
                        form.legalName,

                    organizationType:
                        form.organizationType,

                    description:
                        form.description,

                    foundedYear:
                        form.foundedYear
                            ? Number(form.foundedYear)
                            : undefined,


                    registrationNumber:
                        form.registrationNumber,

                    taxIdentificationNumber:
                        form.taxIdentificationNumber,


                    email:
                        form.email,

                    phone:
                        form.phone,

                    alternativePhone:
                        form.alternativePhone,

                    website:
                        form.website,


                    primaryContact: {

                        name:
                            form.primaryContactName,

                        position:
                            form.primaryContactPosition,

                        email:
                            form.primaryContactEmail,

                        phone:
                            form.primaryContactPhone

                    },


                    address:
                        form.address,

                    addressLine2:
                        form.addressLine2,

                    city:
                        form.city,

                    stateRegion:
                        form.stateRegion,

                    postalCode:
                        form.postalCode,

                    country:
                        form.country,


                    logo:
                        form.logo

                });


                setSuccess(
                    "Organization information updated successfully."
                );

            }
            catch (err) {

                console.error(
                    "Failed to update organization:",
                    err
                );


                setError(
                    err?.response?.data?.message ||
                    "Failed to update organization information."
                );

            }
            finally {

                setSaving(false);

            }

        };


    // ==========================================
    // LOADING
    // ==========================================

    if (loading) {

        return (

            <Box
                display="flex"
                justifyContent="center"
                alignItems="center"
                minHeight="300px"
            >

                <CircularProgress />

            </Box>

        );

    }


    // ==========================================
    // PAGE
    // ==========================================

    return (

        <Box>

            {/* ==================================
                PAGE HEADER
            ================================== */}

            <Box mb={3}>

                <Typography
                    variant="h4"
                    fontWeight={700}
                >
                    Organization Settings
                </Typography>


                <Typography
                    variant="body2"
                    color="text.secondary"
                    mt={0.5}
                >
                    Manage your organization's information,
                    contact details and legal information.
                </Typography>

            </Box>


            {/* ==================================
                MESSAGES
            ================================== */}

            {error && (

                <Alert
                    severity="error"
                    sx={{ mb: 2 }}
                >
                    {error}
                </Alert>

            )}


            {success && (

                <Alert
                    severity="success"
                    sx={{ mb: 2 }}
                >
                    {success}
                </Alert>

            )}


            {/* ==================================
                FORM
            ================================== */}

            <Box
                component="form"
                onSubmit={handleSubmit}
            >

                {/* ==================================
                    BASIC INFORMATION
                ================================== */}

                <PageCard>

                    <FormSection
                        title="Basic Information"
                    >

                        <Grid
                            container
                            spacing={2}
                        >

                            <Grid
                                size={{ xs: 12, md: 6 }}
                            >

                                <TextField
                                    fullWidth
                                    required
                                    label="Organization Name"
                                    value={form.name}
                                    onChange={
                                        handleChange("name")
                                    }
                                />

                            </Grid>


                            <Grid
                                size={{ xs: 12, md: 6 }}
                            >

                                <TextField
                                    fullWidth
                                    label="Legal Name"
                                    value={form.legalName}
                                    onChange={
                                        handleChange("legalName")
                                    }
                                />

                            </Grid>


                            <Grid
                                size={{ xs: 12, md: 6 }}
                            >

                                <TextField
                                    fullWidth
                                    label="Organization Type"
                                    value={form.organizationType}
                                    onChange={
                                        handleChange(
                                            "organizationType"
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
                                    label="Founded Year"
                                    value={form.foundedYear}
                                    onChange={
                                        handleChange(
                                            "foundedYear"
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
                                    rows={3}
                                    label="Description"
                                    value={form.description}
                                    onChange={
                                        handleChange(
                                            "description"
                                        )
                                    }
                                />

                            </Grid>

                        </Grid>

                    </FormSection>

                </PageCard>


                {/* ==================================
                    LEGAL INFORMATION
                ================================== */}

                <Box mt={3}>

                    <PageCard>

                        <FormSection
                            title="Legal Information"
                        >

                            <Grid
                                container
                                spacing={2}
                            >

                                <Grid
                                    size={{ xs: 12, md: 6 }}
                                >

                                    <TextField
                                        fullWidth
                                        label="Registration Number"
                                        value={
                                            form.registrationNumber
                                        }
                                        onChange={
                                            handleChange(
                                                "registrationNumber"
                                            )
                                        }
                                    />

                                </Grid>


                                <Grid
                                    size={{ xs: 12, md: 6 }}
                                >

                                    <TextField
                                        fullWidth
                                        label="Tax Identification Number"
                                        value={
                                            form.taxIdentificationNumber
                                        }
                                        onChange={
                                            handleChange(
                                                "taxIdentificationNumber"
                                            )
                                        }
                                    />

                                </Grid>

                            </Grid>

                        </FormSection>

                    </PageCard>

                </Box>


                {/* ==================================
                    CONTACT INFORMATION
                ================================== */}

                <Box mt={3}>

                    <PageCard>

                        <FormSection
                            title="Contact Information"
                        >

                            <Grid
                                container
                                spacing={2}
                            >

                                <Grid
                                    size={{ xs: 12, md: 6 }}
                                >

                                    <TextField
                                        fullWidth
                                        required
                                        type="email"
                                        label="Organization Email"
                                        value={form.email}
                                        onChange={
                                            handleChange("email")
                                        }
                                    />

                                </Grid>


                                <Grid
                                    size={{ xs: 12, md: 6 }}
                                >

                                    <TextField
                                        fullWidth
                                        required
                                        label="Phone"
                                        value={form.phone}
                                        onChange={
                                            handleChange("phone")
                                        }
                                    />

                                </Grid>


                                <Grid
                                    size={{ xs: 12, md: 6 }}
                                >

                                    <TextField
                                        fullWidth
                                        label="Alternative Phone"
                                        value={form.alternativePhone}
                                        onChange={
                                            handleChange(
                                                "alternativePhone"
                                            )
                                        }
                                    />

                                </Grid>


                                <Grid
                                    size={{ xs: 12, md: 6 }}
                                >

                                    <TextField
                                        fullWidth
                                        label="Website"
                                        value={form.website}
                                        onChange={
                                            handleChange("website")
                                        }
                                    />

                                </Grid>

                            </Grid>

                        </FormSection>

                    </PageCard>

                </Box>


                {/* ==================================
                    PRIMARY CONTACT
                ================================== */}

                <Box mt={3}>

                    <PageCard>

                        <FormSection
                            title="Primary Contact Person"
                        >

                            <Grid
                                container
                                spacing={2}
                            >

                                <Grid
                                    size={{ xs: 12, md: 6 }}
                                >

                                    <TextField
                                        fullWidth
                                        label="Contact Name"
                                        value={
                                            form.primaryContactName
                                        }
                                        onChange={
                                            handleChange(
                                                "primaryContactName"
                                            )
                                        }
                                    />

                                </Grid>


                                <Grid
                                    size={{ xs: 12, md: 6 }}
                                >

                                    <TextField
                                        fullWidth
                                        label="Position"
                                        value={
                                            form.primaryContactPosition
                                        }
                                        onChange={
                                            handleChange(
                                                "primaryContactPosition"
                                            )
                                        }
                                    />

                                </Grid>


                                <Grid
                                    size={{ xs: 12, md: 6 }}
                                >

                                    <TextField
                                        fullWidth
                                        type="email"
                                        label="Contact Email"
                                        value={
                                            form.primaryContactEmail
                                        }
                                        onChange={
                                            handleChange(
                                                "primaryContactEmail"
                                            )
                                        }
                                    />

                                </Grid>


                                <Grid
                                    size={{ xs: 12, md: 6 }}
                                >

                                    <TextField
                                        fullWidth
                                        label="Contact Phone"
                                        value={
                                            form.primaryContactPhone
                                        }
                                        onChange={
                                            handleChange(
                                                "primaryContactPhone"
                                            )
                                        }
                                    />

                                </Grid>

                            </Grid>

                        </FormSection>

                    </PageCard>

                </Box>


                {/* ==================================
                    ADDRESS
                ================================== */}

                <Box mt={3}>

                    <PageCard>

                        <FormSection
                            title="Organization Address"
                        >

                            <Grid
                                container
                                spacing={2}
                            >

                                <Grid
                                    size={{ xs: 12 }}
                                >

                                    <TextField
                                        fullWidth
                                        label="Address"
                                        value={form.address}
                                        onChange={
                                            handleChange("address")
                                        }
                                    />

                                </Grid>


                                <Grid
                                    size={{ xs: 12 }}
                                >

                                    <TextField
                                        fullWidth
                                        label="Address Line 2"
                                        value={form.addressLine2}
                                        onChange={
                                            handleChange(
                                                "addressLine2"
                                            )
                                        }
                                    />

                                </Grid>


                                <Grid
                                    size={{ xs: 12, md: 6 }}
                                >

                                    <TextField
                                        fullWidth
                                        label="City"
                                        value={form.city}
                                        onChange={
                                            handleChange("city")
                                        }
                                    />

                                </Grid>


                                <Grid
                                    size={{ xs: 12, md: 6 }}
                                >

                                    <TextField
                                        fullWidth
                                        label="State / Region"
                                        value={form.stateRegion}
                                        onChange={
                                            handleChange(
                                                "stateRegion"
                                            )
                                        }
                                    />

                                </Grid>


                                <Grid
                                    size={{ xs: 12, md: 6 }}
                                >

                                    <TextField
                                        fullWidth
                                        label="Postal Code"
                                        value={form.postalCode}
                                        onChange={
                                            handleChange(
                                                "postalCode"
                                            )
                                        }
                                    />

                                </Grid>


                                <Grid
                                    size={{ xs: 12, md: 6 }}
                                >

                                    <TextField
                                        fullWidth
                                        required
                                        label="Country"
                                        value={form.country}
                                        onChange={
                                            handleChange("country")
                                        }
                                    />

                                </Grid>

                            </Grid>

                        </FormSection>

                    </PageCard>

                </Box>


                {/* ==================================
                    BRANDING
                ================================== */}

                <Box mt={3}>

                    <PageCard>

                        <FormSection
                            title="Branding"
                        >

                            <TextField
                                fullWidth
                                label="Logo"
                                value={form.logo}
                                onChange={
                                    handleChange("logo")
                                }
                                helperText="Logo URL or logo reference"
                            />

                        </FormSection>

                    </PageCard>

                </Box>


                {/* ==================================
                    SAVE BUTTON
                ================================== */}

                <Stack
                    direction="row"
                    justifyContent="flex-end"
                    mt={3}
                    mb={5}
                >

                    <Button
                        type="submit"
                        variant="contained"
                        size="large"
                        disabled={saving}
                    >

                        {saving
                            ? "Saving..."
                            : "Save Changes"
                        }

                    </Button>

                </Stack>

            </Box>

        </Box>

    );

};


export default OrganizationSettingsPage;
