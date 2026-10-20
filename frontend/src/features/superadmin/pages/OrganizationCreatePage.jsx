import {
    PASSWORD_RULE_TEXT,
    getPasswordProblem
} from "../../../utils/passwordRule";

import {
    useState
} from "react";


import {
    Box,
    Paper,
    Typography,
    Grid,
    Alert,
    Divider
} from "@mui/material";


import {
    useDispatch,
    useSelector
} from "react-redux";


import {
    useNavigate
} from "react-router-dom";


import {
    AppTextField,
    AppButton
} from "../../../components/ui";


import {
    createOrganizationThunk
} from "../store/organizationThunks";


import {
    selectOrganizationLoading,
    selectOrganizationError,
    selectOrganizationSuccess,
    selectOrganizationMessage
} from "../store/organizationSlice";


// =====================================================
// INITIAL FORM
// =====================================================

const initialForm = {

    name: "",

    email: "",

    phone: "",

    country: "",

    address: "",

    website: "",

    logo: "",

    adminName: "",

    adminEmail: "",

    adminPassword: ""

};


// =====================================================
// PAGE
// =====================================================

const OrganizationCreatePage = () => {

    const dispatch =
        useDispatch();


    const navigate =
        useNavigate();


    const loading =
        useSelector(
            selectOrganizationLoading
        );


    const error =
        useSelector(
            selectOrganizationError
        );


    const success =
        useSelector(
            selectOrganizationSuccess
        );


    const message =
        useSelector(
            selectOrganizationMessage
        );


    const [
        formData,
        setFormData
    ] =
        useState(
            initialForm
        );


    const [
        validationError,
        setValidationError
    ] =
        useState("");


    // =================================================
    // CHANGE
    // =================================================

    const handleChange =
        (event) => {

            const {
                name,
                value
            } =
                event.target;


            setFormData(
                previous => ({
                    ...previous,
                    [name]: value
                })
            );


            setValidationError("");

        };


    // =================================================
    // SUBMIT
    // =================================================

    const handleSubmit =
        async (event) => {

            event.preventDefault();


            setValidationError("");


            const organizationName =
                formData.name.trim();


            const organizationEmail =
                formData.email.trim();


            const adminName =
                formData.adminName.trim();


            const adminEmail =
                formData.adminEmail.trim();


            const adminPassword =
                formData.adminPassword;


            if (!organizationName) {

                setValidationError(
                    "Organization name is required."
                );

                return;

            }


            if (!organizationEmail) {

                setValidationError(
                    "Organization email is required."
                );

                return;

            }


            if (!adminName) {

                setValidationError(
                    "Administrator name is required."
                );

                return;

            }


            if (!adminEmail) {

                setValidationError(
                    "Administrator email is required."
                );

                return;

            }


            if (!adminPassword) {

                setValidationError(
                    "Administrator password is required."
                );

                return;

            }


            const passwordProblem =
                getPasswordProblem(adminPassword);

            if (passwordProblem) {

                setValidationError(
                    `Administrator password: ${passwordProblem}`
                );

                return;

            }


            const payload = {

                name:
                    organizationName,

                email:
                    organizationEmail,

                phone:
                    formData.phone.trim(),

                country:
                    formData.country.trim(),

                address:
                    formData.address.trim(),

                website:
                    formData.website.trim(),

                logo:
                    formData.logo.trim(),

                adminName:
                    adminName,

                adminEmail:
                    adminEmail,

                adminPassword:
                    adminPassword

            };


            const result =
                await dispatch(
                    createOrganizationThunk(
                        payload
                    )
                );


            if (
                createOrganizationThunk
                    .fulfilled
                    .match(result)
            ) {

                setTimeout(() => {

                    navigate(
                        "/superadmin/organizations",
                        {
                            replace: true
                        }
                    );

                }, 700);

            }

        };


    // =================================================
    // CANCEL
    // =================================================

    const handleCancel =
        () => {

            navigate(
                "/superadmin/organizations"
            );

        };


    // =================================================
    // RENDER
    // =================================================

    return (
        <Box
            sx={{
                width: "100%",
                maxWidth: 1100,
                mx: "auto",
                py: 3
            }}
        >

            {/* =========================================
                HEADER
            ========================================= */}

            <Box
                sx={{
                    mb: 3
                }}
            >

                <Typography
                    variant="h5"
                    sx={{
                        fontWeight: 700
                    }}
                >
                    Create Organization
                </Typography>


                <Typography
                    variant="body2"
                    sx={{
                        color: "text.secondary",
                        mt: 0.5
                    }}>
                    Create a new organization and its initial
                    organization administrator.
                </Typography>

            </Box>

            {/* =========================================
                ALERTS
            ========================================= */}

            {validationError && (

                <Alert
                    severity="warning"
                    sx={{
                        mb: 2
                    }}
                >
                    {validationError}
                </Alert>

            )}

            {error && (

                <Alert
                    severity="error"
                    sx={{
                        mb: 2
                    }}
                >
                    {error}
                </Alert>

            )}

            {success && (

                <Alert
                    severity="success"
                    sx={{
                        mb: 2
                    }}
                >
                    {message ||
                        "Organization created successfully."}
                </Alert>

            )}

            {/* =========================================
                FORM
            ========================================= */}

            <Paper
                component="form"
                onSubmit={handleSubmit}
                elevation={0}
                sx={{
                    border: "1px solid",
                    borderColor: "divider",
                    borderRadius: 2,
                    overflow: "hidden"
                }}
            >

                {/* =====================================
                    ORGANIZATION INFORMATION
                ===================================== */}

                <Box
                    sx={{
                        p: 3
                    }}
                >

                    <Typography
                        variant="h6"
                        sx={{
                            fontWeight: 700,
                            mb: 0.5
                        }}>
                        Organization Information
                    </Typography>


                    <Typography
                        variant="body2"
                        sx={{
                            color: "text.secondary",
                            mb: 3
                        }}>
                        Enter the basic information for the
                        organization.
                    </Typography>


                    <Grid
                        container
                        spacing={2}
                    >

                        <Grid
                            size={{ xs: 12, md: 6 }}
                        >

                            <AppTextField
                                label="Organization Name"
                                name="name"
                                value={formData.name}
                                onChange={handleChange}
                                required
                                fullWidth
                            />

                        </Grid>


                        <Grid
                            size={{ xs: 12, md: 6 }}
                        >

                            <AppTextField
                                label="Organization Email"
                                name="email"
                                type="email"
                                value={formData.email}
                                onChange={handleChange}
                                required
                                fullWidth
                            />

                        </Grid>


                        <Grid
                            size={{ xs: 12, md: 6 }}
                        >

                            <AppTextField
                                label="Phone"
                                name="phone"
                                value={formData.phone}
                                onChange={handleChange}
                                fullWidth
                            />

                        </Grid>


                        <Grid
                            size={{ xs: 12, md: 6 }}
                        >

                            <AppTextField
                                label="Country"
                                name="country"
                                value={formData.country}
                                onChange={handleChange}
                                fullWidth
                            />

                        </Grid>


                        <Grid
                            size={{ xs: 12 }}
                        >

                            <AppTextField
                                label="Address"
                                name="address"
                                value={formData.address}
                                onChange={handleChange}
                                fullWidth
                                multiline
                                rows={2}
                            />

                        </Grid>


                        <Grid
                            size={{ xs: 12, md: 6 }}
                        >

                            <AppTextField
                                label="Website"
                                name="website"
                                value={formData.website}
                                onChange={handleChange}
                                fullWidth
                            />

                        </Grid>


                        <Grid
                            size={{ xs: 12, md: 6 }}
                        >

                            <AppTextField
                                label="Logo URL"
                                name="logo"
                                value={formData.logo}
                                onChange={handleChange}
                                fullWidth
                            />

                        </Grid>

                    </Grid>

                </Box>


                <Divider />


                {/* =====================================
                    ADMINISTRATOR INFORMATION
                ===================================== */}

                <Box
                    sx={{
                        p: 3
                    }}
                >

                    <Typography
                        variant="h6"
                        sx={{
                            fontWeight: 700,
                            mb: 0.5
                        }}>
                        Initial Administrator
                    </Typography>


                    <Typography
                        variant="body2"
                        sx={{
                            color: "text.secondary",
                            mb: 3
                        }}>
                        This administrator will receive full
                        organization administrator access.
                    </Typography>


                    <Grid
                        container
                        spacing={2}
                    >

                        <Grid
                            size={{ xs: 12, md: 4 }}
                        >

                            <AppTextField
                                label="Administrator Name"
                                name="adminName"
                                value={formData.adminName}
                                onChange={handleChange}
                                required
                                fullWidth
                            />

                        </Grid>


                        <Grid
                            size={{ xs: 12, md: 4 }}
                        >

                            <AppTextField
                                label="Administrator Email"
                                name="adminEmail"
                                type="email"
                                value={formData.adminEmail}
                                onChange={handleChange}
                                required
                                fullWidth
                            />

                        </Grid>


                        <Grid
                            size={{ xs: 12, md: 4 }}
                        >

                            <AppTextField
                                label="Administrator Password"
                                name="adminPassword"
                                type="password"
                                value={formData.adminPassword}
                                onChange={handleChange}
                                required
                                fullWidth
                                helperText={PASSWORD_RULE_TEXT}
                            />

                        </Grid>

                    </Grid>

                </Box>


                <Divider />


                {/* =====================================
                    ACTIONS
                ===================================== */}

                <Box
                    sx={{
                        p: 3,
                        display: "flex",
                        justifyContent: "flex-end",
                        gap: 1.5
                    }}
                >

                    <AppButton
                        type="button"
                        variant="outlined"
                        onClick={handleCancel}
                        disabled={loading}
                    >
                        Cancel
                    </AppButton>


                    <AppButton
                        type="submit"
                        variant="contained"
                        disabled={loading}
                    >
                        {loading
                            ? "Creating..."
                            : "Create Organization"}
                    </AppButton>

                </Box>

            </Paper>

        </Box>
    );

};


export default OrganizationCreatePage;