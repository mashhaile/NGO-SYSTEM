import {
    useEffect,
    useState
} from "react";


import {
    Box,
    Paper,
    Typography,
    Grid,
    Alert,
    Divider,
    CircularProgress
} from "@mui/material";


import {
    useDispatch,
    useSelector
} from "react-redux";


import {
    useNavigate,
    useParams
} from "react-router-dom";


import {
    AppTextField,
    AppButton
} from "../../../components/ui";


import {
    getOrganizationByIdThunk,
    updateOrganizationThunk
} from "../store/organizationThunks";


import {
    selectOrganization,
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

    logo: ""

};


// =====================================================
// PAGE
// =====================================================

const OrganizationEditPage = () => {

    const {
        id
    } = useParams();


    const dispatch =
        useDispatch();


    const navigate =
        useNavigate();


    // =================================================
    // REDUX
    // =================================================

    const organization =
        useSelector(
            selectOrganization
        );


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


    // =================================================
    // STATE
    // =================================================

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


    const [
        initialized,
        setInitialized
    ] =
        useState(false);


    // =================================================
    // LOAD ORGANIZATION
    // =================================================

    useEffect(() => {

        if (id) {

            dispatch(
                getOrganizationByIdThunk(
                    id
                )
            );

        }

    }, [
        dispatch,
        id
    ]);


    // =================================================
    // POPULATE FORM
    // =================================================

    useEffect(() => {

        if (
            organization &&
            !initialized
        ) {

            const data =
                organization?.organization ||
                organization;


            setFormData({

                name:
                    data?.name ||
                    "",

                email:
                    data?.email ||
                    data?.contactEmail ||
                    "",

                phone:
                    data?.phone ||
                    data?.contactPhone ||
                    "",

                country:
                    data?.country ||
                    "",

                address:
                    data?.address ||
                    data?.location ||
                    "",

                website:
                    data?.website ||
                    "",

                logo:
                    data?.logo ||
                    ""

            });


            setInitialized(true);

        }

    }, [
        organization,
        initialized
    ]);


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


            if (!id) {

                setValidationError(
                    "Organization ID is missing."
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
                    formData.logo.trim()

            };


            const result =
                await dispatch(
                    updateOrganizationThunk({
                        id,
                        data: payload
                    })
                );


            if (
                updateOrganizationThunk
                    .fulfilled
                    .match(result)
            ) {

                navigate(
                    `/superadmin/organizations/${id}`,
                    {
                        replace: true
                    }
                );

            }

        };


    // =================================================
    // CANCEL
    // =================================================

    const handleCancel =
        () => {

            navigate(
                `/superadmin/organizations/${id}`
            );

        };


    // =================================================
    // LOADING
    // =================================================

    if (
        loading &&
        !initialized
    ) {

        return (

            <Box
                sx={{
                    minHeight: 320,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center"
                }}
            >

                <CircularProgress />

            </Box>

        );

    }


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
                    fontWeight={700}
                >
                    Edit Organization
                </Typography>


                <Typography
                    variant="body2"
                    color="text.secondary"
                    sx={{
                        mt: 0.5
                    }}
                >
                    Update the organization's basic information.
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
                    {
                        typeof error === "string"
                            ? error
                            : (
                                error?.message ||
                                "Unable to update organization."
                            )
                    }
                </Alert>

            )}


            {success && (

                <Alert
                    severity="success"
                    sx={{
                        mb: 2
                    }}
                >
                    {
                        message ||
                        "Organization updated successfully."
                    }
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
                        fontWeight={700}
                        sx={{
                            mb: 0.5
                        }}
                    >
                        Organization Information
                    </Typography>


                    <Typography
                        variant="body2"
                        color="text.secondary"
                        sx={{
                            mb: 3
                        }}
                    >
                        Update the organization's contact and
                        profile information.
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
                        {
                            loading
                                ? "Saving..."
                                : "Save Changes"
                        }
                    </AppButton>

                </Box>

            </Paper>

        </Box>

    );

};


export default OrganizationEditPage;