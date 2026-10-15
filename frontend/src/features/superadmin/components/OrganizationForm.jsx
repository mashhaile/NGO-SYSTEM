import {
    Box,
    TextField,
    Typography,
    Divider
} from "@mui/material";


// =====================================================
// ORGANIZATION INFORMATION
// SUPER ADMIN
// =====================================================

const OrganizationForm = ({
    formData = {},
    organization = null
}) => {

    const data =
        organization ||
        formData ||
        {};


    // =================================================
    // VALUE HELPER
    // =================================================

    const getValue = (
        primary,
        secondary = ""
    ) => {

        return (
            primary ||
            secondary ||
            "—"
        );

    };


    // =================================================
    // RENDER
    // =================================================

    return (

        <Box>

            {/* =========================================
                HEADER
            ========================================= */}

            <Typography
                variant="h6"
                sx={{
                    fontWeight: 700,
                    mb: 1
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
                Organization information managed by the Super Admin.
            </Typography>


            <Divider
                sx={{
                    mb: 3
                }}
            />


            {/* =========================================
                ORGANIZATION CODE
            ========================================= */}

            <TextField
                fullWidth
                label="Organization Code"
                value={
                    getValue(
                        data?.organizationCode,
                        data?.code
                    )
                }
                InputProps={{
                    readOnly: true
                }}
                sx={{
                    mb: 2
                }}
            />


            {/* =========================================
                NAME
            ========================================= */}

            <TextField
                fullWidth
                label="Organization Name"
                value={
                    getValue(
                        data?.name,
                        data?.organizationName
                    )
                }
                InputProps={{
                    readOnly: true
                }}
                sx={{
                    mb: 2
                }}
            />


            {/* =========================================
                EMAIL
            ========================================= */}

            <TextField
                fullWidth
                label="Email"
                value={
                    getValue(
                        data?.email,
                        data?.contactEmail
                    )
                }
                InputProps={{
                    readOnly: true
                }}
                sx={{
                    mb: 2
                }}
            />


            {/* =========================================
                PHONE
            ========================================= */}

            <TextField
                fullWidth
                label="Phone"
                value={
                    getValue(
                        data?.phone,
                        data?.contactPhone
                    )
                }
                InputProps={{
                    readOnly: true
                }}
                sx={{
                    mb: 2
                }}
            />


            {/* =========================================
                COUNTRY
            ========================================= */}

            <TextField
                fullWidth
                label="Country"
                value={
                    getValue(
                        data?.country
                    )
                }
                InputProps={{
                    readOnly: true
                }}
                sx={{
                    mb: 2
                }}
            />


            {/* =========================================
                ADDRESS
            ========================================= */}

            <TextField
                fullWidth
                multiline
                minRows={3}
                label="Address"
                value={
                    getValue(
                        data?.address
                    )
                }
                InputProps={{
                    readOnly: true
                }}
                sx={{
                    mb: 2
                }}
            />


            {/* =========================================
                WEBSITE
            ========================================= */}

            <TextField
                fullWidth
                label="Website"
                value={
                    getValue(
                        data?.website
                    )
                }
                InputProps={{
                    readOnly: true
                }}
                sx={{
                    mb: 2
                }}
            />


            {/* =========================================
                LOGO
            ========================================= */}

            <TextField
                fullWidth
                label="Logo"
                value={
                    getValue(
                        data?.logo
                    )
                }
                InputProps={{
                    readOnly: true
                }}
            />

        </Box>

    );

};


export default OrganizationForm;