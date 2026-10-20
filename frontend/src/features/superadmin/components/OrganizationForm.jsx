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
                sx={{
                    color: "text.secondary",
                    mb: 3
                }}>
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
                sx={{
                    mb: 2
                }}
                slotProps={{
                    input: {
                        readOnly: true
                    }
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
                sx={{
                    mb: 2
                }}
                slotProps={{
                    input: {
                        readOnly: true
                    }
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
                sx={{
                    mb: 2
                }}
                slotProps={{
                    input: {
                        readOnly: true
                    }
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
                sx={{
                    mb: 2
                }}
                slotProps={{
                    input: {
                        readOnly: true
                    }
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
                sx={{
                    mb: 2
                }}
                slotProps={{
                    input: {
                        readOnly: true
                    }
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
                sx={{
                    mb: 2
                }}
                slotProps={{
                    input: {
                        readOnly: true
                    }
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
                sx={{
                    mb: 2
                }}
                slotProps={{
                    input: {
                        readOnly: true
                    }
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
                slotProps={{
                    input: {
                        readOnly: true
                    }
                }}
            />

        </Box>
    );

};


export default OrganizationForm;