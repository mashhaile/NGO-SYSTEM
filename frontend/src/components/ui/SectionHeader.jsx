import {
    Box,
    Stack,
    Typography
} from "@mui/material";


const SectionHeader = ({
    title,
    subtitle,
    action,
    sx = {}
}) => {

    return (
        <Stack
            direction={{
                xs: "column",
                sm: "row"
            }}

            justifyContent="space-between"

            alignItems={{
                xs: "flex-start",
                sm: "center"
            }}

            spacing={1.5}

            sx={{
                mb: 2.5,
                ...sx
            }}
        >

            <Box>

                <Typography
                    variant="h6"
                    fontWeight={700}
                >
                    {title}
                </Typography>


                {subtitle && (
                    <Typography
                        variant="body2"
                        color="text.secondary"
                        sx={{ mt: 0.5 }}
                    >
                        {subtitle}
                    </Typography>
                )}

            </Box>


            {action}

        </Stack>
    );
};


export default SectionHeader;