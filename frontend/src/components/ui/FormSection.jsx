import {
    Card,
    CardContent,
    Typography,
    Box
} from "@mui/material";


const FormSection = ({
    title,
    subtitle,

    children,

    sx = {},
    contentSx = {}
}) => {

    return (
        <Card
            elevation={0}

            sx={{
                mb: 3,

                borderRadius: 3,

                border: "1px solid",
                borderColor: "divider",

                bgcolor:
                    "background.paper",

                ...sx
            }}
        >

            <CardContent
                sx={{
                    p: {
                        xs: 2,
                        sm: 2.5,
                        md: 3
                    },

                    "&:last-child": {
                        pb: {
                            xs: 2,
                            sm: 2.5,
                            md: 3
                        }
                    },

                    ...contentSx
                }}
            >

                {(title || subtitle) && (
                    <Box sx={{ mb: 2.5 }}>

                        {title && (
                            <Typography
                                variant="h6"
                                fontWeight={700}
                            >
                                {title}
                            </Typography>
                        )}

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
                )}


                {children}

            </CardContent>

        </Card>
    );
};


export default FormSection;