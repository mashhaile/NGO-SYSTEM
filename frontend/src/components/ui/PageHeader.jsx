import {
    Box,
    Stack,
    Typography,
    Button
} from "@mui/material";


const PageHeader = ({
    title,
    subtitle,

    action,
    actionLabel,
    actionIcon,

    secondaryAction,
    secondaryActionLabel,
    secondaryActionIcon,

    children
}) => {

    return (
        <Box
            sx={{
                mb: {
                    xs: 3,
                    md: 4
                }
            }}
        >

            <Stack
                sx={{
                    justifyContent: "space-between",
                    alignItems: {
                        xs: "stretch",
                        sm: "center"
                    }
                }}

                direction={{
                    xs: "column",
                    sm: "row"
                }}

                spacing={2}
            >

                <Box>

                    <Typography
                        variant="h4"
                        sx={{
                            fontWeight: 800,

                            fontSize: {
                                xs: "1.65rem",
                                sm: "1.9rem",
                                md: "2.1rem"
                            },

                            letterSpacing: "-0.025em"
                        }}
                    >
                        {title}
                    </Typography>


                    {subtitle && (
                        <Typography
                            color="text.secondary"
                            sx={{
                                mt: 0.7,
                                maxWidth: 720,
                                lineHeight: 1.6
                            }}
                        >
                            {subtitle}
                        </Typography>
                    )}

                </Box>


                {(action || secondaryAction) && (
                    <Stack
                        direction={{
                            xs: "column",
                            sm: "row"
                        }}
                        spacing={1}
                    >

                        {secondaryAction && (
                            <Button
                                variant="outlined"
                                startIcon={
                                    secondaryActionIcon
                                }
                                onClick={
                                    secondaryAction
                                }
                            >
                                {secondaryActionLabel}
                            </Button>
                        )}


                        {action && (
                            <Button
                                variant="contained"
                                startIcon={actionIcon}
                                onClick={action}
                            >
                                {actionLabel}
                            </Button>
                        )}

                    </Stack>
                )}

            </Stack>


            {children && (
                <Box sx={{ mt: 3 }}>
                    {children}
                </Box>
            )}

        </Box>
    );
};


export default PageHeader;