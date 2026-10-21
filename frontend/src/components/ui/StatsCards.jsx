import {
    Grid,
    Card,
    CardContent,
    Typography,
    Box
} from "@mui/material";


const StatsCards = ({
    items = [],
    columns = {
        xs: 12,
        sm: 6,
        md: 3
    },
    // "small": same compact size for every card (money rows)
    valueSize
}) => {

    return (
        <Grid
            container
            spacing={2}
            sx={{ mb: 3 }}
        >

            {items.map((item, index) => (

                <Grid
                    key={
                        item.key ??
                        item.label ??
                        index
                    }
                    size={columns}
                >

                    <Card
                        elevation={0}
                        sx={{
                            height: "100%",

                            borderRadius: 3,

                            border: "1px solid",
                            borderColor: "divider",

                            transition:
                                "transform .15s ease, box-shadow .15s ease",

                            "&:hover": {
                                transform:
                                    "translateY(-2px)",

                                boxShadow:
                                    "0 10px 25px rgba(15,23,42,0.07)"
                            }
                        }}
                    >

                        <CardContent>

                            {item.icon && (
                                <Box
                                    sx={{
                                        width: 42,
                                        height: 42,
                                        mb: 1.5,

                                        display: "flex",
                                        alignItems: "center",
                                        justifyContent: "center",

                                        borderRadius: 2,

                                        bgcolor:
                                            "action.hover",

                                        color:
                                            "primary.main"
                                    }}
                                >
                                    {item.icon}
                                </Box>
                            )}


                            <Typography
                                variant="body2"
                                sx={{
                                    color: "text.secondary",
                                    fontWeight: 600
                                }}>
                                {item.label}
                            </Typography>


                            <Typography
                                variant="h4"
                                title={String(item.value ?? 0)}
                                sx={{
                                    fontWeight: 800,
                                    mt: 0.75,
                                    // long values (money) get a smaller size so
                                    // they stay on one line
                                    ...((valueSize === "small" || String(item.value ?? "").length > 10) && {
                                        fontSize: { xs: "1.25rem", md: "1.4rem" }
                                    }),
                                    whiteSpace: "nowrap",
                                    overflow: "hidden",
                                    textOverflow: "ellipsis"
                                }}>
                                {item.value ?? 0}
                            </Typography>


                            {item.caption && (
                                <Typography
                                    variant="caption"
                                    sx={{
                                        color: "text.secondary",
                                        display: "block",
                                        mt: 0.5
                                    }}>
                                    {item.caption}
                                </Typography>
                            )}

                        </CardContent>

                    </Card>

                </Grid>

            ))}

        </Grid>
    );
};


export default StatsCards;