import {
    Card,
    CardContent
} from "@mui/material";


const PageCard = ({
    children,

    sx = {},
    contentSx = {}
}) => {

    return (
        <Card
            elevation={0}
            sx={{
                borderRadius: 3,

                border: "1px solid",
                borderColor: "divider",

                bgcolor: "background.paper",

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
                {children}
            </CardContent>

        </Card>
    );
};


export default PageCard;