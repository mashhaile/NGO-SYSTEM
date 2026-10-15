import {
    Box,
    Skeleton,
    Stack
} from "@mui/material";


const SkeletonTable = ({
    rows = 8,
    columns = 6
}) => {

    return (
        <Stack
            spacing={0}
            sx={{
                width: "100%"
            }}
        >

            {Array.from({
                length: rows
            }).map((_, rowIndex) => (

                <Stack
                    key={rowIndex}

                    direction="row"

                    spacing={2}

                    sx={{
                        px: 2,
                        py: 1.5,

                        borderBottom:
                            "1px solid",

                        borderColor:
                            "divider"
                    }}
                >

                    {Array.from({
                        length: columns
                    }).map((_, columnIndex) => (

                        <Box
                            key={columnIndex}
                            sx={{
                                flex: 1,
                                minWidth: 0
                            }}
                        >
                            <Skeleton
                                variant="rounded"
                                height={22}
                            />
                        </Box>

                    ))}

                </Stack>

            ))}

        </Stack>
    );
};


export default SkeletonTable;