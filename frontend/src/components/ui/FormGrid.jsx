import {
    Children,
    cloneElement
} from "react";

import {
    Grid
} from "@mui/material";


const FormGrid = ({
    children,

    spacing = 2,

    columns = 3,

    sx = {}
}) => {

    const items =
        Children.toArray(children);

    const mdSize =
        12 / columns;


    return (
        <Grid
            container
            spacing={spacing}

            sx={{
                width: "100%",
                alignItems: "flex-start",
                ...sx
            }}
        >

            {items.map((child, index) => {

                if (!child) {
                    return null;
                }


                // Components that render several fields
                // (e.g. LocationCascadeFields) set
                // formGridItems and lay out their own cells.

                if (child.type?.formGridItems) {

                    return cloneElement(
                        child,
                        {
                            key:
                                child.key ??
                                index,
                            gridSize: {
                                xs: 12,
                                md: mdSize
                            }
                        }
                    );

                }


                return (
                    <Grid
                        key={
                            child.key ??
                            index
                        }

                        size={{
                            xs: 12,
                            md: mdSize
                        }}

                        sx={{
                            minWidth: 0,

                            "& > *": {
                                width: "100%",
                                minWidth: 0
                            }
                        }}
                    >
                        {child}
                    </Grid>
                );

            })}

        </Grid>
    );
};


export default FormGrid;