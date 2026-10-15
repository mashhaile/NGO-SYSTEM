import {
    Box
} from "@mui/material";

import DynamicField
    from "./DynamicField";


// ==========================================================
// DYNAMIC FORM
// ==========================================================

const DynamicForm = ({
    fields = [],
    values = {},
    setValues
}) => {


    // ======================================================
    // CHANGE HANDLER
    // ======================================================

    const handleChange = (
        key,
        value
    ) => {

        if (!key) {
            return;
        }


        setValues({

            ...values,

            [key]:
                value

        });

    };


    // ======================================================
    // RENDER
    // ======================================================

    return (

        <Box
            sx={{
                display: "flex",
                flexDirection: "column",
                gap: 2
            }}
        >

            {
                Array.isArray(fields) &&
                fields.map((field) => (

                    <DynamicField

                        key={
                            field._id
                        }

                        field={
                            field
                        }

                        value={
                            values[
                                field.key
                            ]
                        }

                        onChange={
                            handleChange
                        }

                    />

                ))
            }

        </Box>

    );

};


export default DynamicForm;