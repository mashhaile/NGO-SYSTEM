import DynamicForm from "./DynamicForm";

const CustomFieldRenderer = ({
    fields = [],
    values = {},
    onChange
}) => {

    // ------------------------------------------------------
    // SAFETY
    // ------------------------------------------------------

    const safeFields =
        Array.isArray(fields)
            ? fields
            : [];


    const safeValues =
        values &&
        typeof values === "object"
            ? values
            : {};


    // ------------------------------------------------------
    // DEBUG
    // ------------------------------------------------------

    console.log(
        "================================"
    );

    console.log(
        "CUSTOM FIELD RENDERER"
    );

    console.log(
        "FIELDS:",
        safeFields
    );

    console.log(
        "VALUES:",
        safeValues
    );

    console.log(
        "================================"
    );


    // ------------------------------------------------------
    // RENDER
    // ------------------------------------------------------

    if (
        safeFields.length === 0
    ) {

        return null;

    }


    return (

        <DynamicForm

            fields={
                safeFields
            }

            values={
                safeValues
            }

            setValues={
                typeof onChange === "function"
                    ? onChange
                    : () => {}
            }

        />

    );

};


export default CustomFieldRenderer;