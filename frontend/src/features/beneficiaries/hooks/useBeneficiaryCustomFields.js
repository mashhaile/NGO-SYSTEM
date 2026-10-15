import {
    useCallback,
    useMemo
} from "react";


const useBeneficiaryCustomFields = ({
    fields = [],
    initialData = null
}) => {


    // =====================================================
    // EDIT CUSTOM FIELDS
    // =====================================================

    const editCustomFields = useMemo(() => {

        const activeFields =
            Array.isArray(fields)
                ? fields
                : [];


        const savedFields =
            Array.isArray(
                initialData?.customFields
            )
                ? initialData.customFields
                : [];


        const fieldMap = new Map();


        // -------------------------------------------------
        // ACTIVE CUSTOM FIELDS
        // -------------------------------------------------

        activeFields.forEach(
            field => {

                if (!field?._id) {
                    return;
                }

                fieldMap.set(
                    String(field._id),
                    field
                );

            }
        );


        // -------------------------------------------------
        // SAVED CUSTOM FIELDS
        // -------------------------------------------------

        savedFields.forEach(
            savedField => {

                if (!savedField) {
                    return;
                }


                const field =
                    savedField.fieldId;


                // Populated field
                if (
                    field &&
                    typeof field === "object" &&
                    field._id
                ) {

                    const fieldId =
                        String(field._id);


                    if (
                        !fieldMap.has(fieldId)
                    ) {

                        fieldMap.set(
                            fieldId,
                            field
                        );

                    }

                    return;

                }


                // fieldId is only an ID
                if (field) {

                    const fieldId =
                        String(field);


                    const definition =
                        activeFields.find(
                            item =>
                                String(
                                    item?._id
                                ) === fieldId
                        );


                    if (
                        definition &&
                        !fieldMap.has(fieldId)
                    ) {

                        fieldMap.set(
                            fieldId,
                            definition
                        );

                    }

                }

            }
        );


        return Array.from(
            fieldMap.values()
        );

    }, [
        fields,
        initialData?.customFields
    ]);


    // =====================================================
    // LOAD SAVED VALUES
    // =====================================================

    const getInitialCustomFieldValues =
        useCallback(
            (
                savedCustomFields = []
            ) => {

                const values = {};


                if (
                    !Array.isArray(
                        savedCustomFields
                    )
                ) {

                    return values;

                }


                savedCustomFields.forEach(
                    savedField => {

                        if (!savedField) {
                            return;
                        }


                        const field =
                            savedField.fieldId;


                        // ---------------------------------
                        // POPULATED FIELD
                        // ---------------------------------

                        if (
                            field &&
                            typeof field === "object"
                        ) {

                            if (field.key) {

                                values[field.key] =
                                    savedField.value;

                            }

                            return;

                        }


                        // ---------------------------------
                        // FIELD ID ONLY
                        // ---------------------------------

                        if (field) {

                            const fieldId =
                                String(field);


                            const definition =
                                (
                                    Array.isArray(fields)
                                        ? fields
                                        : []
                                ).find(
                                    item =>
                                        String(
                                            item?._id
                                        ) === fieldId
                                );


                            if (
                                definition?.key
                            ) {

                                values[
                                    definition.key
                                ] =
                                    savedField.value;

                            }

                        }

                    }
                );


                return values;

            },
            [
                fields
            ]
        );


    // =====================================================
    // BUILD API PAYLOAD
    // =====================================================

    const buildCustomFieldsPayload =
        useCallback(
            (
                form = {}
            ) => {

                if (
                    !Array.isArray(
                        editCustomFields
                    )
                ) {

                    return [];

                }


                return editCustomFields

                    .map(
                        field => {

                            if (!field?._id) {
                                return null;
                            }


                            const value =
                                form?.[field.key];


                            // Do not send empty undefined fields
                            if (
                                value === undefined
                            ) {

                                return null;

                            }


                            return {

                                fieldId:
                                    String(
                                        field._id
                                    ),

                                value:
                                    value === ""
                                        ? null
                                        : value

                            };

                        }
                    )

                    .filter(Boolean);

            },
            [
                editCustomFields
            ]
        );


    return {

        editCustomFields,

        getInitialCustomFieldValues,

        buildCustomFieldsPayload

    };

};


export default useBeneficiaryCustomFields;