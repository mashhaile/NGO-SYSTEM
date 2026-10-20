import {
    useCallback,
    useEffect,
    useState
} from "react";


// =====================================================
// INITIAL STATE
// =====================================================
//
// IMPORTANT:
//
// dateOfBirth is the source of truth for age.
//
// age is NOT stored in the form state.
// The backend calculates and stores the derived age.
//
// =====================================================

const initialState = {

    firstName: "",
    middleName: "",
    lastName: "",

    gender: "",

    dateOfBirth: "",

    phone: "",
    alternativePhone: "",
    email: "",

    country: "",
    region: "",
    zone: "",
    woreda: "",
    regionCode: "",
    zoneCode: "",
    woredaCode: "",
    kebele: "",
    address: "",

    educationLevel: "",
    occupation: "",
    maritalStatus: "",

    isPWD: false,
    disabilityType: "",

    vulnerableGroups: [],

    status: "Active"

};


// =====================================================
// CALCULATE AGE
// =====================================================

const calculateAge = (
    dateOfBirth
) => {

    if (
        dateOfBirth === undefined ||
        dateOfBirth === null ||
        dateOfBirth === ""
    ) {
        return "";
    }


    const dob =
        new Date(
            dateOfBirth
        );


    if (
        Number.isNaN(
            dob.getTime()
        )
    ) {
        return "";
    }


    const today =
        new Date();


    let age =
        today.getFullYear() -
        dob.getFullYear();


    const monthDifference =
        today.getMonth() -
        dob.getMonth();


    if (
        monthDifference < 0 ||

        (
            monthDifference === 0 &&
            today.getDate() < dob.getDate()
        )
    ) {

        age--;

    }


    if (age < 0) {
        return "";
    }


    return age;

};


// =====================================================
// NORMALIZE DATE
// =====================================================
//
// Keeps the form value compatible with AppDatePicker.
//
// =====================================================

const normalizeDate = (
    value
) => {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return "";
    }


    // ---------------------------------------------
    // Date object
    // ---------------------------------------------

    if (
        value instanceof Date
    ) {

        if (
            Number.isNaN(
                value.getTime()
            )
        ) {
            return "";
        }


        return value
            .toISOString()
            .substring(
                0,
                10
            );

    }


    // ---------------------------------------------
    // String
    // ---------------------------------------------

    const stringValue =
        String(value);


    // Already YYYY-MM-DD

    if (
        /^\d{4}-\d{2}-\d{2}/.test(
            stringValue
        )
    ) {

        return stringValue.substring(
            0,
            10
        );

    }


    const parsedDate =
        new Date(
            stringValue
        );


    if (
        Number.isNaN(
            parsedDate.getTime()
        )
    ) {
        return "";
    }


    return parsedDate
        .toISOString()
        .substring(
            0,
            10
        );

};


// =====================================================
// GET LOOKUP ID
// =====================================================

const getLookupId = (
    value
) => {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return "";
    }


    if (
        typeof value === "string" ||
        typeof value === "number"
    ) {

        return String(value);

    }


    if (
        typeof value === "object"
    ) {

        return String(

            value?._id ||

            value?.id ||

            value?.lookupId ||

            ""

        );

    }


    return "";

};


// =====================================================
// GET CUSTOM FIELD ID
// =====================================================

const getCustomFieldId = (
    field
) => {

    if (!field) {
        return null;
    }


    if (
        typeof field === "string" ||
        typeof field === "number"
    ) {

        return String(field);

    }


    return (

        field?._id ||

        field?.id ||

        field?.fieldId?._id ||

        field?.fieldId?.id ||

        field?.fieldId ||

        null

    );

};


// =====================================================
// HOOK
// =====================================================

const useBeneficiaryForm = ({
    initialData = null,
    getInitialCustomFieldValues,
    buildCustomFieldsPayload,
    onSubmit
}) => {


    const [
        form,
        setForm
    ] = useState({
        ...initialState
    });


    // =====================================================
    // INITIAL DATA
    // =====================================================

    useEffect(() => {

        if (!initialData) {

            setForm({
                ...initialState
            });

            return;

        }


        // -------------------------------------------------
        // VULNERABLE GROUPS
        // -------------------------------------------------

        const existingVulnerableGroups =

            Array.isArray(
                initialData.vulnerableGroups
            )

                ? initialData.vulnerableGroups

                    .map(
                        getLookupId
                    )

                    .filter(Boolean)

                : [];


        // -------------------------------------------------
        // DATE OF BIRTH
        // -------------------------------------------------

        const dateOfBirth =
            normalizeDate(
                initialData.dateOfBirth
            );


        // -------------------------------------------------
        // FORM
        // -------------------------------------------------
        //
        // NOTICE:
        //
        // There is deliberately NO `age` property.
        //
        // Age is derived from dateOfBirth.
        //
        // -------------------------------------------------

        const existingForm = {

            firstName:
                initialData.firstName || "",

            middleName:
                initialData.middleName || "",

            lastName:
                initialData.lastName || "",


            gender:
                getLookupId(
                    initialData.gender
                ),


            dateOfBirth,


            phone:
                initialData.phone || "",

            alternativePhone:
                initialData.alternativePhone || "",

            email:
                initialData.email || "",


            country:
                initialData.country || "",

            region:
                initialData.region || "",

            zone:
                initialData.zone || "",

            woreda:
                initialData.woreda || "",

            regionCode:
                initialData.regionCode || "",

            zoneCode:
                initialData.zoneCode || "",

            woredaCode:
                initialData.woredaCode || "",

            kebele:
                initialData.kebele || "",

            address:
                initialData.address || "",


            educationLevel:
                getLookupId(
                    initialData.educationLevel
                ),

            occupation:
                getLookupId(
                    initialData.occupation
                ),

            maritalStatus:
                getLookupId(
                    initialData.maritalStatus
                ),


            isPWD:
                initialData.isPWD === true ||
                initialData.isPWD === "true",


            disabilityType:
                getLookupId(
                    initialData.disabilityType
                ),


            vulnerableGroups:
                existingVulnerableGroups,


            status:
                initialData.status ||
                "Active"

        };


        // -------------------------------------------------
        // CUSTOM FIELDS
        // -------------------------------------------------

        const customFieldValues =

            typeof getInitialCustomFieldValues ===
                "function"

                ? getInitialCustomFieldValues(
                    initialData.customFields
                )

                : {};


        // -------------------------------------------------
        // SET FORM
        // -------------------------------------------------

        setForm({

            ...initialState,

            ...existingForm,

            ...customFieldValues

        });

    }, [
        initialData,
        getInitialCustomFieldValues
    ]);


    // =====================================================
    // CHANGE FIELD
    // =====================================================

    const changeField = (
        key,
        value
    ) => {

        setForm(
            prev => ({

                ...prev,

                [key]: value

            })
        );

    };


    // =====================================================
    // CHANGE SEVERAL FIELDS
    // =====================================================
    //
    // Used by cascading location fields.
    //
    // =====================================================

    const changeFields = useCallback(
        (patch) => {

            setForm(
                prev => ({

                    ...prev,

                    ...patch

                })
            );

        },
        []
    );


    // =====================================================
    // VULNERABLE GROUPS
    // =====================================================

    const handleVulnerableGroupsChange = (
        event
    ) => {

        const value =
            event?.target?.value;


        const normalizedValue =

            Array.isArray(value)

                ? value
                    .map(
                        getLookupId
                    )
                    .filter(Boolean)

                : value

                    ? [
                        getLookupId(
                            value
                        )
                    ].filter(Boolean)

                    : [];


        setForm(
            prev => ({

                ...prev,

                vulnerableGroups:
                    normalizedValue

            })
        );

    };


    // =====================================================
    // PWD
    // =====================================================

    const handlePWDChange = (
        event
    ) => {

        const isPWD =
            event?.target?.value ===
            "true";


        setForm(
            prev => ({

                ...prev,

                isPWD,

                disabilityType:
                    isPWD

                        ? prev.disabilityType

                        : ""

            })
        );

    };


    // =====================================================
    // CUSTOM FIELDS
    // =====================================================

    const handleCustomFieldsChange = (
        newValues
    ) => {

        setForm(
            prev => ({

                ...prev,

                ...newValues

            })
        );

    };


    // =====================================================
    // VALIDATION
    // =====================================================

    const validate = () => {

        if (
            !String(
                form.firstName || ""
            ).trim()
        ) {

            return {

                valid: false,

                message:
                    "First Name is required"

            };

        }


        if (
            !String(
                form.lastName || ""
            ).trim()
        ) {

            return {

                valid: false,

                message:
                    "Last Name is required"

            };

        }


        if (!form.gender) {

            return {

                valid: false,

                message:
                    "Gender is required"

            };

        }


        // -------------------------------------------------
        // DATE OF BIRTH
        // -------------------------------------------------

        if (form.dateOfBirth) {

            const calculatedAge =
                calculateAge(
                    form.dateOfBirth
                );


            if (
                calculatedAge === ""
            ) {

                return {

                    valid: false,

                    message:
                        "Invalid Date of Birth"

                };

            }


            if (
                calculatedAge > 120
            ) {

                return {

                    valid: false,

                    message:
                        "Beneficiary age cannot exceed 120 years"

                };

            }

        }


        // -------------------------------------------------
        // PWD
        // -------------------------------------------------

        if (
            form.isPWD === true &&
            !form.disabilityType
        ) {

            return {

                valid: false,

                message:
                    "Please select disability type"

            };

        }


        return {

            valid: true,

            message: ""

        };

    };


    // =====================================================
    // BUILD PAYLOAD
    // =====================================================

    const buildPayload = (
        customFields = []
    ) => {

        const vulnerableGroups =

            Array.isArray(
                form.vulnerableGroups
            )

                ? form.vulnerableGroups

                    .map(
                        getLookupId
                    )

                    .filter(Boolean)

                : form.vulnerableGroups

                    ? [
                        getLookupId(
                            form.vulnerableGroups
                        )
                    ].filter(Boolean)

                    : [];


        // -------------------------------------------------
        // IMPORTANT
        // -------------------------------------------------
        //
        // AGE IS NOT INCLUDED.
        //
        // The backend calculates:
        //
        // dateOfBirth -> age
        //
        // -------------------------------------------------

        return {

            firstName:
                form.firstName,

            middleName:
                form.middleName,

            lastName:
                form.lastName,


            gender:
                getLookupId(
                    form.gender
                ),


            dateOfBirth:
                form.dateOfBirth ||
                null,


            phone:
                form.phone,

            alternativePhone:
                form.alternativePhone,

            email:
                form.email,


            country:
                form.country,

            region:
                form.region,

            zone:
                form.zone,

            woreda:
                form.woreda,

            regionCode:
                form.regionCode,

            zoneCode:
                form.zoneCode,

            woredaCode:
                form.woredaCode,

            kebele:
                form.kebele,

            address:
                form.address,


            educationLevel:
                getLookupId(
                    form.educationLevel
                ) || null,

            occupation:
                getLookupId(
                    form.occupation
                ) || null,

            maritalStatus:
                getLookupId(
                    form.maritalStatus
                ) || null,


            isPWD:
                Boolean(
                    form.isPWD
                ),


            disabilityType:

                form.isPWD

                    ? (
                        getLookupId(
                            form.disabilityType
                        ) || null
                    )

                    : null,


            vulnerableGroups,


            status:
                form.status || "Active",


            customFields:

                Array.isArray(
                    customFields
                )

                    ? customFields

                        .map(
                            item => {

                                const fieldId =
                                    getCustomFieldId(
                                        item?.fieldId
                                    );


                                if (!fieldId) {
                                    return null;
                                }


                                return {

                                    fieldId:
                                        String(
                                            fieldId
                                        ),

                                    value:
                                        item?.value ??
                                        null

                                };

                            }
                        )

                        .filter(Boolean)

                    : []

        };

    };


    // =====================================================
    // SUBMIT
    // =====================================================

    const submitHandler = async (
        event
    ) => {

        event.preventDefault();


        const validation =
            validate();


        if (!validation.valid) {

            alert(
                validation.message
            );

            return;

        }


        // -------------------------------------------------
        // CUSTOM FIELD PAYLOAD
        // -------------------------------------------------

        const customFields =

            typeof buildCustomFieldsPayload ===
                "function"

                ? buildCustomFieldsPayload(
                    form
                )

                : [];


        // -------------------------------------------------
        // BENEFICIARY PAYLOAD
        // -------------------------------------------------

        const payload =
            buildPayload(
                customFields
            );




        try {

            if (
                typeof onSubmit !==
                "function"
            ) {

                console.error(
                    "Beneficiary onSubmit handler is not defined"
                );

                return;

            }


            await onSubmit(
                payload
            );

        }

        catch (error) {

            console.error(
                "Failed to submit beneficiary:",
                error
            );

        }

    };


    // =====================================================
    // RESET
    // =====================================================

    const resetForm = () => {

        setForm({
            ...initialState
        });

    };


    // =====================================================
    // DERIVED AGE
    // =====================================================
    //
    // This is ONLY for displaying age in the UI.
    //
    // It is NOT part of form state and NOT submitted.
    //
    // =====================================================

    const age =
        calculateAge(
            form.dateOfBirth
        );


    // =====================================================
    // RETURN
    // =====================================================

    return {

        form,

        setForm,

        changeField,

        changeFields,

        handleVulnerableGroupsChange,

        handlePWDChange,

        handleCustomFieldsChange,

        validate,

        buildPayload,

        submitHandler,

        resetForm,

        // ---------------------------------------------
        // DERIVED DISPLAY VALUE
        // ---------------------------------------------

        age

    };

};


export default useBeneficiaryForm;