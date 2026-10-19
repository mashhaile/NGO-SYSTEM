import {
    useMemo
} from "react";


import {
    Box
} from "@mui/material";


import {
    PageCard,
    FormSection,
    FormGrid,
    FormActions,
    AppTextField,
    AppSelect,
    AppDatePicker,
    AppButton
} from "../../../components/ui";


import CustomFieldRenderer
    from "../../customfields/components/CustomFieldRenderer";


import useBeneficiaryForm
    from "../hooks/useBeneficiaryForm";


import LocationCascadeFields
    from "../../locations/components/LocationCascadeFields";


import useBeneficiaryCustomFields
    from "../hooks/useBeneficiaryCustomFields";



// =====================================================
// NORMALIZE LOOKUP OPTIONS
// =====================================================
//
// Backend lookup:
//
// {
//     _id,
//     category,
//     value,
//     code,
//     active
// }
//
// IMPORTANT:
//
// Form stores the LOOKUP ID.
// Select displays the LOOKUP VALUE.
//
// Example:
//
// {
//     value: "6a8d50961401ac4af6ff9aaf",
//     label: "Female"
// }
//
// =====================================================

const normalizeOptions = (
    items
) => {

    if (!Array.isArray(items)) {
        return [];
    }


    return items

        .filter(Boolean)

        .filter(
            (item) =>
                item.active !== false
        )

        .map(
            (item) => {

                const id =
                    item?._id ??
                    item?.id ??
                    "";

                const label =
                    item?.value ??
                    item?.name ??
                    item?.label ??
                    item?.text ??
                    "";

                return {

                    value:
                        String(id),

                    label:
                        String(label)

                };

            }
        )

        .filter(
            (item) =>
                item.value &&
                item.label
        );

};



// =====================================================
// NORMALIZE STATIC / SIMPLE OPTIONS
// =====================================================

const normalizeSimpleOptions = (
    items
) => {

    if (!Array.isArray(items)) {
        return [];
    }


    return items

        .filter(Boolean)

        .map(
            (item) => {

                if (
                    typeof item === "string"
                ) {

                    return {

                        value:
                            item,

                        label:
                            item

                    };

                }


                return {

                    value:
                        String(
                            item?.value ??
                            item?._id ??
                            item?.id ??
                            ""
                        ),

                    label:
                        String(
                            item?.label ??
                            item?.value ??
                            item?.name ??
                            item?.text ??
                            ""
                        )

                };

            }
        )

        .filter(
            (item) =>
                item.value &&
                item.label
        );

};



// =====================================================
// NORMALIZE LOOKUP VALUE
// =====================================================
//
// This protects edit mode in case a lookup value
// arrives as an object instead of an ID.
//
// Example:
//
// { _id: "...", value: "Female" }
//      ↓
// "..."
// =====================================================

const normalizeLookupValue = (
    value
) => {

    if (!value) {
        return "";
    }


    if (
        typeof value === "object"
    ) {

        return String(
            value?._id ??
            value?.id ??
            ""
        );

    }


    return String(value);

};



// =====================================================
// NORMALIZE LOOKUP ARRAY
// =====================================================
//
// Handles:
//
// ["id1", "id2"]
//
// and:
//
// [
//     {
//         _id: "id1",
//         value: "Group 1"
//     }
// ]
//
// =====================================================

const normalizeLookupArray = (
    value
) => {

    if (!Array.isArray(value)) {
        return [];
    }


    return value

        .map(
            (item) => {

                if (
                    typeof item === "object"
                ) {

                    return String(
                        item?._id ??
                        item?.id ??
                        ""
                    );

                }

                return String(item);

            }
        )

        .filter(Boolean);

};



// =====================================================
// BENEFICIARY FORM
// =====================================================

const BeneficiaryForm = ({
    onSubmit,
    fields = [],
    lookups = {},
    initialData = null
}) => {


    // ==// =================================================
// CUSTOM FIELD HOOK
// =================================================

const {
    editCustomFields,
    getInitialCustomFieldValues,
    buildCustomFieldsPayload
} = useBeneficiaryCustomFields({

    fields,

    initialData

});


// =================================================
// BENEFICIARY FORM HOOK
// =================================================

const {
    form,
    setForm,
    changeField,
    changeFields,
    handleVulnerableGroupsChange,
    submitHandler
} = useBeneficiaryForm({

    initialData,

    getInitialCustomFieldValues,

    buildCustomFieldsPayload,

    onSubmit

});


    // =================================================
    // VULNERABLE GROUPS
    // =================================================
    //
    // PWD is handled separately.
    //
    // Remove PWD/disability-related groups from the
    // Vulnerable Groups lookup.
    //
    // =================================================

    const filteredVulnerableGroups =

        useMemo(
            () => {

                const groups =

                    Array.isArray(
                        lookups?.vulnerableGroups
                    )

                        ? lookups.vulnerableGroups

                        : [];


                return groups.filter(
                    (item) => {

                        const name =

                            String(

                                item?.value ||

                                item?.name ||

                                item?.label ||

                                ""

                            )

                                .trim()

                                .toLowerCase();


                        return (

                            !name.includes(
                                "person with disability"
                            )

                            &&

                            !name.includes(
                                "pwd"
                            )

                            &&

                            !name.includes(
                                "disability"
                            )

                        );

                    }
                );

            },
            [
                lookups?.vulnerableGroups
            ]
        );



    // =================================================
    // SYSTEM LOOKUP OPTIONS
    // =================================================

    const genderOptions =

        useMemo(
            () =>
                normalizeOptions(
                    lookups?.genders
                ),
            [
                lookups?.genders
            ]
        );


    const educationOptions =

        useMemo(
            () =>
                normalizeOptions(
                    lookups?.educationLevels
                ),
            [
                lookups?.educationLevels
            ]
        );


    const occupationOptions =

        useMemo(
            () =>
                normalizeOptions(
                    lookups?.occupations
                ),
            [
                lookups?.occupations
            ]
        );


    const maritalStatusOptions =

        useMemo(
            () =>
                normalizeOptions(
                    lookups?.maritalStatuses
                ),
            [
                lookups?.maritalStatuses
            ]
        );


    const disabilityOptions =

        useMemo(
            () =>
                normalizeOptions(
                    lookups?.disabilityTypes
                ),
            [
                lookups?.disabilityTypes
            ]
        );


    const vulnerableGroupOptions =

        useMemo(
            () =>
                normalizeOptions(
                    filteredVulnerableGroups
                ),
            [
                filteredVulnerableGroups
            ]
        );



    // =================================================
    // PWD OPTIONS
    // =================================================
    //
    // PWD is a BOOLEAN, not a lookup.
    //
    // =================================================

    const pwdOptions = [

        {
            value: "true",
            label: "Yes"
        },

        {
            value: "false",
            label: "No"
        }

    ];



    // =================================================
    // STATUS OPTIONS
    // =================================================

    const statusOptions =

        useMemo(
            () => {

                if (
                    Array.isArray(
                        lookups?.statuses
                    )
                    &&
                    lookups.statuses.length > 0
                ) {

                    return normalizeOptions(
                        lookups.statuses
                    );

                }


                return normalizeSimpleOptions(
                    [
                        {
                            value: "Active",
                            label: "Active"
                        },
                        {
                            value: "Inactive",
                            label: "Inactive"
                        }
                    ]
                );

            },
            [
                lookups?.statuses
            ]
        );



    // =================================================
    // SAFE FORM VALUES
    // =================================================

    const vulnerableGroupsValue =

        useMemo(
            () =>
                normalizeLookupArray(
                    form?.vulnerableGroups
                ),
            [
                form?.vulnerableGroups
            ]
        );



    // =================================================
    // SAFE LOOKUP VALUES
    // =================================================

    const genderValue =

        normalizeLookupValue(
            form?.gender
        );


    const educationValue =

        normalizeLookupValue(
            form?.educationLevel
        );


    const occupationValue =

        normalizeLookupValue(
            form?.occupation
        );


    const maritalStatusValue =

        normalizeLookupValue(
            form?.maritalStatus
        );


    const disabilityTypeValue =

        normalizeLookupValue(
            form?.disabilityType
        );



    // =================================================
    // RENDER
    // =================================================

    return (

        <Box
            component="form"
            onSubmit={
                submitHandler
            }
            sx={{
                width: "100%"
            }}
        >


            {/* =================================================
                PERSONAL INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Personal Information"
                >

                    <FormGrid>


                        <AppTextField
                            label="First Name"
                            required
                            value={
                                form?.firstName || ""
                            }
                            onChange={(e) =>
                                changeField(
                                    "firstName",
                                    e.target.value
                                )
                            }
                        />


                        <AppTextField
                            label="Middle Name"
                            value={
                                form?.middleName || ""
                            }
                            onChange={(e) =>
                                changeField(
                                    "middleName",
                                    e.target.value
                                )
                            }
                        />


                        <AppTextField
                            label="Last Name"
                            required
                            value={
                                form?.lastName || ""
                            }
                            onChange={(e) =>
                                changeField(
                                    "lastName",
                                    e.target.value
                                )
                            }
                        />


                        <AppSelect
                            label="Gender"
                            required
                            value={
                                genderValue
                            }
                            placeholder="Select Gender"
                            options={
                                genderOptions
                            }
                            onChange={(e) =>
                                changeField(
                                    "gender",
                                    e.target.value
                                )
                            }
                        />


                        <AppDatePicker
                            label="Date of Birth"
                            name="dateOfBirth"
                            value={
                                form?.dateOfBirth || ""
                            }
                            onChange={
                                (newValue) => {

                                    changeField(

                                        "dateOfBirth",

                                        newValue

                                            ? newValue.format(
                                                "YYYY-MM-DD"
                                            )

                                            : ""

                                    );

                                }
                            }
                        />


                        <AppTextField
    type="number"
    label="Age"
    value={form?.age ?? ""}
    InputProps={{
        readOnly: true
    }}
    helperText="Automatically calculated from Date of Birth"
/>


                    </FormGrid>

                </FormSection>

            </PageCard>



            {/* =================================================
                CONTACT INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Contact Information"
                >

                    <FormGrid>


                        <AppTextField
                            label="Phone"
                            value={
                                form?.phone || ""
                            }
                            onChange={(e) =>
                                changeField(
                                    "phone",
                                    e.target.value
                                )
                            }
                        />


                        <AppTextField
                            label="Alternative Phone"
                            value={
                                form?.alternativePhone || ""
                            }
                            onChange={(e) =>
                                changeField(
                                    "alternativePhone",
                                    e.target.value
                                )
                            }
                        />


                        <AppTextField
                            type="email"
                            label="Email"
                            value={
                                form?.email || ""
                            }
                            onChange={(e) =>
                                changeField(
                                    "email",
                                    e.target.value
                                )
                            }
                        />


                    </FormGrid>

                </FormSection>

            </PageCard>



            {/* =================================================
                ADDRESS INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Address Information"
                >

                    <FormGrid>


                        <AppTextField
                            label="Country"
                            value={
                                form?.country || ""
                            }
                            onChange={(e) =>
                                changeField(
                                    "country",
                                    e.target.value
                                )
                            }
                        />


                        <LocationCascadeFields
                            value={form || {}}
                            onChange={changeFields}
                        />


                        <AppTextField
                            label="Kebele"
                            value={
                                form?.kebele || ""
                            }
                            onChange={(e) =>
                                changeField(
                                    "kebele",
                                    e.target.value
                                )
                            }
                        />


                    </FormGrid>


                    <Box
                        sx={{
                            mt: 2
                        }}
                    >

                        <AppTextField
                            fullWidth
                            multiline
                            rows={3}
                            label="Address"
                            value={
                                form?.address || ""
                            }
                            onChange={(e) =>
                                changeField(
                                    "address",
                                    e.target.value
                                )
                            }
                        />

                    </Box>


                </FormSection>

            </PageCard>



            {/* =================================================
                SOCIO ECONOMIC INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Socio Economic Information"
                >

                    <FormGrid>


                        <AppSelect
                            label="Education Level"
                            value={
                                educationValue
                            }
                            placeholder="Select Education"
                            options={
                                educationOptions
                            }
                            onChange={(e) =>
                                changeField(
                                    "educationLevel",
                                    e.target.value
                                )
                            }
                        />


                        <AppSelect
                            label="Occupation"
                            value={
                                occupationValue
                            }
                            placeholder="Select Occupation"
                            options={
                                occupationOptions
                            }
                            onChange={(e) =>
                                changeField(
                                    "occupation",
                                    e.target.value
                                )
                            }
                        />


                        <AppSelect
                            label="Marital Status"
                            value={
                                maritalStatusValue
                            }
                            placeholder="Select Marital Status"
                            options={
                                maritalStatusOptions
                            }
                            onChange={(e) =>
                                changeField(
                                    "maritalStatus",
                                    e.target.value
                                )
                            }
                        />


                    </FormGrid>

                </FormSection>

            </PageCard>



            {/* =================================================
                VULNERABILITY INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Vulnerability Information"
                >

                    <FormGrid>


                        {/* =========================================
                            PWD
                        ========================================= */}

                        <AppSelect
                            label="Person With Disability (PWD)"
                            value={
                                String(
                                    Boolean(
                                        form?.isPWD
                                    )
                                )
                            }
                            placeholder="Select PWD"
                            options={
                                pwdOptions
                            }
                            onChange={(e) => {

                                const isPWD =
                                    e.target.value ===
                                    "true";


                                setForm(
                                    (prev) => ({

                                        ...prev,

                                        isPWD,

                                        disabilityType:

                                            isPWD

                                                ? prev?.disabilityType

                                                : ""

                                    })
                                );

                            }}
                        />


                        {/* =========================================
                            DISABILITY TYPE
                        ========================================= */}

                        <AppSelect
                            label="Disability Type"
                            required={
                                Boolean(
                                    form?.isPWD
                                )
                            }
                            disabled={
                                !Boolean(
                                    form?.isPWD
                                )
                            }
                            value={
                                disabilityTypeValue
                            }
                            placeholder="Select Disability"
                            options={
                                disabilityOptions
                            }
                            onChange={(e) =>
                                changeField(
                                    "disabilityType",
                                    e.target.value
                                )
                            }
                        />


                        {/* =========================================
                            VULNERABLE GROUPS
                        ========================================= */}

                        <AppSelect
                            label="Vulnerable Groups"
                            value={
                                vulnerableGroupsValue
                            }
                            placeholder="Select Vulnerable Groups"
                            options={
                                vulnerableGroupOptions
                            }
                            SelectProps={{
                                multiple: true
                            }}
                            onChange={
                                handleVulnerableGroupsChange
                            }
                        />


                    </FormGrid>

                </FormSection>

            </PageCard>



            {/* =================================================
                CUSTOM FIELDS
            ================================================= */}

            {
                Array.isArray(
                    editCustomFields
                )

                &&

                editCustomFields.length > 0

                && (

                    <PageCard>

                        <FormSection
                            title="Custom Fields"
                        >

                            <CustomFieldRenderer
                                fields={
                                    editCustomFields
                                }
                                values={
                                    form
                                }
                                onChange={
                                    (newValues) => {

                                        setForm(
                                            (prev) => ({

                                                ...prev,

                                                ...newValues

                                            })
                                        );

                                    }
                                }
                            />

                        </FormSection>

                    </PageCard>

                )
            }



            {/* =================================================
                STATUS
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Status"
                >

                    <FormGrid
                        columns={1}
                    >

                        <AppSelect
                            label="Status"
                            value={
                                form?.status ||
                                "Active"
                            }
                            placeholder="Select Status"
                            options={
                                statusOptions
                            }
                            onChange={(e) =>
                                changeField(
                                    "status",
                                    e.target.value
                                )
                            }
                        />

                    </FormGrid>

                </FormSection>

            </PageCard>



            {/* =================================================
                ACTIONS
            ================================================= */}

            <FormActions>

                <AppButton
                    type="submit"
                    variant="contained"
                    size="large"
                >
                    Save Beneficiary
                </AppButton>

            </FormActions>


        </Box>

    );

};


export default BeneficiaryForm;


// Important:** this fixes the `BeneficiaryForm.jsx` side. The remaining piece that determines how the GET response is converted into `form` is `useBeneficiaryForm`.

//If the edit page still shows blank lookup selections after replacing this file, **do not change this form again**—send me `useBeneficiaryForm.js`, because that hook is then the exact place that needs fixing.
