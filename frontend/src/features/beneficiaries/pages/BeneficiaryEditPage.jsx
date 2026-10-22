import {
    useEffect,
    useState
} from "react";


import {
    useNavigate,
    useParams
} from "react-router-dom";


import BeneficiaryForm
    from "../components/BeneficiaryForm";


import {
    getBeneficiaryByIdService,
    updateBeneficiaryService
} from "../services/beneficiaryService";


import {
    getCustomFieldsByModuleService
} from "../../customfields/services/customFieldService";


import {
    getLookupsByModuleAndCategoryService
} from "../../lookups/services/lookupService";


import {
    PageContainer,
    PageHeader,
    LoadingState,
    EmptyState
} from "../../../components/ui";


// =====================================================
// HELPERS
// =====================================================

const normalizeArray = (response) => {

    if (Array.isArray(response)) {
        return response;
    }

    if (Array.isArray(response?.data?.data)) {
        return response.data.data;
    }

    if (Array.isArray(response?.data?.rows)) {
        return response.data.rows;
    }

    if (Array.isArray(response?.data)) {
        return response.data;
    }

    if (Array.isArray(response?.rows)) {
        return response.rows;
    }

    return [];

};


const getResponseData = (response) => {

    if (
        response?.data?.data &&
        typeof response.data.data === "object"
    ) {
        return response.data.data;
    }

    if (
        response?.data &&
        typeof response.data === "object" &&
        response.data._id
    ) {
        return response.data;
    }

    if (response?._id) {
        return response;
    }

    return null;

};


// =====================================================
// LOOKUP ID
// =====================================================

const getLookupId = (value) => {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return null;
    }

    if (
        typeof value === "string" ||
        typeof value === "number"
    ) {
        return String(value);
    }

    if (typeof value === "object") {

        return (

            value?._id ||

            value?.id ||

            value?.lookupId ||

            null

        );

    }

    return null;

};


// =====================================================
// CUSTOM FIELD ID
// =====================================================

const getCustomFieldId = (field) => {

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
// BUILD CUSTOM FIELDS FOR EDIT
// =====================================================

const buildEditCustomFields = (
    activeFields = [],
    savedCustomFields = []
) => {

    const fieldMap = new Map();


    // -------------------------------------------------
    // ACTIVE CUSTOM FIELD DEFINITIONS
    // -------------------------------------------------

    activeFields.forEach(
        (field) => {

            const fieldId =
                getCustomFieldId(
                    field
                );

            if (!fieldId) {
                return;
            }

            fieldMap.set(
                String(fieldId),
                field
            );

        }
    );


    // -------------------------------------------------
    // SAVED CUSTOM FIELD DEFINITIONS
    // -------------------------------------------------

    savedCustomFields.forEach(
        (item) => {

            const field =
                item?.fieldId;

            const fieldId =
                getCustomFieldId(
                    field
                );

            if (!fieldId) {
                return;
            }


            // Existing active definition wins.

            if (
                fieldMap.has(
                    String(fieldId)
                )
            ) {
                return;
            }


            // Preserve historical field definition
            // when backend populated fieldId.

            if (
                typeof field === "object"
            ) {

                fieldMap.set(
                    String(fieldId),
                    field
                );

            }

        }
    );


    return Array.from(
        fieldMap.values()
    );

};


// =====================================================
// NORMALIZE SAVED CUSTOM FIELDS
// =====================================================

const normalizeBeneficiaryCustomFields = (
    customFields = []
) => {

    if (!Array.isArray(customFields)) {
        return [];
    }


    return customFields

        .map(
            (item) => {

                if (!item) {
                    return null;
                }


                const fieldId =
                    getCustomFieldId(
                        item?.fieldId
                    );


                if (!fieldId) {
                    return null;
                }


                return {

                    fieldId:
                        String(fieldId),

                    value:
                        item?.value ?? null

                };

            }
        )

        .filter(Boolean);

};


// =====================================================
// NORMALIZE BENEFICIARY FOR FORM
// =====================================================

const normalizeBeneficiaryForForm = (
    data
) => {

    if (!data) {
        return null;
    }


    return {

        ...data,


        // -------------------------------------------------
        // SYSTEM LOOKUPS
        // -------------------------------------------------

        gender:
            getLookupId(
                data.gender
            ),

        educationLevel:
            getLookupId(
                data.educationLevel
            ),

        occupation:
            getLookupId(
                data.occupation
            ),

        maritalStatus:
            getLookupId(
                data.maritalStatus
            ),

        disabilityType:
            getLookupId(
                data.disabilityType
            ),


        vulnerableGroups:
            Array.isArray(
                data.vulnerableGroups
            )

                ? data.vulnerableGroups

                    .map(
                        getLookupId
                    )

                    .filter(Boolean)

                : [],


        // -------------------------------------------------
        // BOOLEAN
        // -------------------------------------------------

        isPWD:
            data.isPWD === true ||
            data.isPWD === "true",


        // -------------------------------------------------
        // CUSTOM FIELDS
        // -------------------------------------------------

        customFields:
            normalizeBeneficiaryCustomFields(
                data.customFields
            )

    };

};


// =====================================================
// PAGE
// =====================================================

const BeneficiaryEditPage = () => {

    const {
        id
    } = useParams();


    const navigate =
        useNavigate();


    const [
        loading,
        setLoading
    ] = useState(true);


    const [
        beneficiary,
        setBeneficiary
    ] = useState(null);


    const [
        fields,
        setFields
    ] = useState([]);


    const [
        lookups,
        setLookups
    ] = useState({

        genders: [],

        educationLevels: [],

        occupations: [],

        maritalStatuses: [],

        disabilityTypes: [],

        vulnerableGroups: [],

        pwdOptions: [

            {
                value: "true",
                label: "Yes"
            },

            {
                value: "false",
                label: "No"
            }

        ]

    });


    // =====================================================
    // LOAD
    // =====================================================

    useEffect(
        () => {

            if (!id) {

                setLoading(false);

                return;

            }

            loadData();

        },
        [id]
    );


    const loadData = async () => {

        try {

            setLoading(true);


            const [

                beneficiaryResponse,

                customFieldsResponse,

                gendersResponse,

                educationLevelsResponse,

                occupationsResponse,

                maritalStatusesResponse,

                disabilityTypesResponse,

                vulnerableGroupsResponse

            ] = await Promise.all([

                getBeneficiaryByIdService(
                    id
                ),

                // Custom fields must never block the dropdowns
                // of the form if they cannot be loaded
                getCustomFieldsByModuleService(
                    "Beneficiary"
                ).catch(() => []),

                getLookupsByModuleAndCategoryService(
                    "Beneficiary",
                    "Gender"
                ),

                getLookupsByModuleAndCategoryService(
                    "Beneficiary",
                    "EducationLevel"
                ),

                getLookupsByModuleAndCategoryService(
                    "Beneficiary",
                    "Occupation"
                ),

                getLookupsByModuleAndCategoryService(
                    "Beneficiary",
                    "MaritalStatus"
                ),

                getLookupsByModuleAndCategoryService(
                    "Beneficiary",
                    "DisabilityType"
                ),

                getLookupsByModuleAndCategoryService(
                    "Beneficiary",
                    "VulnerableGroup"
                )

            ]);


            // =================================================
            // BENEFICIARY
            // =================================================

            const beneficiaryData =
                getResponseData(
                    beneficiaryResponse
                );


            if (!beneficiaryData) {

                setBeneficiary(null);

                return;

            }


            // =================================================
            // LOOKUPS
            // =================================================

            const genders =
                normalizeArray(
                    gendersResponse
                );

            const educationLevels =
                normalizeArray(
                    educationLevelsResponse
                );

            const occupations =
                normalizeArray(
                    occupationsResponse
                );

            const maritalStatuses =
                normalizeArray(
                    maritalStatusesResponse
                );

            const disabilityTypes =
                normalizeArray(
                    disabilityTypesResponse
                );

            const vulnerableGroups =
                normalizeArray(
                    vulnerableGroupsResponse
                );


            // =================================================
            // CUSTOM FIELDS
            // =================================================

            const activeFields =
                normalizeArray(
                    customFieldsResponse
                );


            const savedCustomFields =
                Array.isArray(
                    beneficiaryData.customFields
                )
                    ? beneficiaryData.customFields
                    : [];


            const editFields =
                buildEditCustomFields(
                    activeFields,
                    savedCustomFields
                );


            // =================================================
            // NORMALIZE BENEFICIARY
            // =================================================

            const normalizedBeneficiary =
                normalizeBeneficiaryForForm(
                    beneficiaryData
                );


            // =================================================
            // SET DATA
            // =================================================

            setBeneficiary(
                normalizedBeneficiary
            );


            setFields(
                editFields
            );


            setLookups({

                genders,

                educationLevels,

                occupations,

                maritalStatuses,

                disabilityTypes,

                vulnerableGroups,

                pwdOptions: [

                    {
                        value: "true",
                        label: "Yes"
                    },

                    {
                        value: "false",
                        label: "No"
                    }

                ]

            });

        }

        catch (error) {

            console.error(
                "Failed loading beneficiary:",
                error
            );

            console.error(
                "Response:",
                error?.response?.data
            );

            setBeneficiary(null);

        }

        finally {

            setLoading(false);

        }

    };


    // =====================================================
    // UPDATE
    // =====================================================

    const handleSubmit = async (
        data
    ) => {

        try {



            const isPWD =
                data?.isPWD === true ||
                data?.isPWD === "true";


            // =================================================
            // CUSTOM FIELDS
            // =================================================

            const customFields =
                Array.isArray(
                    data?.customFields
                )

                    ? data.customFields

                        .map(
                            (item) => {

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

                    : [];


            // =================================================
            // UPDATE PAYLOAD
            // =================================================
            //
            // IMPORTANT:
            //
            // AGE IS DERIVED FROM DATE OF BIRTH.
            //
            // The frontend must never treat age as an
            // authoritative user-entered value.
            //
            // The backend recalculates age from dateOfBirth.
            //
            // =================================================

            const updatePayload = {

                ...data,


                // -------------------------------------------------
                // REMOVE CLIENT AGE
                // -------------------------------------------------

                age:
                    undefined,


                // -------------------------------------------------
                // SYSTEM LOOKUPS
                // -------------------------------------------------

                gender:
                    getLookupId(
                        data?.gender
                    ),

                educationLevel:
                    getLookupId(
                        data?.educationLevel
                    ),

                occupation:
                    getLookupId(
                        data?.occupation
                    ),

                maritalStatus:
                    getLookupId(
                        data?.maritalStatus
                    ),


                // -------------------------------------------------
                // DISABILITY
                // -------------------------------------------------

                disabilityType:
                    isPWD

                        ? getLookupId(
                            data?.disabilityType
                        )

                        : null,


                // -------------------------------------------------
                // VULNERABLE GROUPS
                // -------------------------------------------------

                vulnerableGroups:
                    Array.isArray(
                        data?.vulnerableGroups
                    )

                        ? data.vulnerableGroups

                            .map(
                                getLookupId
                            )

                            .filter(Boolean)

                        : [],


                // -------------------------------------------------
                // BOOLEAN
                // -------------------------------------------------

                isPWD,


                // -------------------------------------------------
                // CUSTOM FIELDS
                // -------------------------------------------------

                customFields

            };




            await updateBeneficiaryService(
                id,
                updatePayload
            );


            navigate(
                "/beneficiaries"
            );

        }

        catch (error) {

            console.error(
                "Beneficiary update failed:",
                error
            );

            console.error(
                "Update response:",
                error?.response?.data
            );


            const errors =
                error?.response?.data?.errors;


            if (
                Array.isArray(errors) &&
                errors.length > 0
            ) {

                alert(

                    errors

                        .map(
                            (item) => {

                                if (
                                    typeof item ===
                                    "string"
                                ) {

                                    return item;

                                }

                                return (

                                    `${item?.field || "Field"}: ` +

                                    `${item?.message || "Invalid value"}`

                                );

                            }
                        )

                        .join("\n")

                );

                return;

            }


            alert(

                error?.response?.data?.message ||

                "Failed to update beneficiary"

            );

        }

    };


    // =====================================================
    // LOADING
    // =====================================================

    if (loading) {

        return (

            <PageContainer>

                <PageHeader

                    title="Edit Beneficiary"

                    subtitle="Loading beneficiary information"

                />

                <LoadingState
                    message="Loading beneficiary..."
                />

            </PageContainer>

        );

    }


    // =====================================================
    // NOT FOUND
    // =====================================================

    if (!beneficiary) {

        return (

            <PageContainer>

                <PageHeader

                    title="Edit Beneficiary"

                    subtitle="Update beneficiary information"

                />

                <EmptyState

                    title="Beneficiary not found"

                    message="The beneficiary record does not exist."

                />

            </PageContainer>

        );

    }


    // =====================================================
    // RENDER
    // =====================================================

    return (

        <PageContainer>

            <PageHeader

                title="Edit Beneficiary"

                subtitle={

                    beneficiary?.beneficiaryNumber

                        ? `Update ${beneficiary.beneficiaryNumber}`

                        : "Update beneficiary information"

                }

            />


            <BeneficiaryForm

                initialData={
                    beneficiary
                }

                fields={
                    fields
                }

                lookups={
                    lookups
                }

                onSubmit={
                    handleSubmit
                }

            />

        </PageContainer>

    );

};


export default BeneficiaryEditPage;