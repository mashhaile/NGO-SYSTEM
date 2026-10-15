import {
    useEffect,
    useState
} from "react";


import {
    useNavigate,
    useSearchParams
} from "react-router-dom";


import {
    ArrowBack
} from "@mui/icons-material";


import BeneficiaryForm
    from "../components/beneficiaryForm";


import {
    createBeneficiaryService
} from "../services/beneficiaryService";


import {
    getCustomFieldsByModuleService
} from "../../customFields/services/customFieldService";


import {
    getLookupsByModuleAndCategoryService
} from "../../lookups/services/lookupService";


import {
    PageContainer,
    PageHeader,
    LoadingState
} from "../../../components/ui";


// =====================================================
// INITIAL LOOKUPS
// =====================================================

const initialLookups = {

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

};


// =====================================================
// ARRAY
// =====================================================

const extractArray = (response) => {

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

    if (
        typeof value === "object"
    ) {

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
// LOAD LOOKUP
// =====================================================

const loadBeneficiaryLookup = async (
    category
) => {

    try {

        const response =
            await getLookupsByModuleAndCategoryService(
                "Beneficiary",
                category
            );

        return extractArray(
            response
        );

    }

    catch (error) {

        console.error(
            `Failed to load ${category} lookup:`,
            error
        );

        return [];

    }

};


// =====================================================
// PAGE
// =====================================================

const BeneficiaryCreatePage = () => {

    const navigate =
        useNavigate();


    const [
        searchParams
    ] = useSearchParams();


    const organizationId =
        searchParams.get(
            "organizationId"
        ) || null;


    const [
        loading,
        setLoading
    ] = useState(true);


    const [
        fields,
        setFields
    ] = useState([]);


    const [
        lookups,
        setLookups
    ] = useState(
        initialLookups
    );


    // =====================================================
    // BACK URL
    // =====================================================

    const beneficiariesUrl =
        organizationId
            ? `/beneficiaries?organizationId=${organizationId}`
            : "/beneficiaries";


    // =====================================================
    // LOAD
    // =====================================================

    useEffect(
        () => {

            loadData();

        },
        []
    );


    const loadData = async () => {

        try {

            setLoading(true);


            const [

                customFieldsResponse,

                genders,

                educationLevels,

                occupations,

                maritalStatuses,

                disabilityTypes,

                vulnerableGroups

            ] = await Promise.all([

                getCustomFieldsByModuleService(
                    "Beneficiary"
                ),

                loadBeneficiaryLookup(
                    "Gender"
                ),

                loadBeneficiaryLookup(
                    "EducationLevel"
                ),

                loadBeneficiaryLookup(
                    "Occupation"
                ),

                loadBeneficiaryLookup(
                    "MaritalStatus"
                ),

                loadBeneficiaryLookup(
                    "DisabilityType"
                ),

                loadBeneficiaryLookup(
                    "VulnerableGroup"
                )

            ]);


            // =================================================
            // CUSTOM FIELDS
            // =================================================

            setFields(
                extractArray(
                    customFieldsResponse
                )
            );


            // =================================================
            // LOOKUPS
            // =================================================

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
                "Failed to load beneficiary form data:",
                error
            );

            setFields([]);

            setLookups(
                initialLookups
            );

        }

        finally {

            setLoading(false);

        }

    };


    // =====================================================
    // CREATE
    // =====================================================

    const handleSubmit = async (
        data
    ) => {

        try {

            console.log(
                "BENEFICIARY CREATE FORM DATA:",
                data
            );


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
            // CREATE PAYLOAD
            // =================================================
            //
            // IMPORTANT:
            //
            // age is intentionally NOT included.
            //
            // Backend calculates age from dateOfBirth.
            //
            // dateOfBirth = source of truth
            // age          = derived/cache
            //
            // =================================================

            const createPayload = {

                ...data,

                // ---------------------------------------------
                // REMOVE CLIENT-CALCULATED AGE
                // ---------------------------------------------

                age:
                    undefined,


                // ---------------------------------------------
                // LOOKUPS
                // ---------------------------------------------

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


                // ---------------------------------------------
                // DISABILITY
                // ---------------------------------------------

                disabilityType:
                    isPWD

                        ? getLookupId(
                            data?.disabilityType
                        )

                        : null,


                // ---------------------------------------------
                // VULNERABLE GROUPS
                // ---------------------------------------------

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


                // ---------------------------------------------
                // PWD
                // ---------------------------------------------

                isPWD,


                // ---------------------------------------------
                // CUSTOM FIELDS
                // ---------------------------------------------

                customFields

            };


            console.log(
                "BENEFICIARY CREATE PAYLOAD:",
                createPayload
            );


            await createBeneficiaryService(
                createPayload,
                organizationId
            );


            // =================================================
            // RETURN TO BENEFICIARY LIST
            // =================================================

            navigate(
                beneficiariesUrl
            );

        }

        catch (error) {

            console.error(
                "Failed to create beneficiary:",
                error
            );

            console.error(
                "Create response:",
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
                            (item) =>

                                typeof item === "string"

                                    ? item

                                    : (
                                        `${item?.field || "Field"}: ` +
                                        `${item?.message || "Invalid value"}`
                                    )
                        )

                        .join("\n")

                );

                return;

            }


            alert(

                error?.response?.data?.message ||

                "Failed to create beneficiary"

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

                    title="Create Beneficiary"

                    subtitle="Register a new beneficiary"

                    action={() =>
                        navigate(
                            beneficiariesUrl
                        )
                    }

                    actionLabel="Back"

                    actionIcon={
                        <ArrowBack />
                    }

                />

                <LoadingState
                    message="Loading beneficiary form..."
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

                title="Create Beneficiary"

                subtitle={
                    organizationId

                        ? "Register a new beneficiary for the selected organization."

                        : "Register a new beneficiary."
                }

                action={() =>
                    navigate(
                        beneficiariesUrl
                    )
                }

                actionLabel="Back"

                actionIcon={
                    <ArrowBack />
                }

            />


            <BeneficiaryForm

                onSubmit={
                    handleSubmit
                }

                fields={
                    fields
                }

                lookups={
                    lookups
                }

            />

        </PageContainer>

    );

};


export default BeneficiaryCreatePage;