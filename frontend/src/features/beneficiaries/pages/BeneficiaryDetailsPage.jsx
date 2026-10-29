import {
    useEffect,
    useState
} from "react";

import {
    useNavigate,
    useParams
} from "react-router-dom";

import {
    Edit
} from "@mui/icons-material";

import {
    getBeneficiaryByIdService
} from "../services/beneficiaryService";

import {
    getCustomFieldsByModuleService
} from "../../customfields/services/customFieldService";

import useZoneLabel
    from "../../locations/hooks/useZoneLabel";

import {
    PageContainer,
    PageHeader,
    LoadingState,
    PageCard,
    FormSection,
    InfoRow,
    AppButton,
    StatusChip
} from "../../../components/ui";
import { formatDate, formatDateTime } from "../../../utils/date";


// =====================================================
// NORMALIZE RESPONSE DATA
// =====================================================

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

    if (
        response &&
        typeof response === "object" &&
        response._id
    ) {
        return response;
    }

    return null;
};


// =====================================================
// NORMALIZE ARRAY
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


// =====================================================
// GET FIELD ID
// =====================================================

const getFieldId = (field) => {

    if (!field) {
        return null;
    }

    if (
        typeof field.fieldId === "object"
    ) {
        return (
            field.fieldId?._id ||
            field.fieldId?.id ||
            null
        );
    }

    return (
        field.fieldId ||
        null
    );
};


// =====================================================
// GET FIELD LABEL
// =====================================================

const getCustomFieldLabel = (
    field,
    fieldDefinitions
) => {

    if (
        field?.fieldId &&
        typeof field.fieldId === "object"
    ) {

        return (
            field.fieldId.label ||
            field.fieldId.name ||
            field.fieldId.fieldName ||
            field.fieldId.title ||
            "Custom Field"
        );

    }


    const fieldId =
        getFieldId(field);


    if (!fieldId) {
        return "Custom Field";
    }


    const definition =
        fieldDefinitions.find(
            item =>
                String(
                    item?._id ||
                    item?.id
                ) === String(fieldId)
        );


    return (
        definition?.label ||
        definition?.name ||
        definition?.fieldName ||
        definition?.title ||
        "Custom Field"
    );

};


// =====================================================
// FORMAT CUSTOM FIELD VALUE
// =====================================================

const formatCustomFieldValue = (
    value
) => {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return "-";
    }


    if (Array.isArray(value)) {

        return value
            .map(
                item => {

                    if (
                        item &&
                        typeof item === "object"
                    ) {

                        return (
                            item.label ||
                            item.value ||
                            item.name ||
                            item.code ||
                            "-"
                        );

                    }

                    return String(item);

                }
            )
            .filter(
                Boolean
            )
            .join(", ");

    }


    if (
        typeof value === "object"
    ) {

        return (
            value.label ||
            value.value ||
            value.name ||
            value.code ||
            "-"
        );

    }


    return String(value);

};


// =====================================================
// LOOKUP VALUE
// =====================================================

const getLookupValue = (
    value
) => {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return "-";
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
            value.value ||
            value.label ||
            value.name ||
            value.code ||
            "-"
        );

    }


    return "-";

};


// =====================================================
// PAGE
// =====================================================

const BeneficiaryDetailsPage = () => {

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
        customFields,
        setCustomFields
    ] = useState([]);


    const zoneLabel =
        useZoneLabel(
            beneficiary?.regionCode
        );


    // =====================================================
    // LOAD
    // =====================================================

    useEffect(() => {

        if (!id) {
            setLoading(false);
            return;
        }

        loadBeneficiary();

    }, [id]);


    const loadBeneficiary = async () => {

        try {

            setLoading(true);


            const [
                beneficiaryResponse,
                customFieldsResponse
            ] = await Promise.all([

                getBeneficiaryByIdService(
                    id
                ),

                // Custom fields must never block the dropdowns
                // of the form if they cannot be loaded
                getCustomFieldsByModuleService(
                    "Beneficiary"
                ).catch(() => [])

            ]);


            const beneficiaryData =
                getResponseData(
                    beneficiaryResponse
                );


            const fieldDefinitions =
                normalizeArray(
                    customFieldsResponse
                );


            setBeneficiary(
                beneficiaryData
            );


            setCustomFields(
                fieldDefinitions
            );

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

            setCustomFields([]);

        }

        finally {

            setLoading(false);

        }

    };


    // =====================================================
    // DATE
    // =====================================================


// =====================================================
    // DATE TIME
    // =====================================================


// =====================================================
    // VULNERABLE GROUPS
    // =====================================================

    const getVulnerableGroups = () => {

        if (
            !Array.isArray(
                beneficiary?.vulnerableGroups
            )
        ) {
            return "-";
        }


        const values =
            beneficiary.vulnerableGroups
                .map(
                    item =>
                        getLookupValue(item)
                )
                .filter(
                    value =>
                        value !== "-"
                );


        return values.length
            ? values.join(", ")
            : "-";

    };


    // =====================================================
    // LOADING
    // =====================================================

    if (loading) {

        return (

            <PageContainer>

                <PageHeader
                    title="Beneficiary Details"
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
                    title="Beneficiary Details"
                    subtitle="Beneficiary record could not be found."
                />

                <PageCard>

                    <FormSection
                        title="Record Not Found"
                    >

                        <InfoRow
                            label="Beneficiary"
                            value="No beneficiary information available."
                        />

                    </FormSection>

                </PageCard>


                <AppButton
                    variant="outlined"
                    onClick={() =>
                        navigate(
                            "/beneficiaries"
                        )
                    }
                    sx={{
                        mt: 3,
                        mb: 5
                    }}
                >
                    Back to Beneficiaries
                </AppButton>

            </PageContainer>

        );

    }


    // =====================================================
    // SAVED CUSTOM FIELDS
    // =====================================================

    const savedCustomFields =
        Array.isArray(
            beneficiary.customFields
        )
            ? beneficiary.customFields
            : [];


    // =====================================================
    // PAGE
    // =====================================================

    return (

        <PageContainer>

            <PageHeader
                title="Beneficiary Details"
                subtitle={
                    beneficiary.beneficiaryNumber ||
                    "Beneficiary record"
                }
            />


            {/* ACTION */}

            <PageCard>

                <FormSection>

                    <AppButton
                        variant="contained"
                        startIcon={<Edit />}
                        onClick={() =>
                            navigate(
                                `/beneficiaries/${id}/edit`
                            )
                        }
                    >
                        Edit Beneficiary
                    </AppButton>

                </FormSection>

            </PageCard>


            {/* PERSONAL */}

            <PageCard>

                <FormSection
                    title="Personal Information"
                >

                    <InfoRow
                        label="Beneficiary Number"
                        value={
                            beneficiary.beneficiaryNumber ||
                            "-"
                        }
                    />

                    <InfoRow
                        label="First Name"
                        value={
                            beneficiary.firstName ||
                            "-"
                        }
                    />

                    <InfoRow
                        label="Middle Name"
                        value={
                            beneficiary.middleName ||
                            "-"
                        }
                    />

                    <InfoRow
                        label="Last Name"
                        value={
                            beneficiary.lastName ||
                            "-"
                        }
                    />

                    <InfoRow
                        label="Gender"
                        value={
                            getLookupValue(
                                beneficiary.gender
                            )
                        }
                    />

                    <InfoRow
                        label="Date of Birth"
                        value={
                            formatDate(
                                beneficiary.dateOfBirth
                            )
                        }
                    />

                    <InfoRow
                        label="Age"
                        value={
                            beneficiary.age ?? "-"
                        }
                    />

                </FormSection>

            </PageCard>


            {/* CONTACT */}

            <PageCard>

                <FormSection
                    title="Contact Information"
                >

                    <InfoRow
                        label="Phone"
                        value={
                            beneficiary.phone ||
                            "-"
                        }
                    />

                    <InfoRow
                        label="Alternative Phone"
                        value={
                            beneficiary.alternativePhone ||
                            "-"
                        }
                    />

                    <InfoRow
                        label="Email"
                        value={
                            beneficiary.email ||
                            "-"
                        }
                    />

                </FormSection>

            </PageCard>


            {/* ADDRESS */}

            <PageCard>

                <FormSection
                    title="Address Information"
                >

                    <InfoRow
                        label="Country"
                        value={
                            beneficiary.country ||
                            "-"
                        }
                    />

                    <InfoRow
                        label="Region"
                        value={
                            beneficiary.region ||
                            "-"
                        }
                    />

                    <InfoRow
                        label={zoneLabel}
                        value={
                            beneficiary.zone ||
                            "-"
                        }
                    />

                    <InfoRow
                        label="Woreda"
                        value={
                            beneficiary.woreda ||
                            "-"
                        }
                    />

                    <InfoRow
                        label="Kebele"
                        value={
                            beneficiary.kebele ||
                            "-"
                        }
                    />

                    {beneficiary.householdSize ? (
                        <InfoRow
                            label="Household size"
                            value={beneficiary.householdSize}
                        />
                    ) : null}

                    <InfoRow
                        label="Address"
                        value={
                            beneficiary.address ||
                            "-"
                        }
                    />

                </FormSection>

            </PageCard>


            {/* SOCIO ECONOMIC */}

            <PageCard>

                <FormSection
                    title="Socio Economic Information"
                >

                    <InfoRow
                        label="Education Level"
                        value={
                            getLookupValue(
                                beneficiary.educationLevel
                            )
                        }
                    />

                    <InfoRow
                        label="Occupation"
                        value={
                            getLookupValue(
                                beneficiary.occupation
                            )
                        }
                    />

                    <InfoRow
                        label="Marital Status"
                        value={
                            getLookupValue(
                                beneficiary.maritalStatus
                            )
                        }
                    />

                </FormSection>

            </PageCard>


            {/* VULNERABILITY */}

            <PageCard>

                <FormSection
                    title="Vulnerability Information"
                >

                    <InfoRow
                        label="Person With Disability"
                        value={
                            beneficiary.isPWD
                                ? "Yes"
                                : "No"
                        }
                    />

                    <InfoRow
                        label="Disability Type"
                        value={
                            beneficiary.isPWD
                                ? getLookupValue(
                                    beneficiary.disabilityType
                                )
                                : "Not Applicable"
                        }
                    />

                    <InfoRow
                        label="Vulnerable Groups"
                        value={
                            getVulnerableGroups()
                        }
                    />

                </FormSection>

            </PageCard>


            {/* =================================================
                CUSTOM FIELDS
            ================================================= */}

            {
                savedCustomFields.length > 0 && (

                    <PageCard>

                        <FormSection
                            title="Custom Fields"
                        >

                            {
                                savedCustomFields.map(
                                    (
                                        field,
                                        index
                                    ) => {

                                        const fieldId =
                                            getFieldId(
                                                field
                                            );


return (

                                            <InfoRow
                                                key={
                                                    fieldId ||
                                                    index
                                                }

                                                label={
                                                    getCustomFieldLabel(
                                                        field,
                                                        customFields
                                                    )
                                                }

                                                value={
                                                    formatCustomFieldValue(
                                                        field?.value
                                                    )
                                                }
                                            />

                                        );

                                    }
                                )
                            }

                        </FormSection>

                    </PageCard>

                )
            }


            {/* DOCUMENTS */}

            {
                Array.isArray(
                    beneficiary.documents
                ) &&
                beneficiary.documents.length > 0 && (

                    <PageCard>

                        <FormSection
                            title="Documents"
                        >

                            {
                                beneficiary.documents.map(
                                    (
                                        doc,
                                        index
                                    ) => (

                                        <InfoRow
                                            key={index}
                                            label={
                                                doc.documentType ||
                                                "Document"
                                            }
                                            value={
                                                doc.fileName ||
                                                "-"
                                            }
                                        />

                                    )
                                )
                            }

                        </FormSection>

                    </PageCard>

                )
            }


            {/* RECORD */}

            <PageCard>

                <FormSection
                    title="Record Information"
                >

                    <InfoRow
                        label="Status"
                        value={
                            <StatusChip
                                status={
                                    beneficiary.status ||
                                    "Inactive"
                                }
                            />
                        }
                    />

                    <InfoRow
                        label="Created At"
                        value={
                            formatDateTime(
                                beneficiary.createdAt
                            )
                        }
                    />

                    <InfoRow
                        label="Updated At"
                        value={
                            formatDateTime(
                                beneficiary.updatedAt
                            )
                        }
                    />

                </FormSection>

            </PageCard>


            <AppButton
                variant="outlined"
                onClick={() =>
                    navigate(
                        "/beneficiaries"
                    )
                }
                sx={{
                    mt: 3,
                    mb: 5
                }}
            >
                Back to Beneficiaries
            </AppButton>

        </PageContainer>

    );

};


export default BeneficiaryDetailsPage;