import {
    useCallback,
    useEffect,
    useMemo,
    useState
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


import LocationCascadeFields
    from "../../locations/components/LocationCascadeFields";


// =====================================================
// INITIAL STATE
// =====================================================

const initialState = {

    name: "",

    enterpriseType: "",

    status: "Active",

    ownershipType: "",

    businessSector: "",

    description: "",

    startDate: "",

    endDate: "",

    country: "",

    region: "",

    zone: "",

    woreda: "",

    regionCode: "",

    zoneCode: "",

    woredaCode: "",

    kebele: "",

    address: "",

    phone: "",

    email: "",

    customFields: []

};


// =====================================================
// STATIC STATUS OPTIONS
// =====================================================

const statusOptions = [

    {
        value: "Active",
        label: "Active"
    },

    {
        value: "Inactive",
        label: "Inactive"
    }

];


// =====================================================
// NORMALIZE LOOKUP OPTIONS
// =====================================================

const normalizeOptions = (
    items = []
) => {

    if (!Array.isArray(items)) {

        return [];

    }


    return items

        .filter(Boolean)

        .map(item => {

            const id =

                item?._id ||

                item?.id ||

                "";


            const label =

                item?.label ||

                item?.value ||

                item?.name ||

                item?.code ||

                "";


            return {

                value: String(id),

                label: String(label)

            };

        })

        .filter(

            item =>

                item.value &&

                item.label

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
        typeof value === "object"
    ) {

        return String(

            value?._id ||

            value?.id ||

            ""

        );

    }


    return String(value);

};


// =====================================================
// FORMAT DATE
// =====================================================

const formatDate = (
    value
) => {

    if (!value) {

        return "";

    }


    return String(value).substring(
        0,
        10
    );

};


// =====================================================
// ENTERPRISE FORM
// =====================================================

const EnterpriseForm = ({

    onSubmit,

    lookups = {},

    initialData = null,

    loading = false

}) => {


    const [
        form,
        setForm
    ] = useState({

        ...initialState

    });


    // =================================================
    // LOOKUP OPTIONS
    // =================================================

    const enterpriseTypeOptions =

        useMemo(

            () =>

                normalizeOptions(

                    lookups?.enterpriseTypes

                ),

            [
                lookups?.enterpriseTypes
            ]

        );


    const ownershipTypeOptions =

        useMemo(

            () =>

                normalizeOptions(

                    lookups?.ownershipTypes

                ),

            [
                lookups?.ownershipTypes
            ]

        );


    const businessSectorOptions =

        useMemo(

            () =>

                normalizeOptions(

                    lookups?.businessSectors

                ),

            [
                lookups?.businessSectors
            ]

        );


    // =================================================
    // LOAD INITIAL DATA
    // =================================================

    useEffect(() => {

        if (!initialData) {

            setForm({

                ...initialState

            });

            return;

        }


        setForm({

            ...initialState,

            name:
                initialData.name ?? "",


            enterpriseType:

                getLookupId(

                    initialData.enterpriseType

                ),


            status:

                initialData.status ||

                "Active",


            ownershipType:

                getLookupId(

                    initialData.ownershipType

                ),


            businessSector:

                getLookupId(

                    initialData.businessSector

                ),


            description:

                initialData.description ?? "",


            startDate:

                formatDate(

                    initialData.startDate

                ),


            endDate:

                formatDate(

                    initialData.endDate

                ),


            country:

                initialData.country ?? "",


            region:

                initialData.region ?? "",


            zone:

                initialData.zone ?? "",


            woreda:

                initialData.woreda ?? "",


            regionCode:

                initialData.regionCode ?? "",


            zoneCode:

                initialData.zoneCode ?? "",


            woredaCode:

                initialData.woredaCode ?? "",


            kebele:

                initialData.kebele ?? "",


            address:

                initialData.address ?? "",


            phone:

                initialData.phone ?? "",


            email:

                initialData.email ?? "",


            customFields:

                Array.isArray(
                    initialData.customFields
                )

                    ? initialData.customFields

                    : []

        });

    }, [
        initialData
    ]);


    // =================================================
    // CHANGE FIELD
    // =================================================

    const changeField = (

        field,

        value

    ) => {

        setForm(previous => ({

            ...previous,

            [field]: value

        }));

    };


    // =================================================
    // CHANGE SEVERAL FIELDS (location cascade)
    // =================================================

    const changeFields = useCallback(

        (patch) => {

            setForm(previous => ({

                ...previous,

                ...patch

            }));

        },

        []

    );


    // =================================================
    // TEXT CHANGE
    // =================================================

    const handleTextChange =
        field =>
            event => {

                changeField(

                    field,

                    event.target.value

                );

            };


    // =================================================
    // DATE CHANGE
    // =================================================

    const handleDateChange =
        field =>
            newValue => {

                changeField(

                    field,

                    newValue

                        ? newValue.format(
                            "YYYY-MM-DD"
                        )

                        : ""

                );

            };


    // =================================================
    // SUBMIT
    // =================================================

    const submitHandler = event => {

        event.preventDefault();


        if (!form.name.trim()) {

            alert(
                "Enterprise name is required"
            );

            return;

        }


        if (!form.enterpriseType) {

            alert(
                "Enterprise type is required"
            );

            return;

        }


        if (!form.ownershipType) {

            alert(
                "Ownership type is required"
            );

            return;

        }


        if (!form.businessSector) {

            alert(
                "Business sector is required"
            );

            return;

        }


        const payload = {

            name:
                form.name.trim(),


            enterpriseType:
                form.enterpriseType || null,


            status:
                form.status || "Active",


            ownershipType:
                form.ownershipType || null,


            businessSector:
                form.businessSector || null,


            description:
                form.description.trim() || null,


            startDate:
                form.startDate || null,


            endDate:
                form.endDate || null,


            country:
                form.country.trim() || null,


            region:
                form.region.trim() || null,


            zone:
                form.zone.trim() || null,


            woreda:
                form.woreda.trim() || null,


            regionCode:
                form.regionCode || null,


            zoneCode:
                form.zoneCode || null,


            woredaCode:
                form.woredaCode || null,


            kebele:
                form.kebele.trim() || null,


            address:
                form.address.trim() || null,


            phone:
                form.phone.trim() || null,


            email:
                form.email.trim() || null,


            customFields:

                Array.isArray(
                    form.customFields
                )

                    ? form.customFields

                    : []

        };


        onSubmit(
            payload
        );

    };


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
                ENTERPRISE INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Enterprise Information"
                >

                    <FormGrid>


                        <AppTextField

                            label="Enterprise Name"

                            required

                            value={
                                form.name
                            }

                            onChange={
                                handleTextChange(
                                    "name"
                                )
                            }

                        />


                        <AppSelect

                            label="Enterprise Type"

                            required

                            value={
                                form.enterpriseType
                            }

                            placeholder="Select Enterprise Type"

                            options={
                                enterpriseTypeOptions
                            }

                            onChange={event =>

                                changeField(

                                    "enterpriseType",

                                    event.target.value

                                )

                            }

                        />


                        <AppSelect

                            label="Status"

                            value={
                                form.status
                            }

                            placeholder="Select Status"

                            options={
                                statusOptions
                            }

                            onChange={event =>

                                changeField(

                                    "status",

                                    event.target.value

                                )

                            }

                        />


                        <AppSelect

                            label="Ownership Type"

                            required

                            value={
                                form.ownershipType
                            }

                            placeholder="Select Ownership Type"

                            options={
                                ownershipTypeOptions
                            }

                            onChange={event =>

                                changeField(

                                    "ownershipType",

                                    event.target.value

                                )

                            }

                        />


                        <AppSelect

                            label="Business Sector"

                            required

                            value={
                                form.businessSector
                            }

                            placeholder="Select Business Sector"

                            options={
                                businessSectorOptions
                            }

                            onChange={event =>

                                changeField(

                                    "businessSector",

                                    event.target.value

                                )

                            }

                        />


                        <AppDatePicker

                            label="Start Date"

                            name="startDate"

                            value={
                                form.startDate
                            }

                            onChange={
                                handleDateChange(
                                    "startDate"
                                )
                            }

                        />


                        <AppDatePicker

                            label="End Date"

                            name="endDate"

                            value={
                                form.endDate
                            }

                            onChange={
                                handleDateChange(
                                    "endDate"
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

                            label="Description"

                            value={
                                form.description
                            }

                            onChange={
                                handleTextChange(
                                    "description"
                                )
                            }

                        />

                    </Box>

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
                                form.phone
                            }

                            onChange={
                                handleTextChange(
                                    "phone"
                                )
                            }

                        />


                        <AppTextField

                            type="email"

                            label="Email"

                            value={
                                form.email
                            }

                            onChange={
                                handleTextChange(
                                    "email"
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
                                form.country
                            }

                            onChange={
                                handleTextChange(
                                    "country"
                                )
                            }

                        />


                        <LocationCascadeFields

                            value={form}

                            onChange={changeFields}

                        />


                        <AppTextField

                            label="Kebele"

                            value={
                                form.kebele
                            }

                            onChange={
                                handleTextChange(
                                    "kebele"
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
                                form.address
                            }

                            onChange={
                                handleTextChange(
                                    "address"
                                )
                            }

                        />

                    </Box>

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

                    disabled={
                        loading
                    }

                >

                    {
                        loading
                            ? "Saving..."
                            : "Save Enterprise"
                    }

                </AppButton>

            </FormActions>


        </Box>

    );

};


export default EnterpriseForm;