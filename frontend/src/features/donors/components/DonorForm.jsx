import {
    useEffect,
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


// =====================================================
// NORMALIZE DATE
// =====================================================

const normalizeDate = (
    value
) => {

    if (!value) {
        return "";
    }


    if (
        typeof value === "string"
    ) {

        return value.substring(
            0,
            10
        );

    }


    const date =
        new Date(value);


    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return "";
    }


    return date
        .toISOString()
        .substring(
            0,
            10
        );

};


// =====================================================
// BUILD FORM
// =====================================================

const buildForm = (
    data = {}
) => {

    return {

        name:
            data?.name ||
            "",


        donorType:
            data?.donorType ||
            "Organization",


        country:
            data?.country ||
            "",


        website:
            data?.website ||
            "",


        registrationNumber:
            data?.registrationNumber ||
            "",


        email:
            data?.email ||
            "",


        phone:
            data?.phone ||
            "",


        address:
            data?.address ||
            "",


        contactPerson:
            data?.contactPerson ||
            "",


        donorSince:
            normalizeDate(
                data?.donorSince
            ),


        lastContactDate:
            normalizeDate(
                data?.lastContactDate
            ),


        nextFollowUpDate:
            normalizeDate(
                data?.nextFollowUpDate
            ),


        status:
            data?.status ||
            "Active",


        notes:
            data?.notes ||
            ""

    };

};


// =====================================================
// DONOR FORM
// =====================================================

const DonorForm = ({
    initialData = null,
    onSubmit,
    loading = false
}) => {


    const [
        form,
        setForm
    ] = useState(
        () =>
            buildForm(
                initialData
            )
    );


    // =================================================
    // IMPORTANT
    // Update form when GET request finishes
    // =================================================

    useEffect(() => {

        setForm(
            buildForm(
                initialData
            )
        );

    }, [initialData]);


    // =================================================
    // CHANGE FIELD
    // =================================================

    const changeField = (
        field,
        value
    ) => {

        setForm(
            prev => ({

                ...prev,

                [field]:
                    value

            })
        );

    };


    // =================================================
    // SUBMIT
    // =================================================

    const handleSubmit = (
        e
    ) => {

        e.preventDefault();


        onSubmit({
            ...form,

            donorSince:
                form.donorSince ||
                null,

            lastContactDate:
                form.lastContactDate ||
                null,

            nextFollowUpDate:
                form.nextFollowUpDate ||
                null
        });

    };


    // =================================================
    // RENDER
    // =================================================

    return (

        <Box
            component="form"
            onSubmit={
                handleSubmit
            }
            sx={{
                width: "100%"
            }}
        >


            {/* =================================================
                DONOR INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Donor Information"
                >

                    <FormGrid>


                        <AppTextField
                            label="Donor Name"
                            required
                            value={
                                form.name
                            }
                            onChange={
                                e =>
                                    changeField(
                                        "name",
                                        e.target.value
                                    )
                            }
                        />


                        <AppSelect
                            label="Donor Type"
                            value={
                                form.donorType
                            }
                            options={[
                                {
                                    value:
                                        "Individual",
                                    label:
                                        "Individual"
                                },
                                {
                                    value:
                                        "Organization",
                                    label:
                                        "Organization"
                                },
                                {
                                    value:
                                        "Government",
                                    label:
                                        "Government"
                                },
                                {
                                    value:
                                        "NGO",
                                    label:
                                        "NGO"
                                },
                                {
                                    value:
                                        "Corporate",
                                    label:
                                        "Corporate"
                                },
                                {
                                    value:
                                        "Foundation",
                                    label:
                                        "Foundation"
                                }
                            ]}
                            onChange={
                                e =>
                                    changeField(
                                        "donorType",
                                        e.target.value
                                    )
                            }
                        />


                        <AppTextField
                            label="Country"
                            value={
                                form.country
                            }
                            onChange={
                                e =>
                                    changeField(
                                        "country",
                                        e.target.value
                                    )
                            }
                        />


                        <AppTextField
                            label="Website"
                            value={
                                form.website
                            }
                            onChange={
                                e =>
                                    changeField(
                                        "website",
                                        e.target.value
                                    )
                            }
                        />


                        <AppTextField
                            label="Registration Number"
                            value={
                                form.registrationNumber
                            }
                            onChange={
                                e =>
                                    changeField(
                                        "registrationNumber",
                                        e.target.value
                                    )
                            }
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
                            type="email"
                            label="Email"
                            value={
                                form.email
                            }
                            onChange={
                                e =>
                                    changeField(
                                        "email",
                                        e.target.value
                                    )
                            }
                        />


                        <AppTextField
                            label="Phone"
                            value={
                                form.phone
                            }
                            onChange={
                                e =>
                                    changeField(
                                        "phone",
                                        e.target.value
                                    )
                            }
                        />


                        <AppTextField
                            label="Contact Person"
                            value={
                                form.contactPerson
                            }
                            onChange={
                                e =>
                                    changeField(
                                        "contactPerson",
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
                                form.address
                            }
                            onChange={
                                e =>
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
                DONOR DATES
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Donor Dates"
                >

                    <FormGrid>


                        <AppDatePicker
                            label="Donor Since"
                            value={
                                form.donorSince ||
                                ""
                            }
                            onChange={
                                value => {

                                    changeField(
                                        "donorSince",
                                        value
                                            ? value.format(
                                                "YYYY-MM-DD"
                                            )
                                            : ""
                                    );

                                }
                            }
                        />


                        <AppDatePicker
                            label="Last Contact Date"
                            value={
                                form.lastContactDate ||
                                ""
                            }
                            onChange={
                                value => {

                                    changeField(
                                        "lastContactDate",
                                        value
                                            ? value.format(
                                                "YYYY-MM-DD"
                                            )
                                            : ""
                                    );

                                }
                            }
                        />


                        <AppDatePicker
                            label="Next Follow-up Date"
                            value={
                                form.nextFollowUpDate ||
                                ""
                            }
                            onChange={
                                value => {

                                    changeField(
                                        "nextFollowUpDate",
                                        value
                                            ? value.format(
                                                "YYYY-MM-DD"
                                            )
                                            : ""
                                    );

                                }
                            }
                        />

                    </FormGrid>

                </FormSection>

            </PageCard>


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
                                form.status ||
                                "Active"
                            }
                            options={[
                                {
                                    value:
                                        "Active",
                                    label:
                                        "Active"
                                },
                                {
                                    value:
                                        "Inactive",
                                    label:
                                        "Inactive"
                                }
                            ]}
                            onChange={
                                e =>
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
                NOTES
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Notes"
                >

                    <AppTextField
                        fullWidth
                        multiline
                        rows={4}
                        label="Notes"
                        value={
                            form.notes
                        }
                        onChange={
                            e =>
                                changeField(
                                    "notes",
                                    e.target.value
                                )
                        }
                    />

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
                            : "Save Donor"
                    }

                </AppButton>

            </FormActions>


        </Box>

    );

};


export default DonorForm;
