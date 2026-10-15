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


const initialState = {

    name: "",

    description: "",

    category: "",

    budget: "",

    targetBeneficiaries: "",

    startDate: "",

    endDate: "",

    status: "Planned"

};


const ProgramForm = ({

    initialData = null,

    onSubmit,

    loading = false

}) => {


    const [
        form,
        setForm
    ] = useState(initialState);


    // =====================================================
    // LOAD INITIAL DATA
    // =====================================================

    useEffect(() => {

        if (!initialData) {

            setForm({
                ...initialState
            });

            return;

        }


        setForm({

            name:
                initialData.name || "",

            description:
                initialData.description || "",

            category:
                initialData.category || "",

            budget:
                initialData.budget ?? "",

            targetBeneficiaries:
                initialData.targetBeneficiaries ?? "",

            startDate:
                initialData.startDate
                    ? String(
                        initialData.startDate
                    ).substring(0, 10)
                    : "",

            endDate:
                initialData.endDate
                    ? String(
                        initialData.endDate
                    ).substring(0, 10)
                    : "",

            status:
                initialData.status ||
                "Planned"

        });

    }, [
        initialData
    ]);


    // =====================================================
    // CHANGE FIELD
    // =====================================================

    const changeField = (
        key,
        value
    ) => {

        setForm((prev) => ({

            ...prev,

            [key]: value

        }));

    };


    // =====================================================
    // SUBMIT
    // =====================================================

    const submitHandler = (event) => {

        event.preventDefault();


        const payload = {

            name:
                form.name.trim(),

            description:
                form.description.trim(),

            category:
                form.category.trim(),

            budget:
                form.budget === ""
                    ? 0
                    : Number(form.budget),

            targetBeneficiaries:
                form.targetBeneficiaries === ""
                    ? 0
                    : Number(
                        form.targetBeneficiaries
                    ),

            startDate:
                form.startDate || null,

            endDate:
                form.endDate || null,

            status:
                form.status

        };


        onSubmit(payload);

    };


    // =====================================================
    // RENDER
    // =====================================================

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
                PROGRAM INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Program Information"
                >

                    <FormGrid>


                        <AppTextField

                            label="Program Name"

                            required

                            value={
                                form.name
                            }

                            onChange={(event) =>
                                changeField(
                                    "name",
                                    event.target.value
                                )
                            }

                        />


                        <AppTextField

                            label="Category"

                            value={
                                form.category
                            }

                            onChange={(event) =>
                                changeField(
                                    "category",
                                    event.target.value
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

                            rows={4}

                            label="Description"

                            value={
                                form.description
                            }

                            onChange={(event) =>
                                changeField(
                                    "description",
                                    event.target.value
                                )
                            }

                        />

                    </Box>

                </FormSection>

            </PageCard>


            {/* =================================================
                PROGRAM TARGETS
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Program Targets"
                >

                    <FormGrid>


                        <AppTextField

                            type="number"

                            label="Budget"

                            value={
                                form.budget
                            }

                            onChange={(event) =>
                                changeField(
                                    "budget",
                                    event.target.value
                                )
                            }

                            inputProps={{
                                min: 0
                            }}

                        />


                        <AppTextField

                            type="number"

                            label="Target Beneficiaries"

                            value={
                                form.targetBeneficiaries
                            }

                            onChange={(event) =>
                                changeField(
                                    "targetBeneficiaries",
                                    event.target.value
                                )
                            }

                            inputProps={{
                                min: 0
                            }}

                        />


                    </FormGrid>

                </FormSection>

            </PageCard>


            {/* =================================================
                PROGRAM DATES
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Program Dates"
                >

                    <FormGrid>


                        <AppDatePicker

                            label="Start Date"

                            name="startDate"

                            value={
                                form.startDate
                            }

                            onChange={(newValue) => {

                                changeField(

                                    "startDate",

                                    newValue
                                        ? newValue.format(
                                            "YYYY-MM-DD"
                                        )
                                        : ""

                                );

                            }}

                        />


                        <AppDatePicker

                            label="End Date"

                            name="endDate"

                            value={
                                form.endDate
                            }

                            onChange={(newValue) => {

                                changeField(

                                    "endDate",

                                    newValue
                                        ? newValue.format(
                                            "YYYY-MM-DD"
                                        )
                                        : ""

                                );

                            }}

                        />


                    </FormGrid>

                </FormSection>

            </PageCard>


            {/* =================================================
                STATUS
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Program Status"
                >

                    <FormGrid
                        columns={1}
                    >

                        <AppSelect

                            label="Status"

                            value={
                                form.status
                            }

                            placeholder="Select Status"

                            options={[

                                {
                                    value: "Planned",
                                    label: "Planned"
                                },

                                {
                                    value: "Active",
                                    label: "Active"
                                },

                                {
                                    value: "Completed",
                                    label: "Completed"
                                },

                                {
                                    value: "Suspended",
                                    label: "Suspended"
                                },

                                {
                                    value: "Cancelled",
                                    label: "Cancelled"
                                }

                            ]}

                            onChange={(event) =>
                                changeField(
                                    "status",
                                    event.target.value
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

                    disabled={
                        loading
                    }

                >

                    {
                        loading
                            ? "Saving..."
                            : "Save Program"
                    }

                </AppButton>

            </FormActions>


        </Box>

    );

};


export default ProgramForm;