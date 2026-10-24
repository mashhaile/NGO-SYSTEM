import {
    CURRENCIES,
    CURRENCY_NAMES
} from "../../budgets/utils/budgetUtils";

import {
    useEffect,
    useMemo,
    useState
} from "react";

import {
    Box,
    TextField
} from "@mui/material";

import {
    PageCard,
    FormSection,
    FormGrid,
    FormActions,
    AppSelect,
    AppDatePicker,
    AppButton
} from "../../../components/ui";


// =====================================================
// DEFAULT FORM
// =====================================================

const defaultForm = {

    donor: "",
    program: "",
    project: "",
    activity: "",
    activityRun: "",

    title: "",
    amount: "",

    currency: "USD",
    // another currency than ETB: 1 unit = ? ETB on the day it was received
    receivedRate: "",
    receivedRateDate: "",
    donationDate: "",
    financialYear: "",

    fundingSource: "Donation",
    fundingRestriction: "Unrestricted",
    donationType: "Cash",
    status: "Received",

    receiptNumber: "",
    referenceNumber: "",
    description: ""

};


// =====================================================
// NORMALIZE OPTIONS
// =====================================================

const normalizeOptions = (items) => {

    if (!Array.isArray(items)) {
        return [];
    }

    return items
        .filter(Boolean)
        .map((item) => {

            const id =
                item?._id ??
                item?.id ??
                item?.value ??
                "";

            const label =
                item?.name ??
                item?.label ??
                item?.value ??
                item?.text ??
                item?.title ??
                "";

            return {
                value: String(id),
                label: String(label)
            };

        })
        .filter(
            (item) =>
                item.value &&
                item.label
        );

};


// =====================================================
// NORMALIZE VALUE
// =====================================================

const normalizeValue = (value) => {

    if (!value) {
        return "";
    }

    if (typeof value === "object") {

        return String(
            value?._id ??
            value?.id ??
            ""
        );

    }

    return String(value);

};

// =====================================================
// GET RELATED ID
// =====================================================

const getRelatedId = (
    item,
    field
) => {

    if (!item) {
        return "";
    }


    // -----------------------------------------
    // Direct relationship
    // -----------------------------------------

    const directValue =
        item?.[field];


    const directId =
        normalizeValue(
            directValue
        );


    if (directId) {
        return directId;
    }


    // -----------------------------------------
    // Relationship ID
    //
    // Examples:
    // programId
    // projectId
    // activityId
    // -----------------------------------------

    const idValue =
        item?.[
            `${field}Id`
        ];


    const id =
        normalizeValue(
            idValue
        );


    if (id) {
        return id;
    }


    // -----------------------------------------
    // Common lookup aliases
    // -----------------------------------------

    const aliases = {

        program: [
            "program",
            "programId",
            "program_id"
        ],

        project: [
            "project",
            "projectId",
            "project_id"
        ],

        activity: [
            "activity",
            "activityId",
            "activity_id"
        ]

    };


    const fields =
        aliases[field] || [];


    for (
        const alias of fields
    ) {

        const value =
            normalizeValue(
                item?.[alias]
            );


        if (value) {
            return value;
        }

    }


    return "";
};


// =====================================================
// DONATION FORM
// =====================================================

const DonationForm = ({

    initialData = {},

    donors = [],
    programs = [],
    projects = [],
    activities = [],
    activityRuns = [],

    onSubmit,

    loading = false

}) => {

    const [
        form,
        setForm
    ] = useState(defaultForm);


    // =================================================
    // EDIT MODE
    // =================================================

    useEffect(() => {

        if (!initialData?._id) {
            return;
        }

        setForm({

            donor:
                normalizeValue(
                    initialData.donor
                ),

            program:
                normalizeValue(
                    initialData.program
                ),

            project:
                normalizeValue(
                    initialData.project
                ),

            activity:
                normalizeValue(
                    initialData.activity
                ),

            activityRun:
                normalizeValue(
                    initialData.activityRun
                ),

            title:
                initialData.title || "",

            amount:
                initialData.amount ?? "",

            currency:
                initialData.currency || "USD",
            receivedRate:
                initialData.receivedRate ? String(initialData.receivedRate) : "",
            receivedRateDate:
                initialData.receivedRateDate ? String(initialData.receivedRateDate).slice(0, 10) : "",

            donationDate:
                initialData.donationDate
                    ? String(
                        initialData.donationDate
                    ).substring(0, 10)
                    : "",

            financialYear:
                initialData.financialYear || "",

            fundingSource:
                initialData.fundingSource ||
                "Donation",

            fundingRestriction:
                initialData.fundingRestriction ||
                "Unrestricted",

            donationType:
                initialData.donationType ||
                "Cash",

            status:
                initialData.status ||
                "Received",

            receiptNumber:
                initialData.receiptNumber || "",

            referenceNumber:
                initialData.referenceNumber || "",

            description:
                initialData.description || ""

        });

    }, [initialData]);


    // =================================================
    // FILTER PROJECTS BY PROGRAM
    // =================================================

    const filteredProjects =
        useMemo(() => {

            if (!form.program) {
                return [];
            }

            return projects.filter(
                (project) => {

                    const projectProgram =
                        getRelatedId(
                            project,
                            "program"
                        );

                    return (
                        projectProgram ===
                        form.program
                    );

                }
            );

        }, [
            projects,
            form.program
        ]);


    // =================================================
    // FILTER ACTIVITIES BY PROJECT
    // =================================================

    const filteredActivities =
        useMemo(() => {

            if (!form.project) {
                return [];
            }

            return activities.filter(
                (activity) => {

                    const activityProject =
                        getRelatedId(
                            activity,
                            "project"
                        );

                    return (
                        activityProject ===
                        form.project
                    );

                }
            );

        }, [
            activities,
            form.project
        ]);


    // =================================================
    // FILTER ACTIVITY RUNS BY ACTIVITY
    // =================================================

    const filteredActivityRuns =
        useMemo(() => {

            if (!form.activity) {
                return [];
            }

            return activityRuns.filter(
                (activityRun) => {

                    const runActivity =
                        getRelatedId(
                            activityRun,
                            "activity"
                        );

                    return (
                        runActivity ===
                        form.activity
                    );

                }
            );

        }, [
            activityRuns,
            form.activity
        ]);


    // =================================================
    // OPTIONS
    // =================================================

    const donorOptions =
        useMemo(
            () =>
                normalizeOptions(
                    donors
                ),
            [donors]
        );


    const programOptions =
        useMemo(
            () =>
                normalizeOptions(
                    programs
                ),
            [programs]
        );


    const projectOptions =
        useMemo(
            () =>
                normalizeOptions(
                    filteredProjects
                ),
            [filteredProjects]
        );


    const activityOptions =
        useMemo(
            () =>
                normalizeOptions(
                    filteredActivities
                ),
            [filteredActivities]
        );


    const activityRunOptions =
        useMemo(
            () =>
                normalizeOptions(
                    filteredActivityRuns
                ),
            [filteredActivityRuns]
        );


    // =================================================
    // STATIC OPTIONS
    // =================================================

    // the shared currency list (with CHF, Swiss Franc)
    const currencyOptions =
        CURRENCIES.map(code => ({ value: code, label: `${code} - ${CURRENCY_NAMES[code] || code}` }));


    const fundingSourceOptions = [

        {
            value: "Grant",
            label: "Grant"
        },

        {
            value: "Donation",
            label: "Donation"
        },

        {
            value: "Government Funding",
            label: "Government Funding"
        },

        {
            value: "Corporate CSR",
            label: "Corporate CSR"
        },

        {
            value: "Internal",
            label: "Internal"
        },

        {
            value: "Other",
            label: "Other"
        }

    ];


    const fundingRestrictionOptions = [

        {
            value: "Restricted",
            label: "Restricted"
        },

        {
            value: "Unrestricted",
            label: "Unrestricted"
        }

    ];


    const donationTypeOptions = [

        {
            value: "Cash",
            label: "Cash"
        },

        {
            value: "Bank Transfer",
            label: "Bank Transfer"
        },

        {
            value: "Material",
            label: "Material"
        },

        {
            value: "Equipment",
            label: "Equipment"
        },

        {
            value: "Service",
            label: "Service"
        },

        {
            value: "Other",
            label: "Other"
        }

    ];


    const statusOptions = [

        {
            value: "Pledged",
            label: "Pledged"
        },

        {
            value: "Received",
            label: "Received"
        },

        {
            value: "Cancelled",
            label: "Cancelled"
        }

    ];


    // =================================================
    // CHANGE FIELD
    // =================================================

    const changeField = (
        field,
        value
    ) => {

        setForm(
            previous => {

                // -----------------------------------------
                // PROGRAM CHANGED
                // -----------------------------------------

                if (field === "program") {

                    return {

                        ...previous,

                        program:
                            value,

                        project:
                            "",

                        activity:
                            "",

                        activityRun:
                            ""

                    };

                }


                // -----------------------------------------
                // PROJECT CHANGED
                // -----------------------------------------

                if (field === "project") {

                    return {

                        ...previous,

                        project:
                            value,

                        activity:
                            "",

                        activityRun:
                            ""

                    };

                }


                // -----------------------------------------
                // ACTIVITY CHANGED
                // -----------------------------------------

                if (field === "activity") {

                    return {

                        ...previous,

                        activity:
                            value,

                        activityRun:
                            ""

                    };

                }


                // -----------------------------------------
                // NORMAL FIELD
                // -----------------------------------------

                return {

                    ...previous,

                    [field]:
                        value

                };

            }
        );

    };


    // =================================================
    // SUBMIT
    // =================================================

    const handleSubmit = (
        event
    ) => {

        event.preventDefault();


        if (!form.donor) {

            alert(
                "Please select a donor."
            );

            return;

        }


        if (!form.title.trim()) {

            alert(
                "Please enter donation title."
            );

            return;

        }


        if (
            form.amount === "" ||
            Number(form.amount) <= 0
        ) {

            alert(
                "Please enter donation amount."
            );

            return;

        }


        if (!form.donationDate) {
            alert(
                "Please select donation date."
            );
            return;
        }


        if (
            form.currency !== "ETB" &&
            form.status === "Received" &&
            !(Number(form.receivedRate) > 0)
        ) {
            alert(
                `Please enter the exchange rate on the day this donation was received (1 ${form.currency} = ? ETB).`
            );
            return;
        }


        const payload = {

            donor:
                form.donor,

            program:
                form.program ||
                null,

            project:
                form.project ||
                null,

            activity:
                form.activity ||
                null,

            activityRun:
                form.activityRun ||
                null,

            title:
                form.title.trim(),

            amount:
                Number(form.amount),

            currency:
                form.currency,
            receivedRate:
                form.currency !== "ETB" && Number(form.receivedRate) > 0
                    ? Number(form.receivedRate)
                    : null,
            receivedRateDate:
                form.currency !== "ETB" && Number(form.receivedRate) > 0
                    ? form.receivedRateDate || form.donationDate
                    : null,
            donationDate:
                form.donationDate,

            financialYear:
                form.financialYear.trim() ||
                null,

            fundingSource:
                form.fundingSource,

            fundingRestriction:
                form.fundingRestriction,

            donationType:
                form.donationType,

            status:
                form.status,

            receiptNumber:
                form.receiptNumber.trim() ||
                null,

            referenceNumber:
                form.referenceNumber.trim() ||
                null,

            description:
                form.description.trim() ||
                null

        };


        if (
            typeof onSubmit ===
            "function"
        ) {

            onSubmit(
                payload
            );

        }

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
                DONATION INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Donation Information"
                >

                    <FormGrid>

                        {/* DONOR */}

                        <AppSelect
                            label="Donor"
                            required
                            value={
                                form.donor
                            }
                            placeholder="Select Donor"
                            options={
                                donorOptions
                            }
                            onChange={(
                                event
                            ) =>
                                changeField(
                                    "donor",
                                    event.target.value
                                )
                            }
                        />


                        {/* TITLE */}

                        <TextField
                            fullWidth
                            required
                            label="Donation Title"
                            value={
                                form.title
                            }
                            onChange={(
                                event
                            ) =>
                                changeField(
                                    "title",
                                    event.target.value
                                )
                            }
                        />


                        {/* PROGRAM */}

                        <AppSelect
                            label="Program"
                            value={
                                form.program
                            }
                            placeholder="No Program"
                            options={
                                programOptions
                            }
                            onChange={(
                                event
                            ) =>
                                changeField(
                                    "program",
                                    event.target.value
                                )
                            }
                        />


                        {/* PROJECT */}

                        <AppSelect
                            label="Project"
                            value={
                                form.project
                            }
                            placeholder={
                                form.program
                                    ? "Select Project"
                                    : "Select Program First"
                            }
                            options={
                                projectOptions
                            }
                            disabled={
                                !form.program
                            }
                            onChange={(
                                event
                            ) =>
                                changeField(
                                    "project",
                                    event.target.value
                                )
                            }
                        />


                        {/* ACTIVITY */}

                        <AppSelect
                            label="Activity"
                            value={
                                form.activity
                            }
                            placeholder={
                                form.project
                                    ? "Select Activity"
                                    : "Select Project First"
                            }
                            options={
                                activityOptions
                            }
                            disabled={
                                !form.project
                            }
                            onChange={(
                                event
                            ) =>
                                changeField(
                                    "activity",
                                    event.target.value
                                )
                            }
                        />


                        {/* ACTIVITY RUN */}

                        <AppSelect
                            label="Activity Run"
                            value={
                                form.activityRun
                            }
                            placeholder={
                                form.activity
                                    ? "Select Activity Run"
                                    : "Select Activity First"
                            }
                            options={
                                activityRunOptions
                            }
                            disabled={
                                !form.activity
                            }
                            onChange={(
                                event
                            ) =>
                                changeField(
                                    "activityRun",
                                    event.target.value
                                )
                            }
                        />

                    </FormGrid>

                </FormSection>

            </PageCard>


            {/* =================================================
                FINANCIAL INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Financial Information"
                >

                    <FormGrid>

                        <TextField
                            fullWidth
                            required
                            type="number"
                            label="Amount"
                            value={
                                form.amount
                            }
                            onChange={(
                                event
                            ) =>
                                changeField(
                                    "amount",
                                    event.target.value
                                )
                            }
                            slotProps={{
                                htmlInput: {
                                    min: 0,
                                    step: "0.01"
                                }
                            }}
                        />


                        <AppSelect
                            label="Currency"
                            value={
                                form.currency
                            }
                            options={
                                currencyOptions
                            }
                            onChange={(
                                event
                            ) =>
                                changeField(
                                    "currency",
                                    event.target.value
                                )
                            }
                        />


                        {form.currency !== "ETB" && (

                            <TextField
                                label={`Rate (1 ${form.currency} = ? ETB)`}
                                type="number"
                                required={form.status === "Received"}
                                value={form.receivedRate}
                                onChange={event => changeField("receivedRate", event.target.value)}
                                helperText={
                                    Number(form.receivedRate) > 0 && Number(form.amount) > 0
                                        ? `= ETB ${(Number(form.amount) * Number(form.receivedRate)).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}. The donor's figures stay in ${form.currency}.`
                                        : `The rate on the day it was received (its date is the donation date). The donor's figures stay in ${form.currency}; ETB totals use this rate.`
                                }
                                inputProps={{
                                    min: 0,
                                    step: "0.0001"
                                }}
                                fullWidth
                            />

                        )}


                        <AppDatePicker
                            label="Donation Date"
                            required
                            name="donationDate"
                            value={
                                form.donationDate ||
                                ""
                            }
                            onChange={(
                                newValue
                            ) => {

                                changeField(
                                    "donationDate",
                                    newValue
                                        ? newValue.format(
                                            "YYYY-MM-DD"
                                        )
                                        : ""
                                );

                            }}
                        />


                        <TextField
                            fullWidth
                            label="Financial Year"
                            value={
                                form.financialYear
                            }
                            onChange={(
                                event
                            ) =>
                                changeField(
                                    "financialYear",
                                    event.target.value
                                )
                            }
                        />

                    </FormGrid>

                </FormSection>

            </PageCard>


            {/* =================================================
                FUNDING INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Funding Information"
                >

                    <FormGrid>

                        <AppSelect
                            label="Funding Source"
                            value={
                                form.fundingSource
                            }
                            options={
                                fundingSourceOptions
                            }
                            onChange={(
                                event
                            ) =>
                                changeField(
                                    "fundingSource",
                                    event.target.value
                                )
                            }
                        />


                        <AppSelect
                            label="Funding Restriction"
                            value={
                                form.fundingRestriction
                            }
                            options={
                                fundingRestrictionOptions
                            }
                            onChange={(
                                event
                            ) =>
                                changeField(
                                    "fundingRestriction",
                                    event.target.value
                                )
                            }
                        />


                        <AppSelect
                            label="Donation Type"
                            value={
                                form.donationType
                            }
                            options={
                                donationTypeOptions
                            }
                            onChange={(
                                event
                            ) =>
                                changeField(
                                    "donationType",
                                    event.target.value
                                )
                            }
                        />

                    </FormGrid>

                </FormSection>

            </PageCard>


            {/* =================================================
                REFERENCE INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Reference Information"
                >

                    <FormGrid>

                        <TextField
                            fullWidth
                            label="Receipt Number"
                            value={
                                form.receiptNumber
                            }
                            onChange={(
                                event
                            ) =>
                                changeField(
                                    "receiptNumber",
                                    event.target.value
                                )
                            }
                        />


                        <TextField
                            fullWidth
                            label="Reference Number"
                            value={
                                form.referenceNumber
                            }
                            onChange={(
                                event
                            ) =>
                                changeField(
                                    "referenceNumber",
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

                        <TextField
                            fullWidth
                            multiline
                            rows={4}
                            label="Description"
                            value={
                                form.description
                            }
                            onChange={(
                                event
                            ) =>
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
                                form.status
                            }
                            options={
                                statusOptions
                            }
                            onChange={(
                                event
                            ) =>
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
                            : "Save Donation"
                    }

                </AppButton>

            </FormActions>

        </Box>

    );

};


export default DonationForm;
