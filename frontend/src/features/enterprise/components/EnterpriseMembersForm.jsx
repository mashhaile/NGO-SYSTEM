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
    AppSelect,
    AppDatePicker,
    AppButton
} from "../../../components/ui";


import useEnterpriseMemberForm
    from "../hooks/useEnterpriseMemberForm";


// =====================================================
// ENTERPRISE MEMBER FORM
// =====================================================

const EnterpriseMemberForm = ({
    onSubmit,
    initialData = null,
    enterprises = [],
    beneficiaries = []
}) => {


    const {
        form,
        changeField,
        submitHandler
    } =
        useEnterpriseMemberForm({
            initialData,
            onSubmit
        });


    // =================================================
    // ENTERPRISE OPTIONS
    // =================================================

    const enterpriseOptions =
        useMemo(() => {

            if (
                !Array.isArray(
                    enterprises
                )
            ) {

                return [];

            }


            return enterprises

                .filter(Boolean)

                .map(
                    enterprise => ({

                        value:
                            enterprise?._id,

                        label:
                            enterprise?.name ||

                            enterprise?.enterpriseNumber ||

                            "Enterprise"

                    })
                )

                .filter(
                    item =>
                        item.value &&
                        item.label
                );

        }, [
            enterprises
        ]);


    // =================================================
    // BENEFICIARY OPTIONS
    // =================================================

    const beneficiaryOptions =
        useMemo(() => {

            if (
                !Array.isArray(
                    beneficiaries
                )
            ) {

                return [];

            }


            return beneficiaries

                .filter(Boolean)

                .map(
                    beneficiary => {

                        const fullName = [

                            beneficiary?.firstName,

                            beneficiary?.middleName,

                            beneficiary?.lastName

                        ]
                            .filter(Boolean)
                            .join(" ");


                        return {

                            value:
                                beneficiary?._id,

                            label:
                                fullName ||

                                beneficiary?.beneficiaryNumber ||

                                beneficiary?.phone ||

                                beneficiary?.email ||

                                "Beneficiary"

                        };

                    }
                )

                .filter(
                    item =>
                        item.value &&
                        item.label
                );

        }, [
            beneficiaries
        ]);


    // =================================================
    // MEMBER ROLE OPTIONS
    // =================================================
    //
    // Must match EnterpriseMember schema exactly.
    //
    // =================================================

    const memberRoleOptions = [

        {
            value:
                "Member",

            label:
                "Member"
        },

        {
            value:
                "Partner",

            label:
                "Partner"
        },

        {
            value:
                "Shareholder",

            label:
                "Shareholder"
        },

        {
            value:
                "Manager",

            label:
                "Manager"
        },

        {
            value:
                "Employee",

            label:
                "Employee"
        }

    ];


    // =================================================
    // STATUS OPTIONS
    // =================================================

    const statusOptions = [

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

    ];


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
                width:
                    "100%"
            }}
        >

            {/* =================================================
                MEMBERSHIP INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Enterprise Membership"
                >

                    <FormGrid>

                        {/* =====================================
                            ENTERPRISE
                        ===================================== */}

                        <AppSelect
                            label="Enterprise"
                            required
                            value={
                                form.enterprise || ""
                            }
                            placeholder="Select Enterprise"
                            options={
                                enterpriseOptions
                            }
                            onChange={
                                event =>
                                    changeField(
                                        "enterprise",
                                        event.target.value
                                    )
                            }
                        />


                        {/* =====================================
                            BENEFICIARY
                        ===================================== */}

                        <AppSelect
                            label="Beneficiary"
                            required
                            value={
                                form.beneficiary || ""
                            }
                            placeholder="Select Beneficiary"
                            options={
                                beneficiaryOptions
                            }
                            onChange={
                                event =>
                                    changeField(
                                        "beneficiary",
                                        event.target.value
                                    )
                            }
                        />


                        {/* =====================================
                            MEMBER ROLE
                        ===================================== */}

                        <AppSelect
                            label="Member Role"
                            required
                            value={
                                form.memberRole ||
                                "Member"
                            }
                            placeholder="Select Member Role"
                            options={
                                memberRoleOptions
                            }
                            onChange={
                                event =>
                                    changeField(
                                        "memberRole",
                                        event.target.value
                                    )
                            }
                        />


                        {/* =====================================
                            JOINED DATE
                        ===================================== */}

                        <AppDatePicker
                            label="Joined Date"
                            name="joinedDate"
                            value={
                                form.joinedDate ||
                                null
                            }
                            onChange={
                                newValue => {

                                    changeField(

                                        "joinedDate",

                                        newValue
                                            ? newValue.format(
                                                "YYYY-MM-DD"
                                            )
                                            : ""

                                    );

                                }
                            }
                        />


                        {/* =====================================
                            LEFT DATE
                        ===================================== */}

                        <AppDatePicker
                            label="Left Date"
                            name="leftDate"
                            value={
                                form.leftDate ||
                                null
                            }
                            onChange={
                                newValue => {

                                    changeField(

                                        "leftDate",

                                        newValue
                                            ? newValue.format(
                                                "YYYY-MM-DD"
                                            )
                                            : ""

                                    );

                                }
                            }
                        />


                        {/* =====================================
                            STATUS
                        ===================================== */}

                        <AppSelect
                            label="Status"
                            value={
                                form.status ||
                                "Active"
                            }
                            placeholder="Select Status"
                            options={
                                statusOptions
                            }
                            onChange={
                                event =>
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
                >
                    Save Member
                </AppButton>

            </FormActions>

        </Box>

    );

};


export default EnterpriseMemberForm;
