import {
    useEffect,
    useState
} from "react";


import {
    useDispatch,
    useSelector
} from "react-redux";


import {
    useNavigate,
    useParams
} from "react-router-dom";


import {
    Box,
    Alert
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


import {
    createEnterpriseMemberThunk
} from "../store/enterpriseMemberThunks";


import {
    getBeneficiariesThunk
} from "../../beneficiaries/store/beneficiaryThunks";


// =====================================================
// CREATE ENTERPRISE MEMBER
// =====================================================

const EnterpriseMemberCreatePage = () => {

    const dispatch =
        useDispatch();


    const navigate =
        useNavigate();


    // =================================================
    // ROUTE
    // =================================================

    const {
        enterpriseId
    } = useParams();


    // =================================================
    // FORM
    // =================================================

    const [
        form,
        setForm
    ] = useState({

        beneficiary: "",

        memberRole: "Member",

        joinedDate: ""

    });


    // =================================================
    // REDUX
    // =================================================

    const {
        actionLoading,
        error
    } =
        useSelector(
            state =>
                state.enterpriseMembers
        );


    const {
        beneficiaries = []
    } =
        useSelector(
            state =>
                state.beneficiaries
        );


    // =================================================
    // LOAD BENEFICIARIES
    // =================================================

    useEffect(() => {

        dispatch(
            getBeneficiariesThunk({

                page: 1,

                limit: 1000

            })
        );

    }, [
        dispatch
    ]);


    // =================================================
    // HANDLE CHANGE
    // =================================================

    const handleChange = (
        field,
        value
    ) => {

        setForm(
            previous => ({

                ...previous,

                [field]:
                    value

            })
        );

    };


    // =================================================
    // BENEFICIARY OPTIONS
    // =================================================

    const beneficiaryOptions =

        Array.isArray(
            beneficiaries
        )

            ? beneficiaries

                .filter(
                    beneficiary =>
                        beneficiary?._id
                )

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
                                beneficiary._id,

                            label:
                                fullName ||

                                beneficiary?.phone ||

                                beneficiary?.email ||

                                beneficiary._id

                        };

                    }
                )

                .filter(
                    item =>
                        item.value &&
                        item.label
                )

            : [];


    // =================================================
    // SUBMIT
    // =================================================

    const handleSubmit = async (
        event
    ) => {

        event.preventDefault();


        // =================================================
        // VALIDATE ENTERPRISE
        // =================================================

        if (
            !enterpriseId
        ) {

            console.error(
                "EnterpriseMemberCreatePage: enterpriseId is missing"
            );

            return;

        }


        // =================================================
        // VALIDATE BENEFICIARY
        // =================================================

        if (
            !form.beneficiary
        ) {

            return;

        }


        // =================================================
        // BUILD PAYLOAD
        // =================================================

        const payload = {

            enterprise:
                String(
                    enterpriseId
                ).trim(),

            beneficiary:
                String(
                    form.beneficiary
                ).trim(),

            memberRole:
                form.memberRole
                    ? String(
                        form.memberRole
                    ).trim()
                    : "Member",

            joinedDate:
                form.joinedDate
                    ? form.joinedDate
                    : null

        };


        // =================================================
        // DEBUG
        // =================================================



        // =================================================
        // CREATE
        // =================================================

        const result =
            await dispatch(

                createEnterpriseMemberThunk(
                    payload
                )

            );


        // =================================================
        // SUCCESS
        // =================================================

        if (
            createEnterpriseMemberThunk.fulfilled.match(
                result
            )
        ) {

            navigate(
                `/enterprises/${enterpriseId}/members`
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
                ERROR
            ================================================= */}

            {
                error && (

                    <Alert
                        severity="error"
                        sx={{
                            mb: 2
                        }}
                    >

                        {
                            typeof error === "object"

                                ? (
                                    error.message ||
                                    "Failed to create enterprise member"
                                )

                                : error
                        }

                    </Alert>

                )
            }


            {/* =================================================
                MEMBER INFORMATION
            ================================================= */}

            <PageCard>

                <FormSection
                    title="Add Enterprise Member"
                >

                    <FormGrid>

                        {/* =====================================
                            BENEFICIARY
                        ===================================== */}

                        <AppSelect

                            label="Beneficiary"

                            required

                            value={
                                form.beneficiary
                            }

                            placeholder="Select Beneficiary"

                            options={
                                beneficiaryOptions
                            }

                            onChange={
                                event =>
                                    handleChange(
                                        "beneficiary",
                                        event.target.value
                                    )
                            }

                        />


                        {/* =====================================
                            MEMBER ROLE
                        ===================================== */}

                        <AppTextField

                            label="Member Role"

                            placeholder="Enter member role"

                            value={
                                form.memberRole
                            }

                            onChange={
                                event =>
                                    handleChange(
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

                                    handleChange(

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

                    </FormGrid>

                </FormSection>

            </PageCard>


            {/* =================================================
                ACTIONS
            ================================================= */}

            <FormActions>

                <AppButton

                    type="button"

                    variant="outlined"

                    onClick={() =>
                        navigate(
                            `/enterprises/${enterpriseId}/members`
                        )
                    }

                >
                    Cancel
                </AppButton>


                <AppButton

                    type="submit"

                    variant="contained"

                    disabled={
                        actionLoading ||
                        !enterpriseId ||
                        !form.beneficiary
                    }

                >

                    {
                        actionLoading

                            ? "Adding..."

                            : "Add Member"
                    }

                </AppButton>

            </FormActions>

        </Box>

    );

};


export default EnterpriseMemberCreatePage;
