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
    AppDatePicker,
    AppButton
} from "../../../components/ui";


import {
    getEnterpriseMemberByIdThunk,
    updateEnterpriseMemberThunk
} from "../store/enterpriseMemberThunks";


// =====================================================
// ENTERPRISE MEMBER EDIT PAGE
// =====================================================

const EnterpriseMemberEditPage = () => {

    const dispatch =
        useDispatch();


    const navigate =
        useNavigate();


    const {
        enterpriseId,
        memberId,
        id
    } = useParams();


    // =====================================================
    // MEMBER ID
    // =====================================================

    const memberIdentifier =
        memberId || id;


    // =====================================================
    // FORM
    // =====================================================

    const [
        form,
        setForm
    ] = useState({

        beneficiary: "",

        memberRole: "",

        joinedDate: "",

        leftDate: "",

        status: "Active"

    });


    // =====================================================
    // REDUX
    // =====================================================

    const {

        selectedMember = null,

        loading = false,

        actionLoading = false,

        error = null

    } = useSelector(

        state =>
            state.enterpriseMembers || {}

    );


    // =====================================================
    // LOAD MEMBER
    // =====================================================

    useEffect(() => {

        if (!memberIdentifier) {

            return;

        }


        dispatch(

            getEnterpriseMemberByIdThunk(
                memberIdentifier
            )

        );

    }, [

        dispatch,

        memberIdentifier

    ]);


    // =====================================================
    // LOAD MEMBER INTO FORM
    // =====================================================

    useEffect(() => {

        if (!selectedMember) {

            return;

        }


        const beneficiary =
            selectedMember?.beneficiary;


        setForm({

            beneficiary:

                typeof beneficiary === "object"

                    ? (
                        beneficiary?._id ||
                        beneficiary?.id ||
                        ""
                    )

                    : (
                        beneficiary ||
                        ""
                    ),


            memberRole:

                typeof selectedMember?.memberRole === "object"

                    ? (
                        selectedMember.memberRole?.value ||
                        selectedMember.memberRole?.label ||
                        selectedMember.memberRole?.name ||
                        ""
                    )

                    : (
                        selectedMember?.memberRole ||
                        ""
                    ),


            joinedDate:

                selectedMember?.joinedDate

                    ? String(
                        selectedMember.joinedDate
                    ).substring(
                        0,
                        10
                    )

                    : "",


            leftDate:

                selectedMember?.leftDate

                    ? String(
                        selectedMember.leftDate
                    ).substring(
                        0,
                        10
                    )

                    : "",


            status:

                typeof selectedMember?.status === "object"

                    ? (
                        selectedMember.status?.value ||
                        selectedMember.status?.label ||
                        selectedMember.status?.name ||
                        "Active"
                    )

                    : (
                        selectedMember?.status ||
                        "Active"
                    )

        });

    }, [
        selectedMember
    ]);


    // =====================================================
    // CHANGE FIELD
    // =====================================================

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


    // =====================================================
    // SUBMIT
    // =====================================================

    const handleSubmit = async (
        event
    ) => {

        event.preventDefault();


        if (!memberIdentifier) {

            return;

        }


        if (!form.beneficiary) {

            return;

        }


        const payload = {

            beneficiary:
                form.beneficiary,

            memberRole:
                form.memberRole.trim() || null,

            joinedDate:
                form.joinedDate || null,

            leftDate:
                form.leftDate || null,

            status:
                form.status || "Active"

        };


        const result =
            await dispatch(

                updateEnterpriseMemberThunk({

                    id:
                        memberIdentifier,

                    data:
                        payload

                })

            );


        if (
            updateEnterpriseMemberThunk.fulfilled.match(
                result
            )
        ) {

            const targetEnterpriseId =

                enterpriseId ||

                (
                    typeof selectedMember?.enterprise === "object"

                        ? (
                            selectedMember.enterprise?._id ||
                            selectedMember.enterprise?.id
                        )

                        : selectedMember?.enterprise
                );


            if (targetEnterpriseId) {

                navigate(
                    `/enterprises/${targetEnterpriseId}/members/${memberIdentifier}`
                );

            } else {

                navigate(
                    `/enterprise-members/${memberIdentifier}`
                );

            }

        }

    };


    // =====================================================
    // BENEFICIARY DISPLAY NAME
    // =====================================================

    const beneficiary =
        selectedMember?.beneficiary;


    const beneficiaryName =

        typeof beneficiary === "object"

            ? (

                [
                    beneficiary?.firstName,
                    beneficiary?.middleName,
                    beneficiary?.lastName

                ]
                    .filter(Boolean)
                    .join(" ")

                ||

                beneficiary?.phone

                ||

                beneficiary?.email

                ||

                beneficiary?.beneficiaryNumber

                ||

                beneficiary?._id

                ||

                ""

            )

            : (

                beneficiary || ""

            );


    // =====================================================
    // ENTERPRISE
    // =====================================================

    const enterprise =
        selectedMember?.enterprise;


    const enterpriseName =

        typeof enterprise === "object"

            ? (

                enterprise?.name ||

                enterprise?.enterpriseNumber ||

                ""

            )

            : (

                enterprise || ""

            );


    // =====================================================
    // LOADING
    // =====================================================

    if (
        loading &&
        !selectedMember
    ) {

        return (

            <Box
                sx={{
                    width: "100%",
                    p: 3
                }}
            >

                Loading enterprise member...

            </Box>

        );

    }


    // =====================================================
    // NO MEMBER
    // =====================================================

    if (
        !loading &&
        !selectedMember
    ) {

        return (

            <Box
                sx={{
                    width: "100%"
                }}
            >

                <Alert
                    severity="error"
                    sx={{
                        mb: 2
                    }}
                >

                    Enterprise member not found.

                </Alert>


                <AppButton
                    variant="outlined"
                    onClick={() =>
                        navigate(
                            "/enterprise-members"
                        )
                    }
                >

                    Back to Enterprise Members

                </AppButton>

            </Box>

        );

    }


    // =====================================================
    // RENDER
    // =====================================================

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
                                    "Failed to update enterprise member."
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
                    title="Edit Enterprise Member"
                >

                    <FormGrid>


                        {/* =====================================
                            ENTERPRISE
                        ===================================== */}

                        <AppTextField

                            label="Enterprise"

                            value={
                                enterpriseName
                            }

                            InputProps={{
                                readOnly: true
                            }}

                        />


                        {/* =====================================
                            BENEFICIARY
                        ===================================== */}

                        <AppTextField

                            label="Beneficiary"

                            value={
                                beneficiaryName
                            }

                            InputProps={{
                                readOnly: true
                            }}

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

                            onChange={(e) =>
                                handleChange(
                                    "memberRole",
                                    e.target.value
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

                                    handleChange(

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

                        <AppTextField

                            label="Status"

                            value={
                                form.status
                            }

                            InputProps={{
                                readOnly: true
                            }}

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

                    onClick={() => {

                        const targetEnterpriseId =

                            enterpriseId ||

                            (
                                typeof selectedMember?.enterprise === "object"

                                    ? (
                                        selectedMember.enterprise?._id ||
                                        selectedMember.enterprise?.id
                                    )

                                    : selectedMember?.enterprise
                            );


                        if (targetEnterpriseId) {

                            navigate(
                                `/enterprises/${targetEnterpriseId}/members/${memberIdentifier}`
                            );

                        } else {

                            navigate(
                                "/enterprise-members"
                            );

                        }

                    }}

                >

                    Cancel

                </AppButton>


                <AppButton

                    type="submit"

                    variant="contained"

                    disabled={

                        actionLoading ||

                        !memberIdentifier ||

                        !form.beneficiary

                    }

                >

                    {
                        actionLoading

                            ? "Saving..."

                            : "Save Changes"
                    }

                </AppButton>


            </FormActions>

        </Box>

    );

};


export default EnterpriseMemberEditPage;