import {
    useEffect,
    useState
} from "react";


// =====================================================
// INITIAL STATE
// =====================================================

const initialState = {

    enterprise: "",

    beneficiary: "",

    memberRole: "Member",

    joinedDate: "",

    leftDate: "",

    status: "Active"

};


// =====================================================
// HOOK
// =====================================================

const useEnterpriseMemberForm = ({

    initialData = null,

    onSubmit

}) => {


    const [
        form,
        setForm
    ] = useState({

        ...initialState

    });


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


        const enterpriseId =

            typeof initialData.enterprise === "object"

                ? initialData.enterprise?._id

                : initialData.enterprise;


        const beneficiaryId =

            typeof initialData.beneficiary === "object"

                ? initialData.beneficiary?._id

                : initialData.beneficiary;


        setForm({

            ...initialState,


            enterprise:

                enterpriseId || "",


            beneficiary:

                beneficiaryId || "",


            memberRole:

                initialData.memberRole ||

                "Member",


            joinedDate:

                initialData.joinedDate

                    ? String(

                        initialData.joinedDate

                    ).substring(0, 10)

                    : "",


            leftDate:

                initialData.leftDate

                    ? String(

                        initialData.leftDate

                    ).substring(0, 10)

                    : "",


            status:

                initialData.status ||

                "Active"

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

            [field]:

                value

        }));

    };


    // =================================================
    // SUBMIT
    // =================================================

    const submitHandler = (

        event

    ) => {

        event.preventDefault();


        if (!form.enterprise) {

            alert(
                "Please select an enterprise"
            );

            return;

        }


        if (!form.beneficiary) {

            alert(
                "Please select a beneficiary"
            );

            return;

        }


        const payload = {

            enterprise:
                form.enterprise,


            beneficiary:
                form.beneficiary,


            memberRole:
                form.memberRole || "Member",


            joinedDate:
                form.joinedDate || null,


            leftDate:
                form.leftDate || null,


            status:
                form.status || "Active"

        };


        onSubmit(payload);

    };


    // =================================================
    // RESET
    // =================================================

    const resetForm = () => {

        setForm({

            ...initialState

        });

    };


    // =================================================
    // RETURN
    // =================================================

    return {

        form,

        setForm,

        changeField,

        submitHandler,

        resetForm

    };

};


export default useEnterpriseMemberForm;