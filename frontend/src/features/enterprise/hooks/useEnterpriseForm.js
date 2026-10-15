import {
    useEffect,
    useState
} from "react";


const initialState = {

    name: "",

    description: "",

    enterpriseType: "",

    sector: "",

    businessStatus: "",

    startDate: "",

    country: "",

    region: "",

    zone: "",

    woreda: "",

    kebele: "",

    address: "",

    phone: "",

    alternativePhone: "",

    email: "",

    registrationNumber: "",

    capital: "",

    status: "Active"

};


const useEnterpriseForm = ({

    initialData = null,

    onSubmit

}) => {


    const [

        form,

        setForm

    ] = useState({

        ...initialState

    });



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

                initialData.name ||

                "",


            description:

                initialData.description ||

                "",


            enterpriseType:

                initialData.enterpriseType?._id ||

                initialData.enterpriseType ||

                "",


            sector:

                initialData.sector?._id ||

                initialData.sector ||

                "",


            businessStatus:

                initialData.businessStatus?._id ||

                initialData.businessStatus ||

                "",


            startDate:

                initialData.startDate

                    ? String(

                        initialData.startDate

                    ).substring(0, 10)

                    : "",


            country:

                initialData.country ||

                "",


            region:

                initialData.region ||

                "",


            zone:

                initialData.zone ||

                "",


            woreda:

                initialData.woreda ||

                "",


            kebele:

                initialData.kebele ||

                "",


            address:

                initialData.address ||

                "",


            phone:

                initialData.phone ||

                "",


            alternativePhone:

                initialData.alternativePhone ||

                "",


            email:

                initialData.email ||

                "",


            registrationNumber:

                initialData.registrationNumber ||

                "",


            capital:

                initialData.capital ?? "",


            status:

                initialData.status ||

                "Active"

        });

    }, [

        initialData

    ]);



    const changeField = (

        key,

        value

    ) => {

        setForm((prev) => ({

            ...prev,

            [key]: value

        }));

    };



    const submitHandler = (

        event

    ) => {

        event.preventDefault();



        if (!form.name.trim()) {

            alert(

                "Enterprise name is required"

            );

            return;

        }



        const payload = {

            name:

                form.name.trim(),


            description:

                form.description,


            enterpriseType:

                form.enterpriseType ||

                null,


            sector:

                form.sector ||

                null,


            businessStatus:

                form.businessStatus ||

                null,


            startDate:

                form.startDate ||

                null,


            country:

                form.country,


            region:

                form.region,


            zone:

                form.zone,


            woreda:

                form.woreda,


            kebele:

                form.kebele,


            address:

                form.address,


            phone:

                form.phone,


            alternativePhone:

                form.alternativePhone,


            email:

                form.email,


            registrationNumber:

                form.registrationNumber,


            capital:

                form.capital === ""

                    ? null

                    : Number(

                        form.capital

                    ),


            status:

                form.status

        };



        onSubmit(payload);

    };



    const resetForm = () => {

        setForm({

            ...initialState

        });

    };



    return {

        form,

        setForm,

        changeField,

        submitHandler,

        resetForm

    };

};


export default useEnterpriseForm;