import {
    useEffect,
    useState
} from "react";


import {
    useParams,
    useNavigate
} from "react-router-dom";


import {
    useDispatch,
    useSelector
} from "react-redux";


import {
    ArrowBack
} from "@mui/icons-material";


import {
    PageContainer,
    PageHeader,
    PageCard,
    LoadingState
} from "../../../components/ui";


import ProgramForm
from "../components/ProgramForm";


import {
    updateProgramThunk,
    getProgramsThunk
} from "../store";


import {
    getProgramByIdService
} from "../services/programService";



const ProgramEditPage = () => {


    const {
        id
    } = useParams();


    const navigate = useNavigate();

    const dispatch = useDispatch();


    const {
        loading,
        error
    } = useSelector(
        state => state.programs
    );


    const [
        program,
        setProgram
    ] = useState(null);


    const [
        loadError,
        setLoadError
    ] = useState("");



    // =====================================================
    // LOAD PROGRAM
    // =====================================================

    useEffect(() => {

        const loadProgram = async () => {

            try {

                setLoadError("");

                const response =
                    await getProgramByIdService(id);


                const data =
                    response?.data?.data ||
                    response?.data ||
                    response;


                if (!data?._id) {

                    throw new Error(
                        "Program data was not found"
                    );

                }


                setProgram(data);

            }

            catch (error) {

                console.error(
                    "LOAD PROGRAM ERROR:",
                    error
                );


                setLoadError(
                    error.response?.data?.message ||
                    error.message ||
                    "Failed to load program"
                );

            }

        };


        if (id) {
            loadProgram();
        }

    }, [id]);



    // =====================================================
    // SAVE PROGRAM
    // =====================================================

    const save = async (data) => {

        try {

            const result =
                await dispatch(
                    updateProgramThunk({
                        id,
                        data
                    })
                );


            // =============================================
            // UPDATE FAILED
            // =============================================

            if (
                updateProgramThunk.rejected.match(
                    result
                )
            ) {

                console.error(
                    "UPDATE PROGRAM ERROR:",
                    result.payload ||
                    result.error
                );

                return;

            }


            // =============================================
            // UPDATE SUCCESS
            // =============================================

            if (
                updateProgramThunk.fulfilled.match(
                    result
                )
            ) {

                /*
                 * Reload the programs list BEFORE
                 * navigating back to the list page.
                 *
                 * This prevents the list page from
                 * rendering stale/invalid data.
                 */

                await dispatch(
                    getProgramsThunk({
                        search: "",
                        page: 1,
                        limit: 10
                    })
                );


                /*
                 * Now navigate after Redux has
                 * received the fresh program list.
                 */

                navigate(
                    "/programs",
                    {
                        replace: true
                    }
                );

            }

        }

        catch (error) {

            console.error(
                "UPDATE PROGRAM ERROR:",
                error
            );

        }

    };



    // =====================================================
    // LOADING
    // =====================================================

    if (!program) {

        return (

            <PageContainer>

                <PageCard>

                    {
                        loadError

                            ?

                            <div>
                                {loadError}
                            </div>

                            :

                            <LoadingState
                                message="Loading program..."
                            />
                    }

                </PageCard>

            </PageContainer>

        );

    }



    // =====================================================
    // RENDER
    // =====================================================

    return (

        <PageContainer>


            <PageHeader

                title="Edit Program"

                subtitle={
                    program.name
                }

                action={() =>
                    navigate(
                        "/programs"
                    )
                }

                actionLabel="Back"

                actionIcon={
                    <ArrowBack />
                }

            />


            <PageCard>


                {
                    error && (

                        <p
                            style={{
                                color: "red"
                            }}
                        >
                            {error}
                        </p>

                    )
                }


                <ProgramForm

                    initialData={
                        program
                    }

                    onSubmit={
                        save
                    }

                    loading={
                        loading
                    }

                />


            </PageCard>


        </PageContainer>

    );

};


export default ProgramEditPage;