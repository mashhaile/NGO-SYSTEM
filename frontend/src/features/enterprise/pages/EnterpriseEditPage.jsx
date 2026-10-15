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


import EnterpriseForm
    from "../components/EnterpriseForm";


import {
    getEnterpriseByIdThunk,
    updateEnterpriseThunk
} from "../store/enterpriseThunks";


import {
    clearEnterpriseMessage,
    clearSelectedEnterprise
} from "../store/enterpriseSlice";


import {
    getLookupsByModuleAndCategoryService
} from "../../lookups/services/lookupService";


import {
    PageContainer,
    PageHeader,
    LoadingState
} from "../../../components/ui";


// =========================================================
// INITIAL LOOKUPS
// =========================================================

const initialLookups = {

    enterpriseTypes: [],

    ownershipTypes: [],

    businessSectors: []

};


// =========================================================
// COMPONENT
// =========================================================

const EnterpriseEditPage = () => {

    const {
        id
    } = useParams();


    const navigate =
        useNavigate();


    const dispatch =
        useDispatch();


    const {
        selectedEnterprise,
        loading,
        actionLoading,
        error,
        successMessage
    } =
        useSelector(
            state =>
                state.enterprises
        );


    const [
        loadingLookups,
        setLoadingLookups
    ] = useState(true);


    const [
        lookups,
        setLookups
    ] = useState(
        initialLookups
    );


    // =====================================================
    // LOAD ENTERPRISE
    // =====================================================

    useEffect(() => {

        if (!id) {

            return;

        }


        dispatch(
            clearSelectedEnterprise()
        );


        dispatch(
            getEnterpriseByIdThunk(
                id
            )
        );

    }, [
        dispatch,
        id
    ]);


    // =====================================================
    // LOAD LOOKUPS
    // =====================================================

    useEffect(() => {

        let mounted = true;


        const loadLookups = async () => {

            try {

                setLoadingLookups(true);


                const [

                    enterpriseTypes,

                    ownershipTypes,

                    businessSectors

                ] = await Promise.all([

                    getLookupsByModuleAndCategoryService(
                        "Enterprise",
                        "EnterpriseType"
                    ),

                    getLookupsByModuleAndCategoryService(
                        "Enterprise",
                        "OwnershipType"
                    ),

                    getLookupsByModuleAndCategoryService(
                        "Enterprise",
                        "BusinessSector"
                    )

                ]);


                if (!mounted) {

                    return;

                }


                setLookups({

                    enterpriseTypes:
                        Array.isArray(
                            enterpriseTypes
                        )
                            ? enterpriseTypes
                            : [],


                    ownershipTypes:
                        Array.isArray(
                            ownershipTypes
                        )
                            ? ownershipTypes
                            : [],


                    businessSectors:
                        Array.isArray(
                            businessSectors
                        )
                            ? businessSectors
                            : []

                });

            }

            catch (error) {

                console.error(
                    "Failed to load enterprise lookups:",
                    error
                );


                if (mounted) {

                    setLookups(
                        initialLookups
                    );

                }

            }

            finally {

                if (mounted) {

                    setLoadingLookups(false);

                }

            }

        };


        loadLookups();


        return () => {

            mounted = false;

        };

    }, []);


    // =====================================================
    // UPDATE SUCCESS
    // =====================================================

    useEffect(() => {

        if (!successMessage) {

            return;

        }


        dispatch(
            clearEnterpriseMessage()
        );


        navigate(
            `/enterprises/${id}`
        );

    }, [
        successMessage,
        dispatch,
        navigate,
        id
    ]);


    // =====================================================
    // SUBMIT
    // =====================================================

    const handleSubmit = (
        data
    ) => {

        if (
            !id ||
            actionLoading
        ) {

            return;

        }


        dispatch(
            updateEnterpriseThunk({

                id,

                data

            })
        );

    };


    // =====================================================
    // LOADING
    // =====================================================

    if (
        loading ||
        loadingLookups
    ) {

        return (

            <PageContainer>

                <PageHeader
                    title="Edit Enterprise"
                    subtitle="Update enterprise information"
                />


                <LoadingState
                    message="Loading enterprise..."
                />

            </PageContainer>

        );

    }


    // =====================================================
    // NOT FOUND
    // =====================================================

    if (
        !selectedEnterprise
    ) {

        return (

            <PageContainer>

                <PageHeader
                    title="Edit Enterprise"
                    subtitle="Enterprise not found"
                />

            </PageContainer>

        );

    }


    // =====================================================
    // RENDER
    // =====================================================

    return (

        <PageContainer>

            <PageHeader
                title="Edit Enterprise"
                subtitle="Update enterprise information"
            />


            {
                error && (

                    <div
                        style={{
                            color: "red",
                            marginBottom: "16px"
                        }}
                    >

                        {
                            typeof error === "string"
                                ? error
                                : error?.message ||
                                  "Failed to update enterprise"
                        }

                    </div>

                )
            }


            <EnterpriseForm

                initialData={
                    selectedEnterprise
                }

                lookups={
                    lookups
                }

                onSubmit={
                    handleSubmit
                }

                loading={
                    actionLoading
                }

            />

        </PageContainer>

    );

};


export default EnterpriseEditPage;