import {
    useEffect,
    useState
} from "react";

import {
    useDispatch,
    useSelector
} from "react-redux";

import {
    useNavigate
} from "react-router-dom";


import EnterpriseForm
    from "../components/EnterpriseForm";


import {
    createEnterpriseThunk
} from "../store/enterpriseThunks";


import {
    clearEnterpriseMessage
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

const EnterpriseCreatePage = () => {

    const dispatch =
        useDispatch();


    const navigate =
        useNavigate();


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


    const {
        actionLoading,
        successMessage
    } =
        useSelector(
            state =>
                state.enterprises
        );


    // =====================================================
    // LOAD LOOKUPS
    // =====================================================

    useEffect(() => {

        const loadLookups = async () => {

            try {

                setLoadingLookups(true);


                const moduleName =
                    "Enterprise";


                const [

                    enterpriseTypes,

                    ownershipTypes,

                    businessSectors

                ] = await Promise.all([

                    getLookupsByModuleAndCategoryService(
                        moduleName,
                        "EnterpriseType"
                    ),

                    getLookupsByModuleAndCategoryService(
                        moduleName,
                        "OwnershipType"
                    ),

                    getLookupsByModuleAndCategoryService(
                        moduleName,
                        "BusinessSector"
                    )

                ]);


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


                setLookups(
                    initialLookups
                );

            }

            finally {

                setLoadingLookups(false);

            }

        };


        loadLookups();

    }, []);


    // =====================================================
    // SUCCESS
    // =====================================================

    useEffect(() => {

        if (!successMessage) {

            return;

        }


        dispatch(
            clearEnterpriseMessage()
        );


        navigate(
            "/enterprises"
        );

    }, [

        successMessage,

        dispatch,

        navigate

    ]);


    // =====================================================
    // SUBMIT
    // =====================================================

    const handleSubmit = (
        data
    ) => {

        dispatch(
            createEnterpriseThunk(
                data
            )
        );

    };


    // =====================================================
    // LOADING
    // =====================================================

    if (loadingLookups) {

        return (

            <PageContainer>

                <PageHeader
                    title="Create Enterprise"
                    subtitle="Register a new enterprise"
                />

                <LoadingState
                    message="Loading enterprise form..."
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
                title="Create Enterprise"
                subtitle="Register a new enterprise"
            />


            <EnterpriseForm

                onSubmit={
                    handleSubmit
                }

                lookups={
                    lookups
                }

                loading={
                    actionLoading
                }

            />

        </PageContainer>

    );

};


export default EnterpriseCreatePage;