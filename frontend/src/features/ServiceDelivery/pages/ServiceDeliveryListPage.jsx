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


import {
    Add
} from "@mui/icons-material";


import {
    PageContainer,
    PageHeader,
    StatsCards,
    SearchToolbar,
    PageCard
} from "../../../components/ui";


import ServiceDeliveryTable
    from "../components/serviceDeliveryTable";


import {
    getServiceDeliveries
} from "../store";


// =====================================================
// PAGE
// =====================================================

const ServiceDeliveryListPage = () => {

    const dispatch =
        useDispatch();


    const navigate =
        useNavigate();


    const {
        serviceDeliveries = [],
        loading,
        pagination
    } = useSelector(
        (state) =>
            state.serviceDelivery
    );


    const [
        search,
        setSearch
    ] = useState("");


    const [
        page,
        setPage
    ] = useState(1);


    const [
        limit,
        setLimit
    ] = useState(10);


    // =================================================
    // LOAD DATA
    // =================================================

    useEffect(() => {

        const timer =
            setTimeout(
                () => {

                    dispatch(
                        getServiceDeliveries(
                            {
                                search:
                                    search.trim(),

                                page,

                                limit
                            }
                        )
                    );

                },
                500
            );


        return () =>
            clearTimeout(
                timer
            );

    }, [
        dispatch,
        search,
        page,
        limit
    ]);


    // =================================================
    // SEARCH
    // =================================================

    const handleSearch = (
        value
    ) => {

        setSearch(
            value
        );


        setPage(
            1
        );

    };


    // =================================================
    // RESET SEARCH
    // =================================================

    const resetSearch = () => {

        setSearch(
            ""
        );


        setPage(
            1
        );

    };


    // =================================================
    // LIMIT
    // =================================================

    const handleLimitChange = (
        value
    ) => {

        const normalizedLimit =
            Number(
                value
            );


        if (
            !Number.isFinite(
                normalizedLimit
            ) ||
            normalizedLimit <= 0
        ) {

            return;

        }


        setLimit(
            normalizedLimit
        );


        setPage(
            1
        );

    };


    // =================================================
    // PAGINATION
    // =================================================

    const totalPages =
        Number(
            pagination?.totalPages || 0
        );


    const currentPage =
        Number(
            pagination?.page ||
            page
        );


    const hasPagination =
        totalPages > 1;


    const canGoPrevious =
        currentPage > 1;


    const canGoNext =
        totalPages > 0 &&
        currentPage < totalPages;


    const handlePrevious = () => {

        if (
            !canGoPrevious
        ) {

            return;

        }


        setPage(
            currentPage - 1
        );

    };


    const handleNext = () => {

        if (
            !canGoNext
        ) {

            return;

        }


        setPage(
            currentPage + 1
        );

    };


    // =================================================
    // STATISTICS
    // =================================================

    const totalDeliveries =
        Number(
            pagination?.total ?? 0
        );


    const currentRecords =
        serviceDeliveries.length;


    const deliveredRecords =
        serviceDeliveries.filter(
            (item) =>
                item?.status ===
                "Delivered"
        ).length;


    // =================================================
    // PAGE
    // =================================================

    return (

        <PageContainer>

            <PageHeader

                title="Service Deliveries"

                subtitle="Manage delivered services to beneficiaries"

                action={() =>
                    navigate(
                        "/service-deliveries/create"
                    )
                }

                actionLabel="Create Delivery"

                actionIcon={
                    <Add />
                }

            />


            {/* =================================================
                STATISTICS
            ================================================= */}

            <StatsCards

                items={[

                    {
                        label:
                            "Total Deliveries",

                        value:
                            totalDeliveries
                    },


                    {
                        label:
                            "Current Records",

                        value:
                            currentRecords
                    },


                    {
                        label:
                            "Delivered",

                        value:
                            deliveredRecords
                    }

                ]}

            />


            {/* =================================================
                SEARCH
            ================================================= */}

            <SearchToolbar

                search={
                    search
                }

                onSearch={
                    handleSearch
                }

                onReset={
                    resetSearch
                }

                filters={[

                    {
                        key:
                            "limit",

                        label:
                            "Rows",

                        value:
                            limit,

                        onChange:
                            handleLimitChange,

                        options: [

                            {
                                value:
                                    10,

                                label:
                                    "10"
                            },


                            {
                                value:
                                    25,

                                label:
                                    "25"
                            },


                            {
                                value:
                                    50,

                                label:
                                    "50"
                            }

                        ]

                    }

                ]}

            />


            {/* =================================================
                TABLE
            ================================================= */}

            <PageCard>

                <ServiceDeliveryTable

                    data={
                        serviceDeliveries
                    }

                    loading={
                        loading
                    }

                />

            </PageCard>


            {/* =================================================
                PAGINATION
            ================================================= */}

            {
                hasPagination && (

                    <div
                        style={{
                            marginTop: 20,
                            marginBottom: 40,
                            display: "flex",
                            justifyContent: "center",
                            alignItems: "center",
                            gap: 20
                        }}
                    >

                        <button

                            type="button"

                            disabled={
                                !canGoPrevious ||
                                loading
                            }

                            onClick={
                                handlePrevious
                            }

                        >
                            Previous
                        </button>


                        <strong>

                            Page{" "}

                            {currentPage}

                            {" "}of{" "}

                            {totalPages}

                        </strong>


                        <button

                            type="button"

                            disabled={
                                !canGoNext ||
                                loading
                            }

                            onClick={
                                handleNext
                            }

                        >
                            Next
                        </button>

                    </div>

                )
            }

        </PageContainer>

    );

};


export default ServiceDeliveryListPage;