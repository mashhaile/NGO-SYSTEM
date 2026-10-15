import {
    useState
} from "react";


import {
    useNavigate
} from "react-router-dom";


import {
    Add
} from "@mui/icons-material";


import {
    useDonors
} from "../hooks/useDonors";


import DonorTable
    from "../components/DonorTable";


import {
    PageContainer,
    PageHeader,
    StatsCards,
    SearchToolbar,
    PageCard,
    FormSection,
    InfoRow,
    AppButton
} from "../../../components/ui";


// =====================================================
// PAGE
// =====================================================

const DonorListPage = () => {


    const navigate =
        useNavigate();


    // =================================================
    // STATE
    // =================================================

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
    // DATA
    // =================================================

    const {
        data,
        isLoading,
        error
    } = useDonors({

        search,

        page,

        limit

    });


    // =================================================
    // NORMALIZE DATA
    // =================================================

    const donors =

        Array.isArray(
            data?.data
        )

            ? data.data

            : Array.isArray(
                data
            )

                ? data

                : [];


    const pagination =
        data?.pagination;


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
    // LIMIT
    // =================================================

    const handleLimitChange = (
        value
    ) => {

        setLimit(
            Number(value)
        );

        setPage(
            1
        );

    };


    // =================================================
    // RESET
    // =================================================

    const resetSearch = () => {

        setSearch("");

        setPage(1);

    };


    // =================================================
    // PAGE CHANGE
    // =================================================

    const previousPage = () => {

        if (page > 1) {

            setPage(
                page - 1
            );

        }

    };


    const nextPage = () => {

        if (
            pagination &&
            page < pagination.totalPages
        ) {

            setPage(
                page + 1
            );

        }

    };


    // =================================================
    // STATS
    // =================================================

    const totalDonors =
        pagination?.total ||
        donors.length;


    const organizations =
        donors.filter(
            donor =>
                donor?.donorType ===
                "Organization"
        ).length;


    const individuals =
        donors.filter(
            donor =>
                donor?.donorType ===
                "Individual"
        ).length;


    // =================================================
    // RENDER
    // =================================================

    return (

        <PageContainer>


            {/* =================================================
                HEADER
            ================================================= */}

            <PageHeader

                title="Donors"

                subtitle="Manage NGO donors and funding partners"

                action={() =>
                    navigate(
                        "/donors/create"
                    )
                }

                actionLabel="Add Donor"

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
                            "Total Donors",

                        value:
                            totalDonors
                    },

                    {
                        label:
                            "Organizations",

                        value:
                            organizations
                    },

                    {
                        label:
                            "Individuals",

                        value:
                            individuals
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
                ERROR
            ================================================= */}

            {
                error && (

                    <PageCard>

                        <FormSection
                            title="Unable to Load Donors"
                        >

                            <InfoRow
                                label="Error"
                                value={
                                    error?.response
                                        ?.data
                                        ?.message ||
                                    error?.message ||
                                    "Failed to load donors."
                                }
                            />

                        </FormSection>

                    </PageCard>

                )
            }


            {/* =================================================
                TABLE
            ================================================= */}

            <PageCard>

                <DonorTable

                    data={
                        donors
                    }

                    loading={
                        isLoading
                    }

                />

            </PageCard>


            {/* =================================================
                PAGINATION
            ================================================= */}

            {
                pagination &&
                pagination.totalPages > 1 && (

                    <PageCard>

                        <FormSection>

                            <div
                                style={{
                                    display:
                                        "flex",

                                    alignItems:
                                        "center",

                                    justifyContent:
                                        "center",

                                    gap:
                                        "16px",

                                    flexWrap:
                                        "wrap"
                                }}
                            >

                                <AppButton
                                    variant="outlined"
                                    disabled={
                                        page <= 1
                                    }
                                    onClick={
                                        previousPage
                                    }
                                >
                                    Previous
                                </AppButton>


                                <strong>

                                    Page {
                                        page
                                    } of {
                                        pagination.totalPages
                                    }

                                </strong>


                                <AppButton
                                    variant="outlined"
                                    disabled={
                                        page >=
                                        pagination.totalPages
                                    }
                                    onClick={
                                        nextPage
                                    }
                                >
                                    Next
                                </AppButton>

                            </div>

                        </FormSection>

                    </PageCard>

                )
            }


        </PageContainer>

    );

};


export default DonorListPage;
