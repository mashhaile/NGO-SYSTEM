import {
    useEffect,
    useMemo,
    useState
} from "react";


import {
    useNavigate
} from "react-router-dom";


import {
    Alert,
    Link
} from "@mui/material";


import {
    Add
} from "@mui/icons-material";


import {
    PageContainer,
    PageHeader,
    PageCard,
    SearchToolbar,
    DataTable,
    StatusChip
} from "../../../components/ui";


import useAuth
    from "../../auth/hooks/useAuth";


import {
    getTorsApi,
    getApiErrorMessage
} from "../api/torApi";


import {
    hasPermission,
    TOR_STATUS
} from "../utils/torPermissions";


import {
    formatAmount
} from "../utils/torBudget";



const STATUS_OPTIONS = [
    {
        value: "",
        label: "All statuses"
    },
    ...Object.values(TOR_STATUS).map(status => ({
        value: status,
        label: status
    }))
];


const formatDate = (value) =>
    value
        ? new Date(value).toLocaleDateString()
        : "-";



// =====================================================
// TOR LIST PAGE
// =====================================================

const TorListPage = () => {

    const navigate =
        useNavigate();

    const {
        user
    } = useAuth();

    const [search, setSearch] =
        useState("");

    const [status, setStatus] =
        useState("");

    const [paginationModel, setPaginationModel] =
        useState({
            page: 0,
            pageSize: 10
        });

    const [result, setResult] =
        useState({
            rows: [],
            total: 0,
            loading: true,
            error: ""
        });


    // =================================================
    // LOAD
    // =================================================

    useEffect(() => {

        let cancelled = false;

        const timer =
            setTimeout(() => {

                getTorsApi({
                    search,
                    status,
                    page: paginationModel.page + 1,
                    limit: paginationModel.pageSize
                })

                    .then(response => {

                        if (!cancelled) {
                            setResult({
                                rows: response.data || [],
                                total: response.pagination?.total || 0,
                                loading: false,
                                error: ""
                            });
                        }

                    })

                    .catch(error => {

                        if (!cancelled) {
                            setResult(prev => ({
                                ...prev,
                                loading: false,
                                error: getApiErrorMessage(
                                    error,
                                    "Failed to load terms of reference."
                                )
                            }));
                        }

                    });

            }, 300);

        return () => {
            cancelled = true;
            clearTimeout(timer);
        };

    }, [search, status, paginationModel]);


    const columns = useMemo(() => [

        {
            field: "torNumber",
            headerName: "TOR No.",
            minWidth: 130,
            renderCell: (params) => (
                <Link
                    component="button"
                    underline="hover"
                    fontWeight={600}
                    onClick={() =>
                        navigate(`/tors/${params.row._id}`)
                    }
                >
                    {params.value}
                </Link>
            )
        },

        {
            field: "title",
            headerName: "Title",
            flex: 1.6,
            minWidth: 220
        },

        {
            field: "project",
            headerName: "Project",
            flex: 1.1,
            minWidth: 170,
            valueGetter: (value) =>
                value?.name || "-"
        },

        {
            field: "activity",
            headerName: "Activity",
            flex: 1.1,
            minWidth: 170,
            valueGetter: (value) =>
                value?.name || "Not created yet"
        },

        {
            field: "startDate",
            headerName: "Dates",
            minWidth: 190,
            valueGetter: (value, row) =>
                row.startDate
                    ? `${formatDate(row.startDate)} – ${formatDate(row.endDate || row.startDate)}`
                    : "-"
        },

        {
            field: "region",
            headerName: "Location",
            flex: 1,
            minWidth: 160,
            valueGetter: (value, row) =>
                [row.woreda, row.zone, row.region]
                    .filter(Boolean)
                    .join(", ") || row.venue || "-"
        },

        {
            field: "totalBudget",
            headerName: "Budget",
            minWidth: 150,
            align: "right",
            headerAlign: "right",
            valueGetter: (value, row) =>
                formatAmount(value, row.currency)
        },

        {
            field: "status",
            headerName: "Status",
            minWidth: 130,
            renderCell: (params) => (
                <StatusChip
                    status={params.value}
                />
            )
        }

    ], [navigate]);


    const changeSearch = (value) => {

        setSearch(value);

        setPaginationModel(prev => ({
            ...prev,
            page: 0
        }));

    };


    return (

        <PageContainer>

            <PageHeader
                title="Terms of Reference"
                subtitle="Prepare, submit and approve TORs for activities and trainings."
                {...(
                    hasPermission(user, "tor.create")
                        ? {
                            action: () =>
                                navigate("/tors/create"),
                            actionLabel: "New TOR",
                            actionIcon: <Add />
                        }
                        : {}
                )}
            />


            <SearchToolbar
                search={search}
                onSearch={changeSearch}
                onReset={() => {
                    changeSearch("");
                    setStatus("");
                }}
                filters={[
                    {
                        key: "status",
                        label: "Status",
                        value: status,
                        onChange: (value) => {
                            setStatus(value);
                            setPaginationModel(prev => ({
                                ...prev,
                                page: 0
                            }));
                        },
                        options: STATUS_OPTIONS
                    }
                ]}
            />


            {result.error && (

                <Alert
                    severity="error"
                    sx={{ mb: 3 }}
                >
                    {result.error}
                </Alert>

            )}


            <PageCard>

                <DataTable
                    rows={result.rows}
                    columns={columns}
                    loading={result.loading}
                    paginationMode="server"
                    rowCount={result.total}
                    paginationModel={paginationModel}
                    onPaginationModelChange={setPaginationModel}
                    onRowDoubleClick={(params) =>
                        navigate(`/tors/${params.row._id}`)
                    }
                />

            </PageCard>

        </PageContainer>

    );

};


export default TorListPage;
