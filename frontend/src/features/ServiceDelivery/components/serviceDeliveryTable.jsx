import {
    Box,
    IconButton,
    Tooltip
} from "@mui/material";

import {
    Visibility,
    Edit,
    Delete
} from "@mui/icons-material";

import {
    useNavigate
} from "react-router-dom";

import {
    useDispatch
} from "react-redux";

import {
    deleteServiceDelivery,
    getServiceDeliveries
} from "../store";

import {
    DataTable,
    StatusChip
} from "../../../components/ui";


const ServiceDeliveryTable = ({
    data = [],
    loading = false,
    search = "",
    page = 1,
    limit = 10
}) => {

    const navigate = useNavigate();

    const dispatch = useDispatch();


    // =================================================
    // HELPERS
    // =================================================

    const formatMoney = (
        value
    ) => {

        const amount =
            Number(value);

        if (
            !Number.isFinite(
                amount
            )
        ) {

            return "ETB 0.00";

        }

        return (
            `ETB ${amount.toLocaleString(
                undefined,
                {
                    minimumFractionDigits: 2,
                    maximumFractionDigits: 2
                }
            )}`
        );

    };


    const getLookupValue = (
        lookup
    ) => {

        if (
            !lookup
        ) {

            return "";

        }


        if (
            typeof lookup === "string"
        ) {

            return lookup;

        }


        return (
            lookup?.value ||
            lookup?.name ||
            lookup?.label ||
            lookup?.title ||
            lookup?.text ||
            lookup?.code ||
            lookup?._id ||
            ""
        );

    };


    // =================================================
    // DELETE
    // =================================================

    const handleDelete = async (
        id
    ) => {

        if (
            !id
        ) {

            window.alert(
                "Service delivery ID is missing."
            );

            return;

        }


        const confirmed =
            window.confirm(
                "Delete this service delivery record?"
            );


        if (
            !confirmed
        ) {

            return;

        }


        try {

            await dispatch(
                deleteServiceDelivery(
                    id
                )
            ).unwrap();


            await dispatch(
                getServiceDeliveries({
                    search:
                        typeof search === "string"
                            ? search.trim()
                            : "",

                    page:
                        Number(page) || 1,

                    limit:
                        Number(limit) || 10
                })
            ).unwrap();

        }

        catch (
            error
        ) {

            console.error(
                "Service delivery delete failed:",
                error
            );


            const message =
                typeof error === "string"
                    ? error
                    : error?.message ||
                      "Failed to delete service delivery.";


            window.alert(
                message
            );

        }

    };


    // =================================================
    // BENEFICIARY DISPLAY
    // =================================================

    const getBeneficiaryName = (
        beneficiary
    ) => {

        if (
            !beneficiary
        ) {

            return "";

        }


        if (
            typeof beneficiary === "string"
        ) {

            return beneficiary;

        }


        const firstName =
            beneficiary?.firstName ||
            "";

        const lastName =
            beneficiary?.lastName ||
            "";

        const fullName =
            `${firstName} ${lastName}`.trim();


        return (
            beneficiary?.fullName ||
            fullName ||
            beneficiary?.beneficiaryNumber ||
            beneficiary?.name ||
            ""
        );

    };


    const renderBeneficiaries = (
        row
    ) => {

        const associations =
            Array.isArray(
                row?.beneficiaries
            )
                ? row.beneficiaries
                : [];


        if (
            associations.length > 0
        ) {

            const names =
                associations
                    .map(
                        (
                            association
                        ) => {

                            const beneficiary =
                                association?.beneficiary ||
                                association;


                            return getBeneficiaryName(
                                beneficiary
                            );

                        }
                    )
                    .filter(
                        Boolean
                    );


            if (
                names.length > 0
            ) {

                return names.join(
                    ", "
                );

            }

        }


        const legacyName =
            getBeneficiaryName(
                row?.beneficiary
            );


        return (
            legacyName ||
            "-"
        );

    };


    // =================================================
    // SERVICE DISPLAY
    // =================================================

    const getServiceTypeName = (
        item
    ) => {

        return (
            getLookupValue(
                item?.serviceType
            ) ||
            ""
        );

    };


    const renderServices = (
        row
    ) => {

        const items =
            Array.isArray(
                row?.items
            )
                ? row.items
                : [];


        const services =
            items
                .map(
                    getServiceTypeName
                )
                .filter(
                    Boolean
                );


        const uniqueServices =
            [
                ...new Set(
                    services
                )
            ];


        if (
            uniqueServices.length === 0
        ) {

            return "-";

        }


        const visibleServices =
            uniqueServices.slice(
                0,
                2
            );


        const remainingCount =
            Math.max(
                0,
                uniqueServices.length -
                visibleServices.length
            );


        const displayValue =
            visibleServices.join(
                ", "
            );


        if (
            remainingCount > 0
        ) {

            return (
                `${displayValue} +${remainingCount} more`
            );

        }


        return displayValue;

    };


    // =================================================
    // COLUMNS
    // =================================================

    const columns = [

        {
            field:
                "deliveryNumber",

            headerName:
                "Delivery No",

            minWidth:
                140,

            flex:
                1

        },


        {
            field:
                "beneficiaries",

            headerName:
                "Beneficiaries",

            minWidth:
                220,

            flex:
                1.5,

            renderCell:
                (
                    params
                ) => {

                    const value =
                        renderBeneficiaries(
                            params.row
                        );


                    return (

                        <Box
                            sx={{
                                width:
                                    "100%",

                                whiteSpace:
                                    "normal",

                                overflow:
                                    "hidden",

                                textOverflow:
                                    "ellipsis",

                                lineHeight:
                                    1.4
                            }}
                            title={
                                value
                            }
                        >
                            {
                                value
                            }
                        </Box>

                    );

                }

        },


        {
            field:
                "program",

            headerName:
                "Program",

            minWidth:
                180,

            flex:
                1.2,

            renderCell:
                (
                    params
                ) => {

                    return (
                        getLookupValue(
                            params.row?.program
                        ) ||
                        "-"
                    );

                }

        },


        {
            field:
                "project",

            headerName:
                "Project",

            minWidth:
                150,

            flex:
                1,

            renderCell:
                (
                    params
                ) => {

                    return (
                        getLookupValue(
                            params.row?.project
                        ) ||
                        "-"
                    );

                }

        },


        {
            field:
                "activity",

            headerName:
                "Activity",

            minWidth:
                150,

            flex:
                1,

            renderCell:
                (
                    params
                ) => {

                    return (
                        getLookupValue(
                            params.row?.activity
                        ) ||
                        "-"
                    );

                }

        },


        {
            field:
                "serviceType",

            headerName:
                "Services",

            minWidth:
                200,

            flex:
                1.3,

            renderCell:
                (
                    params
                ) => {

                    const value =
                        renderServices(
                            params.row
                        );


                    return (

                        <Box
                            sx={{
                                width:
                                    "100%",

                                whiteSpace:
                                    "normal",

                                overflow:
                                    "hidden",

                                textOverflow:
                                    "ellipsis",

                                lineHeight:
                                    1.4
                            }}
                            title={
                                value
                            }
                        >
                            {
                                value
                            }
                        </Box>

                    );

                }

        },


        {
            field:
                "totalAmount",

            headerName:
                "Amount",

            width:
                140,

            align:
                "right",

            headerAlign:
                "right",

            renderCell:
                (
                    params
                ) => {

                    return (
                        formatMoney(
                            params.value
                        )
                    );

                }

        },


        {
            field:
                "status",

            headerName:
                "Status",

            width:
                130,

            renderCell:
                (
                    params
                ) => {

                    return (

                        <StatusChip
                            status={
                                params.value ||
                                "Draft"
                            }
                        />

                    );

                }

        },


        {
            field:
                "createdAt",

            headerName:
                "Created",

            width:
                130,

            renderCell:
                (
                    params
                ) => {

                    if (
                        !params.value
                    ) {

                        return "-";

                    }


                    const date =
                        new Date(
                            params.value
                        );


                    if (
                        Number.isNaN(
                            date.getTime()
                        )
                    ) {

                        return "-";

                    }


                    return date.toLocaleDateString();

                }

        },


        {
            field:
                "actions",

            headerName:
                "Actions",

            width:
                160,

            sortable:
                false,

            filterable:
                false,

            renderCell:
                (
                    params
                ) => (

                    <Box
                        sx={{
                            display:
                                "flex",

                            alignItems:
                                "center",

                            gap:
                                0.5
                        }}
                    >

                        <Tooltip
                            title="View service delivery"
                        >

                            <IconButton
                                size="small"

                                onClick={() =>
                                    navigate(
                                        `/service-deliveries/${params.row._id}`
                                    )
                                }
                            >

                                <Visibility
                                    fontSize="small"
                                />

                            </IconButton>

                        </Tooltip>


                        <Tooltip
                            title="Edit service delivery"
                        >

                            <IconButton
                                size="small"

                                onClick={() =>
                                    navigate(
                                        `/service-deliveries/${params.row._id}/edit`
                                    )
                                }
                            >

                                <Edit
                                    fontSize="small"
                                />

                            </IconButton>

                        </Tooltip>


                        <Tooltip
                            title="Delete service delivery"
                        >

                            <IconButton
                                size="small"

                                color="error"

                                disabled={
                                    loading
                                }

                                onClick={() =>
                                    handleDelete(
                                        params.row._id
                                    )
                                }
                            >

                                <Delete
                                    fontSize="small"
                                />

                            </IconButton>

                        </Tooltip>

                    </Box>

                )

        }

    ];


    // =================================================
    // ROWS
    // =================================================

    const rows =
        Array.isArray(
            data
        )
            ? data.map(
                (
                    item
                ) => ({

                    ...item,

                    id:
                        item?._id ||
                        item?.id

                })
            )
            : [];


    // =================================================
    // RENDER
    // =================================================

    return (

        <DataTable

            rows={
                rows
            }

            columns={
                columns
            }

            loading={
                loading
            }

            getRowId={
                (
                    row
                ) =>
                    row?._id ||
                    row?.id

            }

        />

    );

};


export default ServiceDeliveryTable;