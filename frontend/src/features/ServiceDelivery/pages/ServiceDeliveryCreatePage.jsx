import {
    useEffect,
    useState
} from "react";


import {
    useNavigate
} from "react-router-dom";


import {
    ArrowBack
} from "@mui/icons-material";


import {
    PageContainer,
    PageHeader,
    PageCard,
    LoadingState
} from "../../../components/ui";


import ServiceDeliveryForm
    from "../components/serviceDeliveryForm";


import {
    createServiceDeliveryService
} from "../services/serviceDeliveryService";


import {
    getBeneficiariesLookupService
} from "../../beneficiaries/services/beneficiaryService";


import {
    getProgramsService
} from "../../programs/services/programService";


import {
    getProjectsService
} from "../../projects/services/projectService";


import {
    getActivitiesService
} from "../../activities/services/activityService";


import {
    getActivityRunsService
} from "../../activityRuns/services/activityRunService";


import {
    getLookupOptionsService
} from "../services/lookupService";


// =====================================================
// PAGE
// =====================================================

const ServiceDeliveryCreatePage = () => {

    const navigate =
        useNavigate();


    const [
        loading,
        setLoading
    ] = useState(false);


    const [
        pageLoading,
        setPageLoading
    ] = useState(true);


    const [
        beneficiaries,
        setBeneficiaries
    ] = useState([]);


    const [
        programs,
        setPrograms
    ] = useState([]);


    const [
        projects,
        setProjects
    ] = useState([]);


    const [
        activities,
        setActivities
    ] = useState([]);


    const [
        activityRuns,
        setActivityRuns
    ] = useState([]);


    const [
        serviceCategories,
        setServiceCategories
    ] = useState([]);


    const [
        units,
        setUnits
    ] = useState([]);


    const [
        formData,
        setFormData
    ] = useState({

        recipientType:
            "Individual",

        recipientName:
            "",

        allocationMethod:
            "Individual",

        beneficiaries:
            [],

        program:
            "",

        project:
            "",

        activity:
            "",

        activityRun:
            "",

        deliveryDate:
            null,

        deliveryLocation:
            "",

        status:
            "Delivered",

        items: [

            {

                serviceCategory:
                    "",

                serviceType:
                    "",

                allocationBehavior:
                    "CONSUMPTION",

                quantity:
                    1,

                unit:
                    "",

                unitCost:
                    0,

                donor:
                    "",

                donation:
                    "",

                detailItems:
                    [],

                remarks:
                    ""

            }

        ]

    });


    // =================================================
    // EXTRACT LIST
    // =================================================

    const extractList = (
        response
    ) => {

        if (
            Array.isArray(
                response
            )
        ) {

            return response;

        }


        if (
            Array.isArray(
                response?.data
            )
        ) {

            return response.data;

        }


        if (
            Array.isArray(
                response?.data?.data
            )
        ) {

            return response.data.data;

        }


        if (
            Array.isArray(
                response?.data?.results
            )
        ) {

            return response.data.results;

        }


        if (
            Array.isArray(
                response?.results
            )
        ) {

            return response.results;

        }


        return [];

    };


    // =================================================
    // NORMALIZE ID
    // =================================================

    const normalizeId = (
        value
    ) => {

        if (
            value === undefined ||
            value === null ||
            value === ""
        ) {

            return null;

        }


        if (
            typeof value ===
            "object"
        ) {

            const nestedId =
                value?._id ??
                value?.id ??
                value?.value ??
                null;


            return nestedId
                ? String(
                    nestedId
                )
                : null;

        }


        return String(
            value
        );

    };


    // =================================================
    // NORMALIZE BENEFICIARY ALLOCATION
    // =================================================

    const normalizeBeneficiaryAllocation = (
        allocation
    ) => {

        if (
            !allocation
        ) {

            return null;

        }


        // ---------------------------------------------
        // SERVICE ITEM
        // ---------------------------------------------

        const serviceItemId =
            normalizeId(
                allocation?.serviceItem
            );


        if (
            !serviceItemId
        ) {

            return null;

        }


        // ---------------------------------------------
        // DETAIL ITEM
        //
        // Important:
        // Preserve detailItem when the allocation
        // belongs to a supporting detail item.
        // ---------------------------------------------

        const detailItemId =
            normalizeId(
                allocation?.detailItem
            );


        // ---------------------------------------------
        // NUMERIC VALUES
        // ---------------------------------------------

        const quantity =
            Number(
                allocation?.quantity ??
                0
            );


        const allocatedValue =
            Number(
                allocation?.allocatedValue ??
                0
            );


        // ---------------------------------------------
        // NORMALIZED ALLOCATION
        // ---------------------------------------------

        const normalizedAllocation = {

            serviceItem:
                serviceItemId,

            detailItem:
                detailItemId,

            quantity:
                Number.isFinite(
                    quantity
                )
                    ? quantity
                    : 0,

            allocatedValue:
                Number.isFinite(
                    allocatedValue
                )
                    ? allocatedValue
                    : 0,

            remarks:
                typeof allocation?.remarks ===
                "string"
                    ? allocation.remarks
                    : ""

        };


        return normalizedAllocation;

    };


    // =================================================
    // NORMALIZE BENEFICIARY RECORD
    // =================================================

    const normalizeBeneficiaryRecord = (
        record
    ) => {

        if (
            record === undefined ||
            record === null ||
            record === ""
        ) {

            return null;

        }


        if (
            typeof record !==
            "object"
        ) {

            return {

                beneficiary:
                    String(
                        record
                    ),

                enrollment:
                    null,

                status:
                    "Received",

                quantity:
                    null,

                remarks:
                    "",

                allocations:
                    []

            };

        }


        // ---------------------------------------------
        // BENEFICIARY
        // ---------------------------------------------

        const beneficiary =
            record?.beneficiary;


        const normalizedBeneficiary =
            typeof beneficiary ===
            "object"
                ? (
                    beneficiary?._id ??
                    beneficiary?.id ??
                    beneficiary?.value ??
                    ""
                )
                : (
                    beneficiary ??
                    record?._id ??
                    record?.id ??
                    record?.value ??
                    ""
                );


        if (
            !normalizedBeneficiary
        ) {

            return null;

        }


        // ---------------------------------------------
        // QUANTITY
        // ---------------------------------------------

        const rawQuantity =
            record?.quantity;


        const quantity =
            rawQuantity === undefined ||
            rawQuantity === null ||
            rawQuantity === ""
                ? null
                : Number(
                    rawQuantity
                );


        // ---------------------------------------------
        // ALLOCATIONS
        // ---------------------------------------------

        const allocations =
            Array.isArray(
                record?.allocations
            )
                ? record.allocations
                    .map(
                        normalizeBeneficiaryAllocation
                    )
                    .filter(
                        Boolean
                    )
                : [];


        // ---------------------------------------------
        // ENROLLMENT
        // ---------------------------------------------

        const enrollment =
            record?.enrollment;


        const normalizedEnrollment =
            typeof enrollment ===
            "object"
                ? (
                    enrollment?._id ??
                    enrollment?.id ??
                    enrollment?.value ??
                    ""
                )
                : (
                    enrollment ||
                    ""
                );


        return {

            beneficiary:
                String(
                    normalizedBeneficiary
                ),

            enrollment:
                normalizedEnrollment
                    ? String(
                        normalizedEnrollment
                    )
                    : null,

            status:
                record?.status ||
                "Received",

            quantity:
                quantity !== null &&
                Number.isFinite(
                    quantity
                )
                    ? quantity
                    : null,

            remarks:
                typeof record?.remarks ===
                "string"
                    ? record.remarks
                    : "",

            allocations

        };

    };


    // =================================================
    // NORMALIZE DETAIL ITEMS
    // =================================================

    const normalizeDetailItems = (
        detailItems
    ) => {

        if (
            !Array.isArray(
                detailItems
            )
        ) {

            return [];

        }


        return detailItems
            .map(
                (
                    detail
                ) => {

                    if (
                        !detail
                    ) {

                        return null;

                    }


                    const quantity =
                        Number(
                            detail?.quantity ??
                            1
                        );


                    const unitCost =
                        Number(
                            detail?.unitCost ??
                            0
                        );


                    const safeQuantity =
                        Number.isFinite(
                            quantity
                        ) &&
                        quantity > 0
                            ? quantity
                            : 1;


                    const safeUnitCost =
                        Number.isFinite(
                            unitCost
                        ) &&
                        unitCost >= 0
                            ? unitCost
                            : 0;


                    const normalizedDetail = {

                        name:
                            typeof detail?.name ===
                            "string"
                                ? detail.name.trim()
                                : "",

                        quantity:
                            safeQuantity,

                        unit:
                            normalizeId(
                                detail?.unit
                            ),

                        unitCost:
                            safeUnitCost,

                        totalCost:
                            safeQuantity *
                            safeUnitCost

                    };


                    // ---------------------------------
                    // PRESERVE DETAIL ITEM ID
                    // ---------------------------------

                    const detailId =
                        normalizeId(
                            detail?._id ??
                            detail?.id
                        );


                    if (
                        detailId
                    ) {

                        normalizedDetail._id =
                            detailId;

                    }


                    return normalizedDetail;

                }
            )
            .filter(
                Boolean
            );

    };


    // =================================================
    // LOAD INITIAL DATA
    // =================================================

    useEffect(() => {

        let cancelled = false;


        const loadData = async () => {

            try {

                const [

                    programRes,

                    projectRes,

                    activityRes,

                    activityRunRes,

                    categoryRes,

                    unitRes

                ] = await Promise.all([

                    getProgramsService(),

                    getProjectsService(),

                    getActivitiesService(),

                    getActivityRunsService(),

                    getLookupOptionsService(
                        "ServiceCategory"
                    ),

                    getLookupOptionsService(
                        "Unit"
                    )

                ]);


                if (
                    cancelled
                ) {

                    return;

                }


                setPrograms(
                    extractList(
                        programRes
                    )
                );


                setProjects(
                    extractList(
                        projectRes
                    )
                );


                setActivities(
                    extractList(
                        activityRes
                    )
                );


                setActivityRuns(
                    extractList(
                        activityRunRes
                    )
                );


                setServiceCategories(
                    extractList(
                        categoryRes
                    )
                );


                setUnits(
                    extractList(
                        unitRes
                    )
                );

            }
            catch (
                error
            ) {

                console.error(
                    "Service Delivery loading error:",
                    error
                );


                if (
                    !cancelled
                ) {

                    setBeneficiaries([]);

                    setPrograms([]);

                    setProjects([]);

                    setActivities([]);

                    setActivityRuns([]);

                    setServiceCategories([]);

                    setUnits([]);

                }

            }
            finally {

                if (
                    !cancelled
                ) {

                    setPageLoading(
                        false
                    );

                }

            }

        };


        loadData();


        return () => {

            cancelled = true;

        };

    }, []);


    // =================================================
    // LOAD BENEFICIARIES WHEN PROGRAM CHANGES
    // =================================================

    useEffect(() => {

        let cancelled = false;


        const programId =
            formData?.program
                ? String(
                    formData.program
                )
                : "";


        if (
            !programId
        ) {

            setBeneficiaries([]);


            return () => {

                cancelled = true;

            };

        }


        setBeneficiaries([]);


        const loadBeneficiaries =
            async () => {

                try {

                    const response =
                        await getBeneficiariesLookupService(
                            programId
                        );


                    if (
                        cancelled
                    ) {

                        return;

                    }


                    const list =
                        extractList(
                            response
                        );


                    setBeneficiaries(
                        list
                    );

                }
                catch (
                    error
                ) {

                    console.error(
                        "Program beneficiary loading error:",
                        error
                    );


                    if (
                        !cancelled
                    ) {

                        setBeneficiaries([]);

                    }

                }

            };


        loadBeneficiaries();


        return () => {

            cancelled = true;

        };

    }, [
        formData?.program
    ]);


    // =================================================
    // SUBMIT
    // =================================================

    const handleSubmit = async (
        data
    ) => {

        try {

            // -----------------------------------------
            // ALLOCATION / RECIPIENT
            // -----------------------------------------

            const recipientType =
                data?.recipientType ||
                "Individual";


            const recipientName =
                typeof data?.recipientName ===
                "string"
                    ? data.recipientName.trim()
                    : "";


            const allocationMethod =
                data?.allocationMethod ||
                "Individual";


            // -----------------------------------------
            // RECIPIENT IDENTITY VALIDATION
            // -----------------------------------------

            const recipientNameRequired =
                recipientType ===
                    "Household" ||
                recipientType ===
                    "Group / Community" ||
                recipientType ===
                    "Institution";


            if (
                recipientNameRequired &&
                !recipientName
            ) {

                const label =
                    recipientType ===
                        "Household"
                        ? "Household name or identifier"
                        : recipientType ===
                            "Group / Community"
                            ? "Group / Community name"
                            : "Institution name";


                alert(
                    `Please enter the ${label}.`
                );


                return;

            }


            // -----------------------------------------
            // BENEFICIARIES
            // -----------------------------------------

            const normalizedBeneficiaries =
                Array.isArray(
                    data?.beneficiaries
                )
                    ? data.beneficiaries
                        .map(
                            normalizeBeneficiaryRecord
                        )
                        .filter(
                            Boolean
                        )
                    : [];


            const selectedBeneficiaries =
                normalizedBeneficiaries.map(
                    (record) =>
                        record.beneficiary
                );


            const requiresBeneficiaries =
                recipientType ===
                    "Individual" ||
                (
                    allocationMethod ===
                    "Individual"
                );


            if (
                requiresBeneficiaries &&
                selectedBeneficiaries.length === 0
            ) {

                alert(
                    "Please select at least one beneficiary."
                );


                return;

            }


            // -----------------------------------------
            // ITEMS
            // -----------------------------------------

            const items =
                Array.isArray(
                    data?.items
                )
                    ? data.items
                    : [];


            if (
                items.length === 0
            ) {

                alert(
                    "Please add at least one service item."
                );


                return;

            }


            // -----------------------------------------
            // VALIDATE ITEMS
            // -----------------------------------------

            for (
                let i = 0;
                i < items.length;
                i++
            ) {

                const item =
                    items[i];


                const serviceCategory =
                    item?.serviceCategory
                        ? String(
                            item.serviceCategory
                        )
                        : "";


                const serviceType =
                    item?.serviceType
                        ? String(
                            item.serviceType
                        )
                        : "";


                const unit =
                    item?.unit
                        ? String(
                            item.unit
                        )
                        : "";


                const quantity =
                    Number(
                        item?.quantity ??
                        0
                    );


                const unitCost =
                    Number(
                        item?.unitCost ??
                        0
                    );


                if (
                    !serviceCategory
                ) {

                    alert(
                        `Please select Service Category for item ${i + 1}.`
                    );


                    return;

                }


                if (
                    !serviceType
                ) {

                    alert(
                        `Please select Service Type for item ${i + 1}.`
                    );


                    return;

                }


                if (
                    !unit
                ) {

                    alert(
                        `Please select Unit for item ${i + 1}.`
                    );


                    return;

                }


                if (
                    !Number.isFinite(
                        quantity
                    ) ||
                    quantity < 1
                ) {

                    alert(
                        `Quantity must be at least 1 for item ${i + 1}.`
                    );


                    return;

                }


                if (
                    !Number.isFinite(
                        unitCost
                    ) ||
                    unitCost < 0
                ) {

                    alert(
                        `Unit Cost cannot be negative for item ${i + 1}.`
                    );


                    return;

                }

            }


            setLoading(
                true
            );


            // -----------------------------------------
            // PAYLOAD
            // -----------------------------------------

            const payload = {

                ...data,

                recipientType:
                    recipientType,

                recipientName:
                    recipientName,

                allocationMethod:
                    allocationMethod,

                beneficiaries:
                    normalizedBeneficiaries,

                program:
                    data?.program
                        ? String(
                            data.program
                        )
                        : "",

                project:
                    data?.project
                        ? String(
                            data.project
                        )
                        : "",

                activity:
                    data?.activity
                        ? String(
                            data.activity
                        )
                        : "",

                activityRun:
                    data?.activityRun
                        ? String(
                            data.activityRun
                        )
                        : "",

                items:
                    items.map(
                        (
                            item
                        ) => {

                            const normalizedItem = {

                                serviceCategory:
                                    item?.serviceCategory
                                        ? String(
                                            item.serviceCategory
                                        )
                                        : "",

                                serviceType:
                                    item?.serviceType
                                        ? String(
                                            item.serviceType
                                        )
                                        : "",

                                allocationBehavior:
                                    item?.allocationBehavior ||
                                    "CONSUMPTION",

                                quantity:
                                    Number(
                                        item?.quantity ??
                                        1
                                    ),

                                unit:
                                    item?.unit
                                        ? String(
                                            item.unit
                                        )
                                        : "",

                                unitCost:
                                    Number(
                                        item?.unitCost ??
                                        0
                                    ),

                                donor:
                                    item?.donor
                                        ? String(
                                            item.donor
                                        )
                                        : null,

                                donation:
                                    item?.donation
                                        ? String(
                                            item.donation
                                        )
                                        : null,

                                detailItems:
                                    normalizeDetailItems(
                                        item?.detailItems
                                    ),

                                remarks:
                                    typeof item?.remarks ===
                                    "string"
                                        ? item.remarks
                                        : ""

                            };


                            // ---------------------------------
                            // PRESERVE SERVICE ITEM ID
                            // ---------------------------------

                            const serviceItemId =
                                normalizeId(
                                    item?._id ??
                                    item?.id
                                );


                            if (
                                serviceItemId
                            ) {

                                normalizedItem._id =
                                    serviceItemId;

                            }


                            return normalizedItem;

                        }
                    )

            };


            // -----------------------------------------
            // TOTAL AMOUNT
            // -----------------------------------------

            delete payload.totalAmount;


            // -----------------------------------------
            // CREATE
            // -----------------------------------------

            await createServiceDeliveryService(
                payload
            );


            navigate(
                "/service-deliveries"
            );

        }
        catch (
            error
        ) {

            console.error(
                "SERVICE DELIVERY CREATE ERROR:",
                error?.response?.data ||
                error
            );


            alert(
                error?.response?.data?.message ||
                error?.message ||
                "Failed to create service delivery."
            );

        }
        finally {

            setLoading(
                false
            );

        }

    };


    // =================================================
    // PAGE LOADING
    // =================================================

    if (
        pageLoading
    ) {

        return (

            <PageContainer>

                <LoadingState />

            </PageContainer>

        );

    }


    // =================================================
    // RENDER
    // =================================================

    return (

        <PageContainer>

            <PageHeader

                title="Create Service Delivery"

                subtitle="Register delivered services to beneficiaries"

                action={() =>
                    navigate(
                        "/service-deliveries"
                    )
                }

                actionLabel="Back"

                actionIcon={
                    <ArrowBack />
                }

            />


            <PageCard>

                <ServiceDeliveryForm

                    formData={
                        formData
                    }

                    setFormData={
                        setFormData
                    }

                    beneficiaries={
                        beneficiaries
                    }

                    programs={
                        programs
                    }

                    projects={
                        projects
                    }

                    activities={
                        activities
                    }

                    activityRuns={
                        activityRuns
                    }

                    serviceCategories={
                        serviceCategories
                    }

                    units={
                        units
                    }

                    onSubmit={
                        handleSubmit
                    }

                    loading={
                        loading
                    }

                />

            </PageCard>

        </PageContainer>

    );

};


export default ServiceDeliveryCreatePage;