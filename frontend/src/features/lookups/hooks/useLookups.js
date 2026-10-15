import {
    useQuery,
    useMutation,
    useQueryClient
} from "@tanstack/react-query";

import {
    getLookupsService,
    getLookupsByModuleAndCategoryService,
    getLookupByIdService,
    createLookupService,
    createLookupsBulkService,
    updateLookupService,
    deleteLookupService
} from "../services/lookupService";


// ==========================================================
// GET ALL LOOKUPS
// ==========================================================

export const useLookups = (
    params = {}
) => {

    return useQuery({

        queryKey: [
            "lookups",
            params
        ],

        queryFn: () =>
            getLookupsService(params),

        staleTime:
            5 * 60 * 1000

    });

};


// ==========================================================
// GET LOOKUPS BY MODULE + CATEGORY
// ==========================================================
//
// Normal:
//
// useLookupsByModuleAndCategory(
//     "Beneficiary",
//     "Gender"
// )
//
// Dependent:
//
// useLookupsByModuleAndCategory(
//     "ServiceDelivery",
//     "ServiceType",
//     categoryId
// )
//
// ==========================================================

export const useLookupsByModuleAndCategory = (
    module,
    category,
    parentLookup = null
) => {

    const hasParent =
        Boolean(
            parentLookup
        );


    return useQuery({

        queryKey: [
            "lookups",
            module,
            category,
            parentLookup || null
        ],

        queryFn: () =>
            getLookupsByModuleAndCategoryService(

                module,

                category,

                parentLookup

            ),

        enabled:
            Boolean(module) &&
            Boolean(category) &&
            (
                category !== "ServiceType" ||
                hasParent
            ),

        staleTime:
            5 * 60 * 1000

    });

};


// ==========================================================
// GET SERVICE CATEGORIES
// ==========================================================

export const useServiceCategories = () => {

    return useLookupsByModuleAndCategory(

        "ServiceDelivery",

        "ServiceCategory"

    );

};


// ==========================================================
// GET SERVICE TYPES BY CATEGORY
// ==========================================================
//
// Service Types are loaded only after a
// Service Category has been selected.
//
// ==========================================================

export const useServiceTypes = (
    serviceCategoryId
) => {

    return useLookupsByModuleAndCategory(

        "ServiceDelivery",

        "ServiceType",

        serviceCategoryId

    );

};


// ==========================================================
// GET SINGLE LOOKUP
// ==========================================================

export const useLookupById = (
    id
) => {

    return useQuery({

        queryKey: [
            "lookup",
            id
        ],

        queryFn: () =>
            getLookupByIdService(id),

        enabled:
            Boolean(id),

        staleTime:
            5 * 60 * 1000

    });

};


// ==========================================================
// CREATE SINGLE LOOKUP
// ==========================================================

export const useCreateLookup = () => {

    const queryClient =
        useQueryClient();


    return useMutation({

        mutationFn:
            createLookupService,

        onSuccess: () => {

            queryClient.invalidateQueries({

                queryKey: [
                    "lookups"
                ]

            });

        }

    });

};


// ==========================================================
// CREATE BULK LOOKUPS
// ==========================================================

export const useCreateLookupsBulk = () => {

    const queryClient =
        useQueryClient();


    return useMutation({

        mutationFn:
            createLookupsBulkService,

        onSuccess: () => {

            queryClient.invalidateQueries({

                queryKey: [
                    "lookups"
                ]

            });

        }

    });

};


// ==========================================================
// UPDATE LOOKUP
// ==========================================================

export const useUpdateLookup = () => {

    const queryClient =
        useQueryClient();


    return useMutation({

        mutationFn: ({
            id,
            data
        }) =>
            updateLookupService(
                id,
                data
            ),

        onSuccess: (
            response,
            variables
        ) => {

            queryClient.invalidateQueries({

                queryKey: [
                    "lookups"
                ]

            });


            queryClient.invalidateQueries({

                queryKey: [
                    "lookup",
                    variables.id
                ]

            });

        }

    });

};


// ==========================================================
// DELETE / DEACTIVATE LOOKUP
// ==========================================================

export const useDeleteLookup = () => {

    const queryClient =
        useQueryClient();


    return useMutation({

        mutationFn:
            deleteLookupService,

        onSuccess: () => {

            queryClient.invalidateQueries({

                queryKey: [
                    "lookups"
                ]

            });

        }

    });

};