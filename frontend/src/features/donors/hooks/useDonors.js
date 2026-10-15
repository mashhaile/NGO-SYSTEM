import {
    useQuery,
    useMutation,
    useQueryClient
} from "@tanstack/react-query";


import {
    getDonorsService,
    getDonorByIdService,
    createDonorService,
    updateDonorService,
    deleteDonorService
} from "../services/donorService";


// =====================================================
// GET ALL DONORS
// =====================================================

export const useDonors = (params = {}) => {

    return useQuery({

        queryKey: [
            "donors",
            params
        ],

        queryFn: () =>
            getDonorsService(params)

    });

};


// =====================================================
// GET SINGLE DONOR
// =====================================================

export const useDonor = (id) => {

    return useQuery({

        queryKey: [
            "donor",
            id
        ],

        queryFn: () =>
            getDonorByIdService(id),

        enabled: Boolean(id)

    });

};


// =====================================================
// CREATE DONOR
// =====================================================

export const useCreateDonor = () => {

    const queryClient =
        useQueryClient();


    return useMutation({

        mutationFn: (data) =>
            createDonorService(data),


        onSuccess: () => {

            queryClient.invalidateQueries({

                queryKey: [
                    "donors"
                ]

            });

        }

    });

};


// =====================================================
// UPDATE DONOR
// =====================================================

export const useUpdateDonor = () => {

    const queryClient =
        useQueryClient();


    return useMutation({

        mutationFn: ({
            id,
            data
        }) =>
            updateDonorService(
                id,
                data
            ),


        onSuccess: (
            response,
            variables
        ) => {

            // Refresh donor list
            queryClient.invalidateQueries({

                queryKey: [
                    "donors"
                ]

            });


            // Refresh current donor
            queryClient.invalidateQueries({

                queryKey: [
                    "donor",
                    variables.id
                ]

            });

        }

    });

};


// =====================================================
// DELETE DONOR
// =====================================================

export const useDeleteDonor = () => {

    const queryClient =
        useQueryClient();


    return useMutation({

        mutationFn: (id) =>
            deleteDonorService(id),


        onSuccess: (
            response,
            id
        ) => {

            // Refresh donor list
            queryClient.invalidateQueries({

                queryKey: [
                    "donors"
                ]

            });


            // Remove deleted donor
            queryClient.removeQueries({

                queryKey: [
                    "donor",
                    id
                ]

            });

        }

    });

};
