import {
    useQuery,
    useMutation,
    useQueryClient
} from "@tanstack/react-query";


import {
    getDonationsService,
    getDonationByIdService,
    createDonationService,
    updateDonationService,
    deleteDonationService
} from "../services/donationService";



// ==========================================
// GET ALL DONATIONS
// ==========================================

export const useDonations = (
    params = {}
) => {

    return useQuery({

        queryKey: [
            "donations",
            params
        ],

        queryFn: () =>
            getDonationsService(params)

    });

};



// ==========================================
// GET SINGLE DONATION
// ==========================================

export const useDonation = (
    id
) => {

    return useQuery({

        queryKey: [
            "donation",
            id
        ],

        queryFn: () =>
            getDonationByIdService(id),

        enabled:
            Boolean(id)

    });

};



// ==========================================
// CREATE DONATION
// ==========================================

export const useCreateDonation = () => {

    const queryClient =
        useQueryClient();


    return useMutation({

        mutationFn:
            createDonationService,

        onSuccess: () => {

            queryClient.invalidateQueries({

                queryKey: [
                    "donations"
                ]

            });

        }

    });

};



// ==========================================
// UPDATE DONATION
// ==========================================

export const useUpdateDonation = () => {

    const queryClient =
        useQueryClient();


    return useMutation({

        mutationFn:
            ({ id, data }) =>
                updateDonationService(
                    id,
                    data
                ),

        onSuccess: (_, variables) => {

            queryClient.invalidateQueries({

                queryKey: [
                    "donations"
                ]

            });


            queryClient.invalidateQueries({

                queryKey: [
                    "donation",
                    variables.id
                ]

            });

        }

    });

};



// ==========================================
// DELETE DONATION
// ==========================================

export const useDeleteDonation = () => {

    const queryClient =
        useQueryClient();


    return useMutation({

        mutationFn:
            deleteDonationService,

        onSuccess: () => {

            queryClient.invalidateQueries({

                queryKey: [
                    "donations"
                ]

            });

        }

    });

};