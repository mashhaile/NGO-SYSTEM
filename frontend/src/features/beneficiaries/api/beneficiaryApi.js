import axiosClient
    from "../../../services/axiosClient";


// =====================================================
// GET BENEFICIARIES
// =====================================================

export const getBeneficiariesApi =
    async (
        params = {}
    ) => {

        const response =
            await axiosClient.get(
                "/beneficiaries",
                {
                    params
                }
            );

        return response.data;

    };


// =====================================================
// GET BENEFICIARY BY ID
// =====================================================

export const getBeneficiaryByIdApi =
    async (
        id
    ) => {

        const response =
            await axiosClient.get(
                `/beneficiaries/${id}`
            );

        return response.data;

    };


// =====================================================
// CREATE BENEFICIARY
// =====================================================

export const createBeneficiaryApi =
    async (
        data
    ) => {

        const response =
            await axiosClient.post(
                "/beneficiaries",
                data
            );

        return response.data;

    };


// =====================================================
// UPDATE BENEFICIARY
// =====================================================

export const updateBeneficiaryApi =
    async (
        id,
        data
    ) => {

        const response =
            await axiosClient.put(
                `/beneficiaries/${id}`,
                data
            );

        return response.data;

    };


// =====================================================
// DELETE BENEFICIARY
// =====================================================

export const deleteBeneficiaryApi =
    async (
        id
    ) => {

        const response =
            await axiosClient.delete(
                `/beneficiaries/${id}`
            );

        return response.data;

    };


// =====================================================
// BENEFICIARY LOOKUP
// =====================================================

export const getBeneficiaryLookupApi =
    async (
        program = "",
        include = [],
        project = ""
    ) => {

        const response =
            await axiosClient.get(
                "/beneficiaries/lookup",
                {
                    params: {
                        program,
                        ...(project ? { project } : {}),
                        ...(include.length ? { include: include.join(",") } : {})
                    }
                }
            );

        return response.data;

    };