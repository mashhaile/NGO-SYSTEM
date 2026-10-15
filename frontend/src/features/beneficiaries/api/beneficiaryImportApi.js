import axiosClient
    from "../../../services/axiosClient";


// =====================================================
// IMPORT BENEFICIARIES EXCEL
// =====================================================

export const importBeneficiariesApi = async (
    file
) => {

    if (!file) {

        throw new Error(
            "Excel file is required."
        );

    }


    const formData =
        new FormData();


    formData.append(
        "file",
        file
    );


    const response =
        await axiosClient.post(
            "/beneficiaries/import",
            formData,
            {
                headers: {
                    "Content-Type":
                        "multipart/form-data"
                }
            }
        );


    return response.data;

};


// =====================================================
// DOWNLOAD BENEFICIARY TEMPLATE
// =====================================================

export const downloadBeneficiaryTemplateApi =
    async () => {

        const response =
            await axiosClient.get(
                "/beneficiaries/import/template",
                {
                    responseType:
                        "blob"
                }
            );


        return response.data;

    };