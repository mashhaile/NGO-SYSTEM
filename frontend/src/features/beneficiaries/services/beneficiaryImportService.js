import {
    importBeneficiariesApi,
    downloadBeneficiaryTemplateApi
} from "../api/beneficiaryImportApi";


// =====================================================
// IMPORT BENEFICIARIES
// =====================================================

export const importBeneficiariesService = async (
    file
) => {

    if (!file) {

        throw new Error(
            "Excel file is required."
        );

    }

    return await importBeneficiariesApi(
        file
    );

};


// =====================================================
// DOWNLOAD BENEFICIARY TEMPLATE
// =====================================================

export const downloadBeneficiaryTemplateService =
    async () => {

        return await downloadBeneficiaryTemplateApi();

    };