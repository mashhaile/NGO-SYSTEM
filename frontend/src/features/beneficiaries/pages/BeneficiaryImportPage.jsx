import {
    useState
} from "react";

import {
    useNavigate
} from "react-router-dom";

import {
    Stack,
    Typography
} from "@mui/material";

import {
    UploadFile,
    Download
} from "@mui/icons-material";

import {
    PageContainer,
    PageHeader,
    PageCard,
    AppButton,
    AppAlert
} from "../../../components/ui";

import {
    importBeneficiariesService,
    downloadBeneficiaryTemplateService
} from "../services/beneficiaryImportService";


const BeneficiaryImportPage = () => {

    const navigate = useNavigate();


    // =====================================================
    // STATE
    // =====================================================

    const [file, setFile] =
        useState(null);

    const [loading, setLoading] =
        useState(false);

    const [message, setMessage] =
        useState("");

    const [error, setError] =
        useState("");


    // =====================================================
    // FILE SELECT
    // =====================================================

    const handleFileChange = (
        event
    ) => {

        const selectedFile =
            event.target.files?.[0] || null;


        setMessage("");
        setError("");


        if (!selectedFile) {

            setFile(null);

            return;

        }


        // =================================================
        // FILE EXTENSION
        // =================================================

        const fileName =
            String(
                selectedFile.name || ""
            )
                .trim()
                .toLowerCase();


        if (
            !fileName.endsWith(".xlsx")
        ) {

            setFile(null);

            setError(
                "Please select a valid Excel .xlsx file."
            );

            return;

        }


        // =================================================
        // FILE SIZE
        // Backend limit: 10 MB
        // =================================================

        const maxSize =
            10 * 1024 * 1024;


        if (
            selectedFile.size > maxSize
        ) {

            setFile(null);

            setError(
                "The selected file exceeds the 10 MB limit."
            );

            return;

        }


        setFile(
            selectedFile
        );

    };


    // =====================================================
    // IMPORT
    // =====================================================

    const handleImport = async () => {

        setMessage("");
        setError("");


        // =================================================
        // FILE
        // =================================================

        if (!file) {

            setError(
                "Please select an Excel .xlsx file."
            );

            return;

        }


        try {

            setLoading(true);


            const result =
                await importBeneficiariesService(
                    file
                );


            setMessage(
                result?.message ||
                "Beneficiary import completed successfully."
            );


            setFile(null);


        }

        catch (error) {

            setError(

                error?.response?.data?.message ||

                error?.response?.data?.error ||

                error?.message ||

                "Beneficiary import failed."

            );

        }

        finally {

            setLoading(false);

        }

    };


    // =====================================================
    // DOWNLOAD TEMPLATE
    // =====================================================

    const handleTemplate = async () => {

        setMessage("");
        setError("");


        try {

            setLoading(true);


            const blob =
                await downloadBeneficiaryTemplateService();


            const fileBlob =
                blob instanceof Blob
                    ? blob
                    : new Blob(
                        [blob],
                        {
                            type:
                                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                        }
                    );


            const url =
                window.URL.createObjectURL(
                    fileBlob
                );


            const link =
                document.createElement("a");


            link.href =
                url;


            link.download =
                "beneficiary_import_template.xlsx";


            document.body.appendChild(
                link
            );


            link.click();


            link.remove();


            window.URL.revokeObjectURL(
                url
            );


        }

        catch (error) {

            console.error(
                "Template download failed:",
                error
            );


            setError(

                error?.response?.data?.message ||

                error?.message ||

                "Template download failed."

            );

        }

        finally {

            setLoading(false);

        }

    };


    // =====================================================
    // RENDER
    // =====================================================

    return (

        <PageContainer>


            <PageHeader

                title="Import Beneficiaries"

                subtitle={
                    "Bulk upload beneficiaries from an Excel file"
                }

            />


            <PageCard>

                <Stack spacing={3}>


                    {/* =====================================
                        INSTRUCTIONS
                    ====================================== */}

                    <Typography
                        variant="body2"
                        color="text.secondary"
                    >
                        Download the Excel template, fill in
                        the beneficiary information, then upload
                        the completed .xlsx file.
                    </Typography>


                    {/* =====================================
                        AGE INFORMATION
                    ====================================== */}

                    <AppAlert

                        severity="info"

                        message={
                            "Age is calculated automatically from Date of Birth. Do not enter or modify age manually."
                        }

                    />


                    {/* =====================================
                        TEMPLATE + FILE
                    ====================================== */}

                    <Stack

                        direction={{
                            xs: "column",
                            sm: "row"
                        }}

                        spacing={2}

                    >


                        {/* =================================
                            DOWNLOAD TEMPLATE
                        ================================= */}

                        <AppButton

                            variant="outlined"

                            startIcon={
                                <Download />
                            }

                            onClick={
                                handleTemplate
                            }

                            disabled={
                                loading
                            }

                        >
                            Download Template
                        </AppButton>


                        {/* =================================
                            FILE SELECT
                        ================================= */}

                        <AppButton

                            variant="outlined"

                            component="label"

                            startIcon={
                                <UploadFile />
                            }

                            disabled={
                                loading
                            }

                        >

                            Select Excel File

                            <input

                                hidden

                                type="file"

                                accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

                                onChange={
                                    handleFileChange
                                }

                            />

                        </AppButton>


                    </Stack>


                    {/* =====================================
                        SELECTED FILE
                    ====================================== */}

                    {file && (

                        <PageCard

                            variant="outlined"

                            sx={{
                                backgroundColor:
                                    "background.default"
                            }}

                        >

                            <Stack spacing={0.5}>


                                <Typography

                                    variant="body2"

                                    color="text.secondary"

                                >
                                    Selected file
                                </Typography>


                                <Typography
                                    fontWeight={600}
                                >
                                    {file.name}
                                </Typography>


                                <Typography

                                    variant="caption"

                                    color="text.secondary"

                                >
                                    {(
                                        file.size /
                                        1024
                                    ).toFixed(1)} KB
                                </Typography>


                            </Stack>

                        </PageCard>

                    )}


                    {/* =====================================
                        SUCCESS
                    ====================================== */}

                    {message && (

                        <AppAlert

                            severity="success"

                            message={
                                message
                            }

                        />

                    )}


                    {/* =====================================
                        ERROR
                    ====================================== */}

                    {error && (

                        <AppAlert

                            severity="error"

                            message={
                                error
                            }

                        />

                    )}


                    {/* =====================================
                        ACTIONS
                    ====================================== */}

                    <Stack sx={{ justifyContent: "flex-end" }}

                        direction={{
                            xs: "column-reverse",
                            sm: "row"
                        }}

                        spacing={2}

                    >


                        <AppButton

                            variant="outlined"

                            onClick={() =>
                                navigate(
                                    "/beneficiaries"
                                )
                            }

                            disabled={
                                loading
                            }

                        >
                            Back
                        </AppButton>


                        <AppButton

                            variant="contained"

                            disabled={
                                loading ||
                                !file
                            }

                            loading={
                                loading
                            }

                            onClick={
                                handleImport
                            }

                        >
                            Import Beneficiaries
                        </AppButton>


                    </Stack>


                </Stack>

            </PageCard>

        </PageContainer>

    );

};


export default BeneficiaryImportPage;