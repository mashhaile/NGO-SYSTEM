import axiosClient
    from "../../services/axiosClient";


// =====================================================
// REPORT CENTER API
// =====================================================
//
//   catalog            the reports this role can open
//   report(key)        one subject report
//   detail(kind, id)   one record (profile, program …)
//   download(…)        the same as Excel, PDF or CSV
//
// =====================================================

export const getCatalogApi = async () =>
    (await axiosClient.get("/report-center")).data.data;

export const getReportApi = async (key, params = {}) =>
    (await axiosClient.get(`/report-center/${key}`, { params })).data.data;

export const getDetailApi = async (kind, id, params = {}) =>
    (await axiosClient.get(`/report-center/detail/${kind}/${id}`, { params })).data.data;


// Save the file the server makes (name from its header)
export const downloadReportApi = async (path, params, format) => {

    const response =
        await axiosClient.get(path, {
            params: { ...params, format },
            responseType: "blob"
        });

    const header = response.headers?.["content-disposition"] || "";
    const match = header.match(/filename="?([^";]+)"?/i);
    const name = match ? match[1] : `report.${format === "excel" ? "xlsx" : format}`;

    const url = URL.createObjectURL(response.data);
    const link = document.createElement("a");
    link.href = url;
    link.download = name;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);

};
