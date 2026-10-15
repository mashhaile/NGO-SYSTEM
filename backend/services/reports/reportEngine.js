const reportRegistry =
require("./reportRegistry");



const generateReport = async (

    reportName,

    filters,

    context

) => {


    const report =
        reportRegistry[reportName];



    if(!report){

        throw new Error(
            `Unknown report: ${reportName}`
        );

    }


console.log(
    "ENGINE CONTEXT =",
    context
);


return await report.generate(
    filters,
    context
);
   

};



module.exports = {

    generateReport

};