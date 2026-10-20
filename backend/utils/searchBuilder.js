const escapeRegex = require("./escapeRegex");
const buildSearch = (
    search = "",
    fields = []
) => {


    const value = search.trim();


    if (!value || value.length < 2) {

        return {};

    }



    const regex = new RegExp(
        escapeRegex(value),
        "i"
    );



    return {


        $or: fields.map(field => ({


            [field]: regex


        }))


    };


};



module.exports = {
    buildSearch
};