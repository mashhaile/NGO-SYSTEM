const buildSearch = (
    search = "",
    fields = []
) => {


    const value = search.trim();


    if (!value || value.length < 2) {

        return {};

    }



    const regex = new RegExp(
        value,
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