const Counter = require("../models/Counter");


const generateSequence = async (

    moduleName,

    prefix,

    organizationId

) => {


    const counter =

        await Counter.findOneAndUpdate(

            {

                organization:organizationId,

                module:moduleName

            },


            {

                $inc:{
                    sequence:1
                }

            },


            {

                upsert:true,

                new:true

            }

        );



    const number =

        counter.sequence

        .toString()

        .padStart(6,"0");



    return `${prefix}-${number}`;


};



module.exports = generateSequence;