const axios = require('axios');
const stream = require("stream")
const FormData = require('form-data');
const config = require("../../config")

module.exports = async (file) => {
    if (!file) return {};


    const formData = new FormData();
    const bufferStream = new stream.Readable.from(file.buffer)

    formData.append("file", bufferStream, {
        filename: file.originalname
    })

    try{
        const request = await axios.post(config.CDNUrl + "/upload", formData, {
            headers: {
                'Content-Type': 'multipart/form-data',
                'token': process.env.CDN_TOKEN
            }
        })

        return {
            error: false,
            errorCode: null,
            url: request.data.url,
            filename: request.data.filename
        }
        
    }catch(e){
        console.log(e, "ER")
        return {
            error: true,
            errorCode: e.response?.data?.errorCode || null,
            url: null,
            filename: null
        }
    }


}