
import path from 'path'
import fs from 'fs'
import uploadStreamToCloudinary from './uploadStreamToCloudinary.js';
import uploadToCloudinary from './uploadToCloudinary.js';


const getFileExtension = (fileName)=>{
   return fileName.split(".").pop();
}

const uploadAndGetAvatarUrl = async (file, folder, resourceId, type = "stream") => {
    if(type === 'stream'){
        const avatarUrl = await uploadStreamToCloudinary(file,`CRM/profile/${folder}`, resourceId, 2);
        return avatarUrl
    }else{
    const avatarUrl = await uploadToCloudinary(path, `CRM/Profile/${folder}`,resourceId,2);
    fs.unlinkSync(path);
    return avatarUrl;
    }
};


export default uploadAndGetAvatarUrl;