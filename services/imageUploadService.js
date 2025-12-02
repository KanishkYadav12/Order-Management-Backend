import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import uploadAndGetAvatarUrl from "../utils/uploadAndGetUrl.js";

const imageUploadService = catchAsyncError(async (req, res)=>{
    let logoUrl;
    const {folderName, fileName} = req.body;
    if (req.file) {
         logoUrl = await uploadAndGetAvatarUrl(req.file, `OMS-${folderName}`, fileName, "stream");
    }
    return res.json({status : "success", message : "imageUploaded successful", data : {url : logoUrl}})
});

export default imageUploadService;