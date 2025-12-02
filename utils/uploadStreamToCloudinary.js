import { v2 as cloudinary } from "cloudinary";

// Configure Cloudinary with your credentials
cloudinary.config({
  cloud_name: "dpgj9mrly",
  api_key: "551968651855126",
  api_secret: "BAE53B15sBunaCEbmg1gNQM5VV8",
});

const getFileExtension = (fileName)=>{
  return fileName.split('.').pop();
}

const uploadStreamToCloudinary = async (file, folderName, fileName, retries = 2) => {
  const fileExtension = getFileExtension(file.originalname)
  return new Promise((resolve, reject) => {
    const uploadFunction = (retryCount) => {
      cloudinary.uploader.upload_stream(
        {
          resource_type: 'raw', // Specify that you are uploading a raw file
          public_id: `${folderName}/${fileName}.${fileExtension}` // Set folder name and file name
        },
        function (error, result) {
          if (error) {
            console.error("Error uploading file to Cloudinary:", error);
            if (retryCount > 0) {
              console.log(`Retrying upload. ${retryCount} retries left...`);
              uploadFunction(retryCount - 1); // Retry the upload
            } else {
              console.error("Retry limit reached. Upload failed.");
              reject(error);
            }
          } else {
            console.log("File uploaded to Cloudinary successfully");
            resolve(result?.secure_url); // Return the secure URL of the uploaded file
          }
        }
      ).end(file.buffer);
    };

    uploadFunction(retries);
  });
};

export default uploadStreamToCloudinary;
