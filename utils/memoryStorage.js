import multer from 'multer';

// Configure Multer to store the file in memory
const storage = multer.memoryStorage();
const uploadStream = multer({ storage: storage });

export default uploadStream;