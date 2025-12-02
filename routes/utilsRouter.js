import express from 'express'
import uploadStream from '../utils/memoryStorage.js'
import imageUploadService from '../services/imageUploadService.js';

const utilsRouter = express.Router();

utilsRouter.post('/',uploadStream.single('logo'), imageUploadService);

export default utilsRouter;