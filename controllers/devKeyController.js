// controllers/devKeyController.js
import { generateDevKeyService, getAllDevKeysService, useDevKeyService } from '../services/devKeyServices.js';
import { catchAsyncError } from '../middlewares/catchAsyncError.js';

export const generateDevKey = catchAsyncError(async (req, res) => {
  // Call the service to generate a new dev key
  const devKey = await generateDevKeyService();

  res.status(201).json({
    status: "success",
    data: { devKey: devKey.key },
    message: 'Dev key generated successfully',
  });
});

// Get all DevKeys (for testing purposes)

export const getAllDevKeys = catchAsyncError(async (req, res) => {
  // Fetch all dev keys using the service
  const devKeys = await getAllDevKeysService();

  // Respond with the fetched data
  res.status(200).json({
    status: "success",
    data: { devKeys },
    message: 'Dev keys fetched successfully',
  });
});
// Mark a DevKey as used (for testing purposes)
export const useDevKey = catchAsyncError(async (req, res) => {
  const { devKey } = req.body;

  if (!devKey) {
    throw new ClientError('Dev key is required', 400);
  }

  // Use the service to mark the key as used
  const { message } = await useDevKeyService(devKey);

  // Send a successful response
  res.status(200).json({
    status: "success",
    message: message,
  });
});
