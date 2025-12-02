import DevKey from '../models/devKeyModel.js'; // Ensure this path is correct
import { ClientError, ServerError } from '../utils/errorHandler.js';

const generateUniqueDevKey = () => {
    return 'dev-key_' + Math.random().toString(36).substring(2, 15);
};


export const generateDevKeyService = async () => {
    try {
        const devKey = new DevKey({
            key: generateUniqueDevKey(), // Implement your logic to generate a unique key
            expirationDate: new Date(new Date().getTime() + 24 * 60 * 60 * 1000), // 1 day validity
            used: false,
        });

        await devKey.save();

        return devKey;
    } catch (error) {
        throw new ServerError('Error while generating dev key');
    }
};


export const getAllDevKeysService = async () => {
    try {
        const devKeys = await DevKey.find();
        return devKeys;
    } catch (error) {
        throw new ServerError('Error while fetching dev keys');
    }
};



// Service to mark a dev key as used
export const useDevKeyService = async (devKey) => {
  try {
    // Find the dev key in the database
    const key = await DevKey.findOne({ key: devKey });

    if (!key) {
      throw new ClientError('Dev key not found', 400);
    }

    if (key.isUsed) {
      throw new ClientError('Dev key already used', 400);
    }

    // Mark the key as used and save the changes
    key.isUsed = true;
    await key.save();

    return { message: 'Dev key marked as used' };
  } catch (error) {
    if (error instanceof ClientError) {
      throw error; // Re-throw ClientErrors for consistent error handling
    }
    throw new ServerError('Error while marking dev key as used');
  }
};

