import DevKey from '../models/devKeyModel.js';
export const validateDevKey = async (devKey, session = null) => {
    // Check if devKey exists
    const key = await DevKey.findOne({ key: devKey }).session(session);
  
    if (!key) throw new Error(`Invalid dev key: ${devKey}`);
  
    // Check if the dev key has already been used
    if (key.isUsed) throw new Error(`Dev key already used: ${devKey}`);
  
    // Check if the dev key has expired
    if (new Date(key.expirationDate) < new Date()) throw new Error(`Dev key has expired: ${devKey}`);
  
    return key; // Return the key if all checks pass
  };