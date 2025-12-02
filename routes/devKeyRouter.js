//just fo development purpose

import express from 'express';
import { generateDevKey, getAllDevKeys, useDevKey } from '../controllers/devKeyController.js';

const router = express.Router();

router.post('/generate', generateDevKey);

// Route to get all DevKeys (for testing purposes) - no authentication required
router.get('/', getAllDevKeys);

// Route to mark a DevKey as used (for testing purposes) - no authentication required
router.put('/use', useDevKey);

export default router;
