const express = require('express');
const axios = require('axios');
const FormData = require('form-data');
const multer = require('multer');

const app = express();
const upload = multer(); // Handles the image uploads from your form

/**
 * CONFIGURATION
 * Using your specific Railway instance URL. 
 * If both services are in the same Railway project, 
 * you can eventually swap this for the private networking URL.
 */
const N8N_BASE_URL = 'https://courteous-solace-production-413f.up.railway.app';

// 1. Middleware
app.use(express.static('.')); // Serves your index.html and assets
app.use(express.json());

// 2. The "Enhance" Proxy - Initiates the n8n Workflow
app.post('/api/enhance', upload.array('images'), async (req, res) => {
  try {
    const n8nUrl = `${N8N_BASE_URL}/webhook/Batch_EnhancementOptionsWeb`;

    // Rebuild the form data to send to n8n
    const form = new FormData();
    form.append('back_plane', req.body.back_plane || '');
    form.append('time_of_day', req.body.time_of_day || '');
    form.append('paver_style', req.body.paver_style || '');
    form.append('paver_pattern', req.body.paver_pattern || '');
    form.append('image_quality', req.body.image_quality || '');

    // Attach the images from the upload
    if (req.files && req.files.length > 0) {
      req.files.forEach(file => {
        form.append('images', file.buffer, {
          filename: file.originalname,
          contentType: file.mimetype
        });
      });
    }

    console.log(`Forwarding request to n8n: ${n8nUrl}`);

    // Send to n8n
    const response = await axios.post(n8nUrl, form, {
      headers: {
        ...form.getHeaders(),
      },
      maxContentLength: Infinity,
      maxBodyLength: Infinity
    });

    /**
     * CRITICAL FIX: Ensure we send a valid JSON object back.
     * n8n must return { "jobId": "..." } in its 'Respond to Webhook' node.
     */
    const responseData = response.data;
    
    if (!responseData.jobId) {
      console.warn('Warning: n8n responded without a jobId. Check your Respond to Webhook node.');
    }

    return res.status(200).json(responseData);

  } catch (error) {
    const errorData = error.response?.data || error.message;
    console.error('Proxy Error Detail:', errorData);
    return res.status(500).json({ 
      error: 'Enhancement request failed',
      details: errorData 
    });
  }
});

// 3. Status Proxy - Polls the Status Check Workflow
app.get('/api/status', async (req, res) => {
  const { jobId } = req.query;

  // Guard against undefined jobId to prevent infinite loops
  if (!jobId || jobId === 'undefined') {
    return res.status(400).json({ error: 'Missing or invalid jobId parameter' });
  }

  try {
    const statusUrl = `${N8N_BASE_URL}/webhook/check-status?jobId=${jobId}`;
    const response = await axios.get(statusUrl);
    
    // Disable caching for status checks so we get real-time updates
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    
    return res.status(response.status).json(response.data);
  } catch (error) {
    console.error('Status Proxy Error:', error.response?.data || error.message);
    return res.status(500).json({ error: 'Status check failed' });
  }
});

// 4. Start Server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`-----------------------------------------------`);
  console.log(`Server running on port ${PORT}`);
  console.log(`Targeting n8n at: ${N8N_BASE_URL}`);
  console.log(`-----------------------------------------------`);
});
