const express = require('express');
const axios = require('axios');
const FormData = require('form-data');
const multer = require('multer');

const app = express();
const upload = multer(); // Handles the image uploads from your form

// Base URL for n8n (Corrected to your new Railway instance)
const N8N_BASE_URL = 'https://courteous-solace-production-413f.up.railway.app';

// 1. Serve your static HTML files from the root
app.use(express.static('.'));
app.use(express.json());

// 2. The "Proxy" endpoint that hides n8n from the browser
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

    // Attach the images
    if (req.files && req.files.length > 0) {
      req.files.forEach(file => {
        form.append('images', file.buffer, {
          filename: file.originalname,
          contentType: file.mimetype
        });
      });
    }

    // Send to n8n
    const response = await axios.post(n8nUrl, form, {
      headers: form.getHeaders(),
      maxContentLength: Infinity,
      maxBodyLength: Infinity
    });

    return res.status(response.status).json(response.data);

  } catch (error) {
    console.error('Proxy Error:', error.response?.data || error.message);
    return res.status(500).json({ error: 'Enhancement request failed' });
  }
});

// 3. Status Proxy (for polling)
app.get('/api/status', async (req, res) => {
  try {
    const statusUrl = `${N8N_BASE_URL}/webhook/check-status?jobId=${req.query.jobId}`;
    const response = await axios.get(statusUrl);
    
    // Force the browser to not cache this status check
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    
    return res.status(response.status).json(response.data);
  } catch (error) {
    console.error('Status Error:', error.response?.data || error.message);
    return res.status(500).json({ error: 'Status check failed' });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
