const express = require('express');
const axios = require('axios');
const formData = require('form-data');
const multer = require('multer');
const path = require('path');

const app = express();
const upload = multer(); // Handles the image uploads from your form

// 1. Serve your static HTML files from the root
app.use(express.static('.'));
app.use(express.json());

// 2. The "Proxy" endpoint that hides n8n from the browser
app.post('/api/enhance', upload.array('images'), async (req, res) => {
  try {
    const n8nUrl = 'https://imageenhancement-production.up.railway.app/webhook/Batch_EnhancementOptionsWeb';
    
    // Rebuild the form data to send to n8n
    const form = new formData();
    form.append('back_plane', req.body.back_plane);
    form.append('time_of_day', req.body.time_of_day);
    form.append('paver_style', req.body.paver_style);
    form.append('paver_pattern', req.body.paver_pattern);
    form.append('image_quality', req.body.image_quality);

    // Attach the images
    req.files.forEach(file => {
      form.append('images', file.buffer, { filename: file.originalname });
    });

    // Send to n8n - Servers calling servers = No CORS errors!
    const response = await axios.post(n8nUrl, form, {
      headers: { ...form.getHeaders() }
    });

    res.json(response.data);
  } catch (error) {
    console.error('Proxy Error:', error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// 3. Status Proxy (for polling)
app.get('/api/status', async (req, res) => {
  try {
    const statusUrl = `https://imageenhancement-production.up.railway.app/webhook/check-status?jobId=${req.query.jobId}`;`;
    const response = await axios.get(statusUrl);
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: 'Status check failed' });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));