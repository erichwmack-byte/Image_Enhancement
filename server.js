const dns = require('dns');
dns.setDefaultResultOrder('ipv4first');

const express = require('express');
const axios = require('axios');
const FormData = require('form-data');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');
const Stripe = require('stripe');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const crypto = require('crypto');

const app = express();
const upload = multer();

const N8N_BASE_URL = 'https://courteous-solace-production-413f.up.railway.app';
const CALLBACK_SECRET = 'sf_upscale_callback_2024';

const S3_BUCKET = 'imageenhancement-production-storage';
const S3_REGION = process.env.AWS_REGION || 'us-east-2';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const s3Client = new S3Client({
  region: S3_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});

const CREDIT_PACKS = {
  starter:      { credits: 40,  price: 2500,  name: '$25 - 40 Credits' },
  professional: { credits: 90,  price: 5000,  name: '$50 - 90 Credits' },
  studio:       { credits: 200, price: 10000, name: '$100 - 200 Credits' }
};

const CREDIT_COSTS = {
  enhance: 1,
  animate: 4
};

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.static('.'));
app.use('/webhooks/stripe', express.raw({ type: 'application/json' }));
app.use(express.json());

// ── Auth Middleware ───────────────────────────────────────────────────────────
async function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token provided' });
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) return res.status(401).json({ error: 'Invalid token' });
  req.user = user;
  next();
}

// ── S3 Helper ─────────────────────────────────────────────────────────────────
async function uploadBufferToS3(buffer, key, contentType) {
  const command = new PutObjectCommand({
    Bucket: S3_BUCKET,
    Key: key,
    Body: buffer,
    ContentType: contentType || 'image/jpeg',
    ACL: 'public-read'
  });
  await s3Client.send(command);
  return `https://${S3_BUCKET}.s3.${S3_REGION}.amazonaws.com/${key}`;
}

function generateJobId() {
  return crypto.randomBytes(8).toString('hex');
}

// ── Auth Routes ───────────────────────────────────────────────────────────────
app.post('/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  const { data, error } = await supabase.auth.signUp({ email, password });
  if (error) return res.status(400).json({ error: error.message });
  res.json({ user: data.user, session: data.session });
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) return res.status(400).json({ error: error.message });
  res.json({ user: data.user, session: data.session });
});

app.post('/auth/logout', requireAuth, async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  await supabase.auth.admin.signOut(token);
  res.json({ success: true });
});

// ── Password Reset Routes ─────────────────────────────────────────────────────
app.post('/auth/reset-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });
  const { error } = await supabase.auth.resetPasswordForEmail(email, {
    redirectTo: `${req.headers.origin}?reset=true`
  });
  if (error) return res.status(400).json({ error: error.message });
  res.json({ success: true });
});

app.post('/auth/update-password', requireAuth, async (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  const { error } = await supabase.auth.admin.updateUserById(req.user.id, {
    password
  });
  if (error) return res.status(400).json({ error: error.message });
  res.json({ success: true });
});

// ── Credits Routes ────────────────────────────────────────────────────────────
app.get('/api/credits', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('credits')
    .select('balance')
    .eq('user_id', req.user.id)
    .single();
  if (error) return res.status(500).json({ error: 'Could not fetch credits' });
  res.json({ balance: data.balance });
});

async function deductCredits(userId, amount, type, description) {
  const { data: credits } = await supabase
    .from('credits')
    .select('balance')
    .eq('user_id', userId)
    .single();

  if (!credits || credits.balance < amount) return false;

  await supabase
    .from('credits')
    .update({ balance: credits.balance - amount, updated_at: new Date() })
    .eq('user_id', userId);

  await supabase
    .from('credit_transactions')
    .insert({ user_id: userId, amount: -amount, type, description });

  return true;
}

// ── Stripe Routes ─────────────────────────────────────────────────────────────
app.post('/api/purchase', requireAuth, async (req, res) => {
  const { pack } = req.body;
  const creditPack = CREDIT_PACKS[pack];
  if (!creditPack) return res.status(400).json({ error: 'Invalid pack' });

  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    line_items: [{
      price_data: {
        currency: 'usd',
        product_data: { name: creditPack.name },
        unit_amount: creditPack.price
      },
      quantity: 1
    }],
    mode: 'payment',
    success_url: `${req.headers.origin}?purchase=success&credits=${creditPack.credits}`,
    cancel_url: `${req.headers.origin}?purchase=cancelled`,
    metadata: {
      user_id: req.user.id,
      credits: creditPack.credits,
      pack
    }
  });

  res.json({ url: session.url });
});

app.post('/webhooks/stripe', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).json({ error: `Webhook error: ${err.message}` });
  }

  if (event.type === 'checkout.session.completed') {
    try {
      const session = event.data.object;
      const { user_id, credits } = session.metadata;
      const creditsToAdd = parseInt(credits);

      const { data: existing } = await supabase
        .from('credits')
        .select('balance')
        .eq('user_id', user_id)
        .single();

      if (existing) {
        await supabase
          .from('credits')
          .update({ balance: existing.balance + creditsToAdd, updated_at: new Date() })
          .eq('user_id', user_id);
      } else {
        await supabase
          .from('credits')
          .insert({ user_id, balance: creditsToAdd });
      }

      await supabase
        .from('credit_transactions')
        .insert({
          user_id,
          amount: creditsToAdd,
          type: 'purchase',
          description: `Purchased ${creditsToAdd} credits`
        });

      console.log(`Credits added: ${creditsToAdd} for user ${user_id}`);
    } catch (err) {
      console.error('Webhook processing error:', err.message);
      return res.status(500).json({ error: err.message });
    }
  }

  res.json({ received: true });
});

// ── Enhance Proxy (with credit check) ────────────────────────────────────────
// Phase 1 change: server.js now uploads each raw file to S3 itself, creates a
// `projects` row + one `project_images` row per image (status: processing),
// then forwards S3 URLs (not binaries) to n8n instead of raw multipart files.
app.post('/api/enhance', requireAuth, upload.array('images'), async (req, res) => {
  const imageCount = req.files?.length || 1;
  const creditsNeeded = imageCount * CREDIT_COSTS.enhance;

  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'No images provided' });
  }

  const deducted = await deductCredits(
    req.user.id,
    creditsNeeded,
    'enhance',
    `Enhanced ${imageCount} image(s)`
  );
  if (!deducted) return res.status(402).json({ error: 'Insufficient credits' });

  const jobId = generateJobId();

  try {
    // 1. Upload every raw file to S3 first, in parallel.
    const uploads = await Promise.all(
      req.files.map(async (file, index) => {
        const ext = (file.originalname.split('.').pop() || 'jpg').toLowerCase();
        const key = `${jobId}_raw_${index}_${Date.now()}.${ext}`;
        const rawUploadUrl = await uploadBufferToS3(file.buffer, key, file.mimetype);
        return { index, rawUploadUrl, filename: file.originalname };
      })
    );

    // 2. Create the parent `projects` row.
    const { error: projectError } = await supabase
      .from('projects')
      .insert({
        user_id: req.user.id,
        job_id: jobId,
        project_name: `Project — ${new Date().toLocaleDateString()}`,
        status: 'processing'
      });

    if (projectError) {
      console.error('Supabase project insert error:', projectError.message);
      return res.status(500).json({ error: 'Could not create project' });
    }

    // 3. Create one `project_images` row per uploaded image.
    const { data: projectRow } = await supabase
      .from('projects')
      .select('id')
      .eq('job_id', jobId)
      .single();

    const projectImagesPayload = uploads.map(u => ({
      project_id: projectRow.id,
      image_index: String(u.index),
      image_name: `Image ${u.index + 1}`,
      raw_upload_url: u.rawUploadUrl,
      status: 'processing'
    }));

    const { error: imagesError } = await supabase
      .from('project_images')
      .insert(projectImagesPayload);

    if (imagesError) {
      console.error('Supabase project_images insert error:', imagesError.message);
      return res.status(500).json({ error: 'Could not create project images' });
    }

    // 4. Forward S3 URLs (not binaries) to n8n.
    const n8nUrl = `${N8N_BASE_URL}/webhook/Batch_EnhancementOptionsWeb`;
    const response = await axios.post(n8nUrl, {
      job_id: jobId,
      back_plane: req.body.back_plane || '',
      time_of_day: req.body.time_of_day || '',
      paver_style: req.body.paver_style || '',
      paver_pattern: req.body.paver_pattern || '',
      image_quality: req.body.image_quality || '',
      user_email: req.user.email || '',
      user_id: req.user.id || '',
      images: uploads.map(u => ({
        image_index: String(u.index),
        raw_upload_url: u.rawUploadUrl
      }))
    }, {
      headers: { 'Content-Type': 'application/json' }
    });

    const responseData = response.data;
    if (!responseData.jobId && !responseData.job_id) {
      console.warn('Warning: n8n responded without a jobId.');
    }

    return res.status(200).json({
      jobId: jobId,
      status: 'pending',
      ...responseData
    });

  } catch (error) {
    const errorData = error.response?.data || error.message;
    console.error('Enhance error:', errorData);
    return res.status(500).json({ error: 'Enhancement request failed', details: errorData });
  }
});

// ── Animate Proxy (with credit check) ────────────────────────────────────────
app.post('/api/animate', requireAuth, async (req, res) => {
  const deducted = await deductCredits(
    req.user.id,
    CREDIT_COSTS.animate,
    'animate',
    'Animated 1 image'
  );
  if (!deducted) return res.status(402).json({ error: 'Insufficient credits' });

  try {
    const n8nUrl = `${N8N_BASE_URL}/webhook/animate_image`;
    const response = await axios.post(n8nUrl, req.body, {
      headers: { 'Content-Type': 'application/json' }
    });
    return res.status(response.status).json(response.data);
  } catch (error) {
    console.error('Animate error:', error.response?.data || error.message);
    return res.status(500).json({ error: 'Animation request failed' });
  }
});

// ── Upscale: Start Job (async — returns immediately) ─────────────────────────
app.post('/api/upscale', requireAuth, async (req, res) => {
  const { imageUrl, jobId, imageIndex } = req.body;

  if (!imageUrl || !jobId) {
    return res.status(400).json({ error: 'Missing imageUrl or jobId' });
  }

  try {
    const { error: insertError } = await supabase
      .from('upscale_jobs')
      .insert({
        job_id: jobId,
        image_index: String(imageIndex),
        user_id: req.user.id,
        original_url: imageUrl,
        status: 'processing'
      });

    if (insertError) {
      console.error('Supabase insert error:', insertError.message);
      return res.status(500).json({ error: 'Could not create upscale job' });
    }

    const n8nUrl = `${N8N_BASE_URL}/webhook/upscale_image`;
    axios.post(n8nUrl, {
      image_url: imageUrl,
      job_id: jobId,
      image_index: String(imageIndex),
      user_email: req.user.email,
      output_quality: req.body.outputQuality || 80
    }, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 120000
    }).catch(err => {
      console.error('n8n upscale fire-and-forget error:', err.message);
    });

    return res.status(200).json({
      status: 'processing',
      job_id: jobId,
      image_index: String(imageIndex)
    });

  } catch (error) {
    console.error('Upscale error:', error.message);
    return res.status(500).json({ error: 'Upscale request failed' });
  }
});

// ── Upscale: Callback from n8n ───────────────────────────────────────────────
app.post('/api/upscale-callback', async (req, res) => {
  const secret = req.headers['x-callback-secret'];
  if (secret !== CALLBACK_SECRET) {
    return res.status(403).json({ error: 'Invalid callback secret' });
  }

  const { job_id, image_index, status, upscaled_url, error_message } = req.body;

  if (!job_id || !image_index) {
    return res.status(400).json({ error: 'Missing job_id or image_index' });
  }

  try {
    const updateData = {
      status: status || 'completed',
      completed_at: new Date()
    };
    if (upscaled_url) updateData.upscaled_url = upscaled_url;
    if (error_message) updateData.error_message = error_message;

    const { error } = await supabase
      .from('upscale_jobs')
      .update(updateData)
      .eq('job_id', job_id)
      .eq('image_index', String(image_index));

    if (error) {
      console.error('Callback update error:', error.message);
      return res.status(500).json({ error: 'Could not update job' });
    }

    // Phase 1 addition: also update the canonical project_images row so the
    // history gallery / badges always reflect the latest upscale state.
    if (upscaled_url) {
      const { data: projectRow } = await supabase
        .from('projects')
        .select('id')
        .eq('job_id', job_id)
        .single();

      if (projectRow) {
        await supabase
          .from('project_images')
          .update({
            upscaled_url: upscaled_url,
            current_url: upscaled_url,
            resolution_badge: '4K'
          })
          .eq('project_id', projectRow.id)
          .eq('image_index', String(image_index));
      }
    }

    console.log(`Upscale completed: ${job_id} image ${image_index}`);
    return res.status(200).json({ received: true });

  } catch (error) {
    console.error('Callback error:', error.message);
    return res.status(500).json({ error: 'Callback processing failed' });
  }
});

// ── Upscale: Status Check ────────────────────────────────────────────────────
app.get('/api/upscale-status', requireAuth, async (req, res) => {
  const { jobId, imageIndex } = req.query;

  if (!jobId || !imageIndex) {
    return res.status(400).json({ error: 'Missing jobId or imageIndex' });
  }

  try {
    const { data, error } = await supabase
      .from('upscale_jobs')
      .select('status, upscaled_url, error_message')
      .eq('job_id', jobId)
      .eq('image_index', String(imageIndex))
      .single();

    if (error || !data) {
      return res.status(404).json({ error: 'Job not found' });
    }

    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).json({
      status: data.status,
      upscaled_url: data.upscaled_url || null,
      error_message: data.error_message || null
    });

  } catch (error) {
    console.error('Status check error:', error.message);
    return res.status(500).json({ error: 'Status check failed' });
  }
});

// ── Refine: Start Job (async — returns immediately) ──────────────────────────
app.post('/api/refine', requireAuth, async (req, res) => {
  const { imageUrl, jobId, imageIndex, prompt } = req.body;

  if (!imageUrl || !jobId || !prompt) {
    return res.status(400).json({ error: 'Missing imageUrl, jobId, or prompt' });
  }

  try {
    const { error: insertError } = await supabase
      .from('refine_jobs')
      .insert({
        job_id: jobId,
        image_index: String(imageIndex),
        user_id: req.user.id,
        source_url: imageUrl,
        prompt: prompt,
        status: 'processing'
      });

    if (insertError) {
      console.error('Supabase insert error:', insertError.message);
      return res.status(500).json({ error: 'Could not create refine job' });
    }

    const n8nUrl = `${N8N_BASE_URL}/webhook/refine_image`;
    axios.post(n8nUrl, {
      image_url: imageUrl,
      job_id: jobId,
      image_index: String(imageIndex),
      user_email: req.user.email,
      prompt: prompt
    }, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 120000
    }).catch(err => {
      console.error('n8n refine fire-and-forget error:', err.message);
    });

    return res.status(200).json({
      status: 'processing',
      job_id: jobId,
      image_index: String(imageIndex)
    });

  } catch (error) {
    console.error('Refine error:', error.message);
    return res.status(500).json({ error: 'Refine request failed' });
  }
});

// ── Refine: Callback from n8n ────────────────────────────────────────────────
app.post('/api/refine-callback', async (req, res) => {
  const secret = req.headers['x-callback-secret'];
  if (secret !== CALLBACK_SECRET) {
    return res.status(403).json({ error: 'Invalid callback secret' });
  }

  const { job_id, image_index, status, refined_url, error_message } = req.body;

  if (!job_id || !image_index) {
    return res.status(400).json({ error: 'Missing job_id or image_index' });
  }

  try {
    const updateData = {
      status: status || 'completed',
      completed_at: new Date()
    };
    if (refined_url) updateData.refined_url = refined_url;
    if (error_message) updateData.error_message = error_message;

    const { error } = await supabase
      .from('refine_jobs')
      .update(updateData)
      .eq('job_id', job_id)
      .eq('image_index', String(image_index));

    if (error) {
      console.error('Refine callback update error:', error.message);
      return res.status(500).json({ error: 'Could not update job' });
    }

    // Phase 1 addition: keep project_images.current_url in sync with refine results.
    if (refined_url) {
      const { data: projectRow } = await supabase
        .from('projects')
        .select('id')
        .eq('job_id', job_id)
        .single();

      if (projectRow) {
        await supabase
          .from('project_images')
          .update({ current_url: refined_url })
          .eq('project_id', projectRow.id)
          .eq('image_index', String(image_index));
      }
    }

    console.log(`Refine completed: ${job_id} image ${image_index}`);
    return res.status(200).json({ received: true });

  } catch (error) {
    console.error('Refine callback error:', error.message);
    return res.status(500).json({ error: 'Callback processing failed' });
  }
});

// ── Refine: Status Check ─────────────────────────────────────────────────────
app.get('/api/refine-status', requireAuth, async (req, res) => {
  const { jobId, imageIndex } = req.query;

  if (!jobId || !imageIndex) {
    return res.status(400).json({ error: 'Missing jobId or imageIndex' });
  }

  try {
    const { data, error } = await supabase
      .from('refine_jobs')
      .select('status, refined_url, error_message')
      .eq('job_id', jobId)
      .eq('image_index', String(imageIndex))
      .order('created_at', { ascending: false })
      .limit(1)
      .single();

    if (error || !data) {
      return res.status(404).json({ error: 'Job not found' });
    }

    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).json({
      status: data.status,
      refined_url: data.refined_url || null,
      error_message: data.error_message || null
    });

  } catch (error) {
    console.error('Refine status check error:', error.message);
    return res.status(500).json({ error: 'Status check failed' });
  }
});

// ── Project: Enhancement Job Completion Callback from n8n ───────────────────
// Phase 2 will extend this further (healed_url etc). For Phase 1, n8n's
// Job Completed step is unchanged (still writes to Sheets); this route is
// added now so n8n can optionally start posting back to Supabase as soon
// as the Batch Enhancement workflow is updated in Step 1.3/1.4.
app.post('/api/project-image-update', async (req, res) => {
  const secret = req.headers['x-callback-secret'];
  if (secret !== CALLBACK_SECRET) {
    return res.status(403).json({ error: 'Invalid callback secret' });
  }

  const { job_id, image_index, original_url, enhanced_url, healed_url, status, error_message } = req.body;

  if (!job_id || image_index === undefined) {
    return res.status(400).json({ error: 'Missing job_id or image_index' });
  }

  try {
    const { data: projectRow, error: projectLookupError } = await supabase
      .from('projects')
      .select('id')
      .eq('job_id', job_id)
      .single();

    if (projectLookupError || !projectRow) {
      console.error('Project lookup error:', projectLookupError?.message);
      return res.status(404).json({ error: 'Project not found for job_id' });
    }

    const updateData = {};
    if (original_url) updateData.original_url = original_url;
    if (enhanced_url) updateData.enhanced_url = enhanced_url;
    if (healed_url) {
      updateData.healed_url = healed_url;
      updateData.current_url = healed_url;
    }
    if (status) updateData.status = status;
    if (error_message) updateData.error_message = error_message;

    const { error: updateError } = await supabase
      .from('project_images')
      .update(updateData)
      .eq('project_id', projectRow.id)
      .eq('image_index', String(image_index));

    if (updateError) {
      console.error('project_images update error:', updateError.message);
      return res.status(500).json({ error: 'Could not update project image' });
    }

    return res.status(200).json({ received: true });

  } catch (error) {
    console.error('project-image-update error:', error.message);
    return res.status(500).json({ error: 'Update processing failed' });
  }
});

// ── Status Proxy ──────────────────────────────────────────────────────────────
app.get('/api/status', requireAuth, async (req, res) => {
  const { jobId } = req.query;
  if (!jobId || jobId === 'undefined') {
    return res.status(400).json({ error: 'Missing or invalid jobId' });
  }
  try {
    const statusUrl = `${N8N_BASE_URL}/webhook/check-status?jobId=${jobId}`;
    const response = await axios.get(statusUrl);
    res.setHeader('Cache-Control', 'no-store');
    return res.status(response.status).json(response.data);
  } catch (error) {
    console.error('Status error:', error.response?.data || error.message);
    return res.status(500).json({ error: 'Status check failed' });
  }
});

// ── Start Server ──────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`-----------------------------------------------`);
  console.log(`Server running on port ${PORT}`);
  console.log(`Targeting n8n at: ${N8N_BASE_URL}`);
  console.log(`-----------------------------------------------`);
});
