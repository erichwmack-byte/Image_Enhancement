
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

    // 1b. Resolve the album this batch belongs to (existing pick or a new one).
    let albumId = (req.body.albumId || '').trim();
    let albumName = (req.body.albumName || '').trim();
    if (albumId) {
      const { data: album } = await supabase
        .from('albums').select('id, name, user_id').eq('id', albumId).single();
      if (!album || album.user_id !== req.user.id) {
        return res.status(404).json({ error: 'Album not found' });
      }
      albumName = album.name;
    } else {
      if (!albumName) albumName = `Album — ${new Date().toLocaleDateString()}`;
      const { data: newAlbum, error: albumErr } = await supabase
        .from('albums').insert({ user_id: req.user.id, name: albumName }).select('id').single();
      if (albumErr || !newAlbum) {
        console.error('Album insert error:', albumErr && albumErr.message);
        return res.status(500).json({ error: 'Could not create album' });
      }
      albumId = newAlbum.id;
    }

    // 2. Create the parent `projects` row (one per batch, linked to the album).
    const { error: projectError } = await supabase
      .from('projects')
      .insert({
        user_id: req.user.id,
        job_id: jobId,
        album_id: albumId,
        project_name: albumName,
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
          .update({ upscaled_url: upscaled_url, resolution_badge: '4K' })
          .eq('project_id', projectRow.id)
          .eq('image_index', String(image_index));

        // Record the upscale as a new version and make it the active/current image.
        const img = await getProjectImageByJob(job_id, image_index);
        if (img) {
          await appendVersion(img.id, { url: upscaled_url, source: 'upscale' });
        }
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
        // Record the refine as a new version and make it the active/current image.
        const img = await getProjectImageByJob(job_id, image_index);
        if (img) {
          const { data: rj } = await supabase
            .from('refine_jobs')
            .select('prompt')
            .eq('job_id', job_id)
            .eq('image_index', String(image_index))
            .maybeSingle();
          await appendVersion(img.id, { url: refined_url, source: 'refine', prompt: rj && rj.prompt ? rj.prompt : null });
        }
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

  const { job_id, image_index, original_url, enhanced_url, healed_url, current_url, status, error_message } = req.body;

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
    // Phase 2 (non-destructive heal): storing healed_url no longer auto-promotes
    // it to current_url. current_url changes only when explicitly sent (the
    // enhanced default from the batch loop) or via the authed /api/select-image pick.
    if (healed_url) updateData.healed_url = healed_url;
    if (current_url) updateData.current_url = current_url;
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

// ── Versions / Gallery helpers (Phase 2/3) ───────────────────────────────────
// Resolve the canonical project_images row from a (job_id, image_index) pair.
async function getProjectImageByJob(job_id, image_index) {
  const { data: projectRow } = await supabase
    .from('projects').select('id').eq('job_id', job_id).single();
  if (!projectRow) return null;
  const { data: imgRow } = await supabase
    .from('project_images').select('id, project_id')
    .eq('project_id', projectRow.id)
    .eq('image_index', String(image_index))
    .single();
  return imgRow || null;
}

// Load a project_images row and confirm the requesting user owns it (via projects.user_id).
async function getOwnedProjectImage(userId, projectImageId) {
  const { data, error } = await supabase
    .from('project_images')
    .select('id, project_id, enhanced_url, healed_url, current_url, active_version_id, projects!inner(user_id)')
    .eq('id', projectImageId)
    .single();
  if (error || !data) return null;
  if (!data.projects || data.projects.user_id !== userId) return null;
  return data;
}

// Append a new version to an image's history and make it the active/current image.
// The chain is append-only (lossless): undo/redo just move the active cursor.
async function appendVersion(projectImageId, opts) {
  const url = opts.url;
  const source = opts.source;
  const prompt = (opts && opts.prompt) ? opts.prompt : null;

  const { data: last } = await supabase
    .from('project_image_versions')
    .select('seq')
    .eq('project_image_id', projectImageId)
    .order('seq', { ascending: false })
    .limit(1)
    .maybeSingle();
  const nextSeq = (last && last.seq ? last.seq : 0) + 1;

  const { data: version, error: vErr } = await supabase
    .from('project_image_versions')
    .insert({ project_image_id: projectImageId, url: url, source: source, prompt: prompt, seq: nextSeq })
    .select('id, url, source, prompt, seq, created_at')
    .single();
  if (vErr) throw new Error('Could not insert version: ' + vErr.message);

  await supabase
    .from('project_images')
    .update({ active_version_id: version.id, current_url: url })
    .eq('id', projectImageId);

  return version;
}

// Move the active-version cursor backward (undo) or forward (redo) along the chain.
async function moveVersion(userId, projectImageId, dir) {
  const img = await getOwnedProjectImage(userId, projectImageId);
  if (!img) return { code: 404, body: { error: 'Image not found' } };

  const { data: versions } = await supabase
    .from('project_image_versions')
    .select('id, url, seq')
    .eq('project_image_id', projectImageId)
    .order('seq', { ascending: true });

  if (!versions || versions.length === 0) {
    return { code: 400, body: { error: 'No versions yet' } };
  }

  let idx = versions.findIndex(function (v) { return v.id === img.active_version_id; });
  if (idx === -1) idx = versions.length - 1; // cursor unset -> treat latest as active
  const targetIdx = dir === 'undo' ? idx - 1 : idx + 1;
  if (targetIdx < 0 || targetIdx >= versions.length) {
    return { code: 400, body: { error: dir === 'undo' ? 'Nothing to undo' : 'Nothing to redo' } };
  }

  const target = versions[targetIdx];
  await supabase
    .from('project_images')
    .update({ active_version_id: target.id, current_url: target.url })
    .eq('id', projectImageId);

  return {
    code: 200,
    body: {
      ok: true,
      current_url: target.url,
      active_version_id: target.id,
      canUndo: targetIdx > 0,
      canRedo: targetIdx < versions.length - 1
    }
  };
}

// ── Gallery: Supabase-backed data for one job (replaces the n8n Sheets gallery) ─
app.get('/api/gallery', requireAuth, async (req, res) => {
  const { jobId } = req.query;
  if (!jobId || jobId === 'undefined') {
    return res.status(400).json({ error: 'Missing or invalid jobId' });
  }
  try {
    const { data: project, error: pErr } = await supabase
      .from('projects')
      .select('id, job_id, project_name, status, brief_text, logo_url')
      .eq('job_id', jobId)
      .eq('user_id', req.user.id)
      .single();
    if (pErr || !project) return res.status(404).json({ error: 'Project not found' });

    const { data: images, error: iErr } = await supabase
      .from('project_images')
      .select('id, image_index, image_name, original_url, enhanced_url, healed_url, current_url, active_version_id, upscaled_url, resolution_badge, status')
      .eq('project_id', project.id)
      .order('image_index', { ascending: true });
    if (iErr) return res.status(500).json({ error: 'Could not load images' });

    const ids = (images || []).map(function (i) { return i.id; });
    const versionsByImage = {};
    if (ids.length) {
      const { data: versions } = await supabase
        .from('project_image_versions')
        .select('id, project_image_id, url, source, prompt, seq, created_at')
        .in('project_image_id', ids)
        .order('seq', { ascending: true });
      (versions || []).forEach(function (v) {
        if (!versionsByImage[v.project_image_id]) versionsByImage[v.project_image_id] = [];
        versionsByImage[v.project_image_id].push(v);
      });
    }

    const completed = (images || []).filter(function (i) { return i.status === 'completed'; }).length;

    return res.status(200).json({
      job: {
        jobId: project.job_id,
        projectName: project.project_name,
        status: project.status,
        briefText: project.brief_text || '',
        logoUrl: project.logo_url || null,
        totalItems: (images || []).length,
        successCount: completed
      },
      images: (images || []).map(function (i) {
        return {
          projectImageId: i.id,
          image_index: i.image_index,
          image_name: i.image_name,
          original_url: i.original_url,
          enhanced_url: i.enhanced_url,
          healed_url: i.healed_url,
          current_url: i.current_url || i.enhanced_url || null,
          active_version_id: i.active_version_id,
          upscaled_url: i.upscaled_url,
          resolution_badge: i.resolution_badge,
          status: i.status,
          versions: versionsByImage[i.id] || []
        };
      })
    });
  } catch (e) {
    console.error('Gallery error:', e.message);
    return res.status(500).json({ error: 'Gallery load failed' });
  }
});

// ── Pick: user chooses enhanced vs healed; seeds the version chain ────────────
app.post('/api/select-image', requireAuth, async (req, res) => {
  const { projectImageId, choice } = req.body;
  if (!projectImageId || (choice !== 'enhanced' && choice !== 'healed')) {
    return res.status(400).json({ error: 'Missing projectImageId or invalid choice' });
  }
  try {
    const img = await getOwnedProjectImage(req.user.id, projectImageId);
    if (!img) return res.status(404).json({ error: 'Image not found' });
    const url = choice === 'healed' ? img.healed_url : img.enhanced_url;
    if (!url) return res.status(400).json({ error: 'No ' + choice + ' image available' });
    const version = await appendVersion(projectImageId, { url: url, source: choice });
    return res.status(200).json({ ok: true, current_url: url, active_version_id: version.id, version: version });
  } catch (e) {
    console.error('select-image error:', e.message);
    return res.status(500).json({ error: 'Select failed' });
  }
});

// ── Undo / Redo: move the active-version cursor along the saved chain ─────────
app.post('/api/version/undo', requireAuth, async (req, res) => {
  const r = await moveVersion(req.user.id, req.body.projectImageId, 'undo');
  return res.status(r.code).json(r.body);
});
app.post('/api/version/redo', requireAuth, async (req, res) => {
  const r = await moveVersion(req.user.id, req.body.projectImageId, 'redo');
  return res.status(r.code).json(r.body);
});

// ── Dashboard: list a user's albums (projects) with cover + count ────────────
app.get('/api/projects', requireAuth, async (req, res) => {
  try {
    const { data: projects, error } = await supabase
      .from('projects')
      .select('id, job_id, project_name, status, created_at')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: 'Could not load projects' });

    const result = [];
    for (const p of (projects || [])) {
      const { data: imgs } = await supabase
        .from('project_images')
        .select('current_url, enhanced_url, image_index')
        .eq('project_id', p.id)
        .order('image_index', { ascending: true });
      const list = imgs || [];
      const cover = list.find(function (i) { return i.current_url || i.enhanced_url; }) || {};
      result.push({
        projectId: p.id,
        jobId: p.job_id,
        projectName: p.project_name || 'Untitled Project',
        status: p.status,
        createdAt: p.created_at,
        imageCount: list.length,
        coverUrl: cover.current_url || cover.enhanced_url || null
      });
    }
    return res.status(200).json({ projects: result });
  } catch (e) {
    console.error('projects error:', e.message);
    return res.status(500).json({ error: 'Projects load failed' });
  }
});

// ── Dashboard: rename an album ───────────────────────────────────────────────
app.patch('/api/project/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { projectName } = req.body;
  if (!projectName || !projectName.trim()) {
    return res.status(400).json({ error: 'Missing projectName' });
  }
  try {
    const { data: proj } = await supabase
      .from('projects').select('id, user_id').eq('id', id).single();
    if (!proj || proj.user_id !== req.user.id) {
      return res.status(404).json({ error: 'Project not found' });
    }
    const { error } = await supabase
      .from('projects')
      .update({ project_name: projectName.trim(), updated_at: new Date() })
      .eq('id', id);
    if (error) return res.status(500).json({ error: 'Could not rename' });
    return res.status(200).json({ ok: true, projectName: projectName.trim() });
  } catch (e) {
    console.error('rename error:', e.message);
    return res.status(500).json({ error: 'Rename failed' });
  }
});

// ── Versions: jump the cursor to any saved version (history strip clicks) ─────
app.post('/api/version/set', requireAuth, async (req, res) => {
  const { projectImageId, versionId } = req.body;
  if (!projectImageId || !versionId) {
    return res.status(400).json({ error: 'Missing projectImageId or versionId' });
  }
  try {
    const img = await getOwnedProjectImage(req.user.id, projectImageId);
    if (!img) return res.status(404).json({ error: 'Image not found' });
    const { data: v } = await supabase
      .from('project_image_versions')
      .select('id, url, seq')
      .eq('id', versionId)
      .eq('project_image_id', projectImageId)
      .single();
    if (!v) return res.status(404).json({ error: 'Version not found' });

    await supabase
      .from('project_images')
      .update({ active_version_id: v.id, current_url: v.url })
      .eq('id', projectImageId);

    const { data: all } = await supabase
      .from('project_image_versions')
      .select('seq')
      .eq('project_image_id', projectImageId)
      .order('seq', { ascending: true });
    const idx = (all || []).findIndex(function (x) { return x.seq === v.seq; });
    return res.status(200).json({
      ok: true, current_url: v.url, active_version_id: v.id,
      canUndo: idx > 0, canRedo: idx < (all || []).length - 1
    });
  } catch (e) {
    console.error('version/set error:', e.message);
    return res.status(500).json({ error: 'Set failed' });
  }
});

// ── Albums: list a user's albums with cover + count ──────────────────────────
app.get('/api/albums', requireAuth, async (req, res) => {
  try {
    const { data: albums } = await supabase
      .from('albums').select('id, name, created_at, updated_at')
      .eq('user_id', req.user.id).order('created_at', { ascending: false });
    const albumIds = (albums || []).map(function (a) { return a.id; });
    if (!albumIds.length) return res.status(200).json({ albums: [] });

    const { data: projects } = await supabase
      .from('projects').select('id, album_id').in('album_id', albumIds);
    const projIds = (projects || []).map(function (p) { return p.id; });
    const albumOfProj = {}; (projects || []).forEach(function (p) { albumOfProj[p.id] = p.album_id; });

    let imgs = [];
    if (projIds.length) {
      const { data } = await supabase
        .from('project_images')
        .select('project_id, current_url, enhanced_url, image_index, status')
        .in('project_id', projIds).order('image_index', { ascending: true });
      imgs = data || [];
    }

    const agg = {};
    albumIds.forEach(function (id) { agg[id] = { count: 0, cover: null, anyProcessing: false }; });
    imgs.forEach(function (im) {
      const aid = albumOfProj[im.project_id]; const a = agg[aid]; if (!a) return;
      a.count++;
      if (!a.cover && (im.current_url || im.enhanced_url)) a.cover = im.current_url || im.enhanced_url;
      if (im.status !== 'completed') a.anyProcessing = true;
    });

    const result = (albums || []).map(function (a) {
      return {
        albumId: a.id, name: a.name, createdAt: a.created_at, updatedAt: a.updated_at,
        imageCount: agg[a.id].count, coverUrl: agg[a.id].cover,
        status: agg[a.id].anyProcessing ? 'processing' : 'completed'
      };
    });
    return res.status(200).json({ albums: result });
  } catch (e) {
    console.error('albums error:', e.message);
    return res.status(500).json({ error: 'Albums load failed' });
  }
});

// ── Album detail: every image across the album's batches, each with its jobId ─
app.get('/api/album/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const { data: album } = await supabase
      .from('albums').select('id, name, user_id, created_at').eq('id', id).single();
    if (!album || album.user_id !== req.user.id) return res.status(404).json({ error: 'Album not found' });

    const { data: projects } = await supabase
      .from('projects').select('id, job_id, created_at')
      .eq('album_id', id).order('created_at', { ascending: true });
    const projIds = (projects || []).map(function (p) { return p.id; });
    const jobByProj = {}; const projOrder = {};
    (projects || []).forEach(function (p, i) { jobByProj[p.id] = p.job_id; projOrder[p.id] = i; });

    let images = [];
    if (projIds.length) {
      const { data: imgs } = await supabase
        .from('project_images')
        .select('id, project_id, image_index, image_name, original_url, enhanced_url, healed_url, current_url, active_version_id, upscaled_url, resolution_badge, status')
        .in('project_id', projIds);

      const ids = (imgs || []).map(function (i) { return i.id; });
      const versionsByImage = {};
      if (ids.length) {
        const { data: versions } = await supabase
          .from('project_image_versions')
          .select('id, project_image_id, url, source, prompt, seq, created_at')
          .in('project_image_id', ids).order('seq', { ascending: true });
        (versions || []).forEach(function (v) {
          if (!versionsByImage[v.project_image_id]) versionsByImage[v.project_image_id] = [];
          versionsByImage[v.project_image_id].push(v);
        });
      }

      images = (imgs || []).sort(function (a, b) {
        const pa = projOrder[a.project_id], pb = projOrder[b.project_id];
        if (pa !== pb) return pa - pb;
        return (parseInt(a.image_index, 10) || 0) - (parseInt(b.image_index, 10) || 0);
      }).map(function (i) {
        return {
          projectImageId: i.id,
          jobId: jobByProj[i.project_id],
          image_index: i.image_index,
          image_name: i.image_name,
          original_url: i.original_url,
          enhanced_url: i.enhanced_url,
          healed_url: i.healed_url,
          current_url: i.current_url || i.enhanced_url || null,
          active_version_id: i.active_version_id,
          upscaled_url: i.upscaled_url,
          resolution_badge: i.resolution_badge,
          status: i.status,
          versions: versionsByImage[i.id] || []
        };
      });
    }
    return res.status(200).json({
      album: { albumId: album.id, name: album.name, createdAt: album.created_at, totalItems: images.length },
      images: images
    });
  } catch (e) {
    console.error('album detail error:', e.message);
    return res.status(500).json({ error: 'Album load failed' });
  }
});

// ── Album: rename ────────────────────────────────────────────────────────────
app.patch('/api/album/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { name } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Missing name' });
  try {
    const { data: album } = await supabase.from('albums').select('id, user_id').eq('id', id).single();
    if (!album || album.user_id !== req.user.id) return res.status(404).json({ error: 'Album not found' });
    const { error } = await supabase
      .from('albums').update({ name: name.trim(), updated_at: new Date() }).eq('id', id);
    if (error) return res.status(500).json({ error: 'Could not rename' });
    return res.status(200).json({ ok: true, name: name.trim() });
  } catch (e) {
    console.error('album rename error:', e.message);
    return res.status(500).json({ error: 'Rename failed' });
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
