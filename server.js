const dns = require('dns');
dns.setDefaultResultOrder('ipv4first');

const express = require('express');
const axios = require('axios');
const FormData = require('form-data');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');
const Stripe = require('stripe');
const { S3Client, PutObjectCommand, DeleteObjectCommand, CopyObjectCommand } = require('@aws-sdk/client-s3');
const crypto = require('crypto');
const sharp = require('sharp'); // server-side masked composite for inpaint (Path A + composite)

const app = express();
const upload = multer();

const N8N_BASE_URL = 'https://courteous-solace-production-413f.up.railway.app';
const CALLBACK_SECRET = 'sf_upscale_callback_2024';

// Free-trial grant. Set TRIAL_CREDITS=0 in the env to switch the trial off entirely
// without a code change. Granted once per user, only after email verification, and
// only to users who have never had a credits row (i.e. never purchased) — see
// grantTrialIfEligible. 1 credit = one enhance/refine/inpaint/upscale.
const TRIAL_CREDITS = Number(process.env.TRIAL_CREDITS || 50);

// §8E SAM3 smart-select (Replicate hosted SAM3, mattsays/sam3-image). Token is
// server-side only — never shipped to the browser; set REPLICATE_API_TOKEN in the
// Railway env. SAM3-image takes ONE text prompt per prediction, so /api/segment
// fans out one prediction per surface concept below (in parallel) and returns the
// same {concept, instances_found, bbox, mask} shape the old Roboflow path did, so
// the dashboard is unchanged. Pin the version hash — do not float to latest.
const REPLICATE_SEGMENT_VERSION = process.env.REPLICATE_SEGMENT_VERSION
  || 'mattsays/sam3-image:d73db077226443ba4fafd34e233b3626b552eac2a433f90c7c32a9ac89bd9e72';
// Confidence threshold: matches the 0.25 the old Roboflow workflow used to ground
// these surfaces reliably (the model default of 0.5 detects noticeably less).
const SEGMENT_THRESHOLD = Number(process.env.SEGMENT_THRESHOLD || 0.25);
// Concepts to segment — MUST match the dashboard SF_LEXICON `concept` strings
// verbatim (the returned mask is keyed by the prompt we send here). Coping /
// waterline tile intentionally omitted (SAM3 won't ground them zero-shot).
const SF_SEGMENT_CONCEPTS = [
  'pool water', 'raised wall', 'paver floor',
  'paver border', 'raised spa spillway wall', 'raised wall paver cap'
];

// Catalog skip-existing endpoint /api/catalog-slugs added (1.1.0).
// Texture catalog + per-user true-copy seeding added (1.0.9): /api/catalog-upsert
// (n8n-populated material_catalog) + seedUserMaterials() lazy-copy on first /api/materials.
// Auto-Heal RETIRED (1.0.8): the Gemini Flash alternate doubled enhance cost
// ($0.101/image) for a result the user kept ~half the time. Disabled to drop that
// spend. enqueueHeal() short-circuits on this flag, so no heal_jobs, no Flash call,
// no n8n heal fire. The heal-callback/heal-status routes remain as harmless no-ops.
const HEAL_ENABLED = false;

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
  refine: 1,
  inpaint: 1,   // also covers material swap (same /api/inpaint endpoint)
  upscale: 1,
  animate: 8    // Veo ≈ $2/clip — priced as a premium action (~1.9x at $0.48/credit)
};

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.static('.'));
app.use('/webhooks/stripe', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '10mb' })); // raised for inpaint mask (base64 PNG) payloads

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
  // The dashboard calls this on load, so it doubles as the trial-claim path: a newly
  // verified user gets their credits here without any extra client call. The grant is
  // idempotent, so calling it on every load is safe.
  const { data: existing } = await supabase
    .from('credits')
    .select('balance')
    .eq('user_id', req.user.id)
    .maybeSingle();

  if (existing) return res.json({ balance: existing.balance });

  const trial = await grantTrialIfEligible(req.user);
  // No row and not eligible (e.g. unverified email) -> report 0 rather than a 500,
  // which is what used to happen to every brand-new user.
  return res.json({
    balance: trial.balance == null ? 0 : trial.balance,
    trial_granted: trial.granted
  });
});

// Explicit claim endpoint, for a client that wants to trigger/confirm the grant
// directly (e.g. right after email verification) rather than wait for a balance read.
app.post('/api/trial/claim', requireAuth, async (req, res) => {
  const trial = await grantTrialIfEligible(req.user);
  return res.json({
    granted: trial.granted,
    balance: trial.balance == null ? 0 : trial.balance,
    reason: trial.reason,
    trial_credits: TRIAL_CREDITS
  });
});

// Grant the free trial exactly once per user. Safe to call on every dashboard load.
//
// Eligibility (fails CLOSED — if anything is uncertain we do not grant):
//   • TRIAL_CREDITS > 0
//   • the user's email is verified (Supabase email_confirmed_at / confirmed_at)
//   • the user has NO credits row yet. Every paying user gets a row from the Stripe
//     webhook, so this naturally excludes existing customers while still covering
//     dormant sign-ups who never purchased.
//
// Idempotency has two layers: trial_granted_at on the row, and a UNIQUE constraint on
// credits.user_id so two concurrent calls can never both insert (the loser's insert
// errors and is swallowed). Returns { granted, balance, reason }.
async function grantTrialIfEligible(user) {
  if (!TRIAL_CREDITS || TRIAL_CREDITS <= 0) return { granted: false, balance: null, reason: 'trial_disabled' };
  if (!user) return { granted: false, balance: null, reason: 'no_user' };

  const verified = user.email_confirmed_at || user.confirmed_at;
  if (!verified) return { granted: false, balance: null, reason: 'email_unverified' };

  const { data: existing } = await supabase
    .from('credits').select('balance, trial_granted_at').eq('user_id', user.id).maybeSingle();

  if (existing) {
    // Already has credits (purchased, or trial already granted) — never top up.
    return {
      granted: false,
      balance: existing.balance,
      reason: existing.trial_granted_at ? 'already_granted' : 'has_credits'
    };
  }

  const { error } = await supabase
    .from('credits')
    .insert({ user_id: user.id, balance: TRIAL_CREDITS, trial_granted_at: new Date() });

  if (error) {
    // Almost always the unique-constraint race: another request granted it first.
    const { data: now } = await supabase
      .from('credits').select('balance').eq('user_id', user.id).maybeSingle();
    return { granted: false, balance: now ? now.balance : null, reason: 'race_or_error' };
  }

  await supabase.from('credit_transactions').insert({
    user_id: user.id, amount: TRIAL_CREDITS, type: 'trial', description: 'Free trial credits'
  });
  console.log('Trial granted:', user.id, TRIAL_CREDITS, 'credits');
  return { granted: true, balance: TRIAL_CREDITS, reason: 'granted' };
}

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
      resolution_badge: '1K',
      status: 'processing'
    }));

    const { error: imagesError } = await supabase
      .from('project_images')
      .insert(projectImagesPayload);

    if (imagesError) {
      console.error('Supabase project_images insert error:', imagesError.message);
      return res.status(500).json({ error: 'Could not create project images' });
    }

    // 4. Fan out ONE concurrent n8n call per image to the single-image Enhance
    //    workflow (replaces the old serial Batch loop). Each call returns fast —
    //    the workflow ACKs immediately after Set Variables, then processes async
    //    and writes back per image via /api/project-image-update (which in turn
    //    auto-fires heal). Concurrency here is the parallelism win over the loop.
    const n8nUrl = `${N8N_BASE_URL}/webhook/enhance_image`;
    const dispatch = await Promise.allSettled(
      uploads.map(u =>
        axios.post(n8nUrl, {
          job_id: jobId,
          image_index: String(u.index),
          raw_upload_url: u.rawUploadUrl,
          back_plane: req.body.back_plane || '',
          time_of_day: req.body.time_of_day || '',
          paver_style: req.body.paver_style || '',
          paver_pattern: req.body.paver_pattern || '',
          image_quality: req.body.image_quality || '',
          user_email: req.user.email || '',
          user_id: req.user.id || ''
        }, {
          headers: { 'Content-Type': 'application/json' },
          timeout: 20000
        })
      )
    );

    // Identify any images n8n never accepted so we don't leave the dashboard
    // spinner polling a row that will never get a callback.
    const failedIdx = [];
    dispatch.forEach((r, i) => {
      if (r.status === 'rejected') {
        failedIdx.push(uploads[i].index);
        console.error(
          `Enhance dispatch failed for image ${uploads[i].index}:`,
          r.reason?.response?.data || r.reason?.message
        );
      }
    });

    if (failedIdx.length) {
      await Promise.allSettled(
        failedIdx.map(idx =>
          supabase
            .from('project_images')
            .update({ status: 'error', error_message: 'Enhance dispatch failed' })
            .eq('project_id', projectRow.id)
            .eq('image_index', String(idx))
        )
      );
    }

    // Only a hard failure if NOTHING was accepted.
    if (failedIdx.length === uploads.length) {
      return res.status(502).json({ error: 'Enhancement dispatch failed for all images' });
    }

    return res.status(200).json({
      jobId: jobId,
      albumId: albumId,
      status: 'pending',
      dispatched: uploads.length - failedIdx.length,
      failed: failedIdx.length
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

  const deducted = await deductCredits(req.user.id, CREDIT_COSTS.upscale, 'upscale', 'Upscale to 4K');
  if (!deducted) return res.status(402).json({ error: 'Insufficient credits' });

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
      // Resolve the ONE canonical project_images row for this (job_id, image_index)
      // and scope every write to its primary key. Updating by `id` (rather than by
      // project_id + image_index) guarantees a single row is ever touched — even if
      // legacy/dirty rows within a batch happen to share an image_index, which was
      // the only path that could turn every card in a batch to 4K.
      const img = await getProjectImageByJob(job_id, image_index);
      if (img) {
        await supabase
          .from('project_images')
          .update({ upscaled_url: upscaled_url, resolution_badge: '4K' })
          .eq('id', img.id);

        // Record the upscale as a new version and make it the active/current image.
        await appendVersion(img.id, { url: upscaled_url, source: 'upscale' });
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
  const { imageUrl, jobId, imageIndex, prompt, materialId, source_w, source_h } = req.body;

  if (!imageUrl || !jobId || !prompt) {
    return res.status(400).json({ error: 'Missing imageUrl, jobId, or prompt' });
  }

  const deducted = await deductCredits(req.user.id, CREDIT_COSTS.refine, 'refine', 'Refine image');
  if (!deducted) return res.status(402).json({ error: 'Insufficient credits' });

  try {
    // Optional reference image (e.g. "change all the stucco to this material",
    // "put this in the pool"). Resolved server-side with an ownership check.
    let referenceUrl = '';
    if (materialId) {
      const { data: material } = await supabase
        .from('materials').select('id, user_id, image_url').eq('id', materialId).maybeSingle();
      if (!material || material.user_id !== req.user.id) {
        return res.status(404).json({ error: 'Reference image not found' });
      }
      referenceUrl = material.image_url;
    }

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
      prompt: prompt,
      reference_url: referenceUrl,
      source_w: source_w || '',
      source_h: source_h || ''
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

// ── Inpaint: server-side masked composite (Path A + composite) ───────────────
// Gemini regenerates the whole frame, so unmasked pixels can drift. We pin them
// back: take the model output INSIDE the white mask and the original SOURCE
// everywhere else, guaranteeing pixel-identical unmasked regions without leaving
// our endpoint. Degrades gracefully — on any failure we return the raw result.
async function compositeInpaint(sourceUrl, maskUrl, resultUrl, jobId, imageIndex) {
  const [srcRes, maskRes, resRes] = await Promise.all([
    axios.get(sourceUrl, { responseType: 'arraybuffer' }),
    axios.get(maskUrl, { responseType: 'arraybuffer' }),
    axios.get(resultUrl, { responseType: 'arraybuffer' })
  ]);
  const srcBuf = Buffer.from(srcRes.data);
  const maskBuf = Buffer.from(maskRes.data);
  const resBuf = Buffer.from(resRes.data);

  // Source dimensions are the canonical canvas; normalize result + mask to match.
  const meta = await sharp(srcBuf).metadata();
  const W = meta.width, H = meta.height;

  // 1-channel alpha from the mask (white = show result, black = keep source).
  // Canvas-exported mask PNGs are RGBA, so flatten onto black to drop the alpha
  // and force a single greyscale channel. Without this the raw buffer can come
  // back 2-channel (luma+alpha); the channels:1 joinChannel below then throws,
  // which sent the WHOLE composite into the catch → raw model output with the
  // mask un-enforced (full-frame leak). Pin the byte count too, as a guard.
  const alpha = await sharp(maskBuf)
    .resize(W, H, { fit: 'fill' })
    .flatten({ background: { r: 0, g: 0, b: 0 } })
    .greyscale()
    .toColourspace('b-w')
    .removeAlpha()
    .raw()
    .toBuffer();
  if (alpha.length !== W * H) {
    throw new Error(`mask alpha channel mismatch: got ${alpha.length} bytes, expected ${W * H}`);
  }

  // Result image with the mask attached as its alpha channel.
  // Use 'cover' (uniform scale + center-crop), NOT 'fill': Gemini often returns a
  // different aspect ratio than the source, and 'fill' would stretch the model's
  // texture horizontally to match the canvas. 'cover' preserves the texture's
  // proportions. Output is still exactly W×H so joinChannel lines up with the mask.
  const maskedResult = await sharp(resBuf)
    .resize(W, H, { fit: 'cover', position: 'centre' })
    .removeAlpha()
    .joinChannel(alpha, { raw: { width: W, height: H, channels: 1 } })
    .png()
    .toBuffer();

  // Lay the masked result over the untouched source.
  const finalBuf = await sharp(srcBuf)
    .resize(W, H, { fit: 'fill' })
    .composite([{ input: maskedResult }])
    .jpeg({ quality: 95 })
    .toBuffer();

  const key = `${jobId}_inpaint_final_${imageIndex}_${Date.now()}.jpg`;
  return await uploadBufferToS3(finalBuf, key, 'image/jpeg');
}

// ── Inpaint: Start Job (async — mask-based correction, Phase D) ──────────────
// Body: { imageUrl, jobId, imageIndex, prompt, maskData }
//   maskData = a base64 PNG of the mask (white = edit region, black = locked).
//   Accepts a raw base64 string or a full data URL ("data:image/png;base64,...").
app.post('/api/inpaint', requireAuth, async (req, res) => {
  const { imageUrl, jobId, imageIndex, prompt, maskData, materialId, surface, source_w, source_h } = req.body;
  const cleanPrompt = (prompt || '').trim();
  const cleanSurface = ['auto', 'floor', 'wall'].indexOf(surface) !== -1 ? surface : 'auto';

  // A material swap can stand in for a text prompt, so require one OR the other.
  if (!imageUrl || !jobId || !maskData || (!cleanPrompt && !materialId)) {
    return res.status(400).json({ error: 'Missing imageUrl, jobId, maskData, or (prompt | materialId)' });
  }

  const deducted = await deductCredits(req.user.id, CREDIT_COSTS.inpaint, 'inpaint', materialId ? 'Material swap' : 'Inpaint');
  if (!deducted) return res.status(402).json({ error: 'Insufficient credits' });

  try {
    // 0. If a material was chosen, resolve it server-side (ownership-checked, same
    //    pattern as logos) so we never trust a client-supplied URL.
    let materialUrl = null, materialCategory = null;
    if (materialId) {
      const { data: material } = await supabase
        .from('materials').select('id, user_id, image_url, category').eq('id', materialId).maybeSingle();
      if (!material || material.user_id !== req.user.id) {
        return res.status(404).json({ error: 'Material not found' });
      }
      materialUrl = material.image_url;
      materialCategory = material.category || '';
    }

    // 1. Decode the mask and upload it to S3 so n8n can fetch it by URL
    //    (consistent with how every other workflow consumes images).
    const b64 = String(maskData).replace(/^data:image\/\w+;base64,/, '');
    const maskBuffer = Buffer.from(b64, 'base64');
    if (!maskBuffer.length) {
      return res.status(400).json({ error: 'Invalid maskData' });
    }
    const maskKey = `${jobId}_mask_${imageIndex}_${Date.now()}.png`;
    const maskUrl = await uploadBufferToS3(maskBuffer, maskKey, 'image/png');

    // 2. Upsert the tracking row (re-inpainting the same image resets it).
    const { error: upsertError } = await supabase
      .from('inpaint_jobs')
      .upsert({
        job_id: jobId,
        image_index: String(imageIndex),
        user_id: req.user.id,
        source_url: imageUrl,
        mask_url: maskUrl,
        prompt: cleanPrompt,
        material_url: materialUrl,
        inpainted_url: null,
        status: 'processing',
        error_message: null,
        completed_at: null
      }, { onConflict: 'job_id,image_index' });

    if (upsertError) {
      console.error('Supabase inpaint upsert error:', upsertError.message);
      return res.status(500).json({ error: 'Could not create inpaint job' });
    }

    // 3. Fire the Inpaint workflow (fire-and-forget; result lands via callback).
    //    material_url / material_category are only sent when a material was chosen;
    //    the workflow falls back to the plain text-inpaint path when they're absent.
    const n8nUrl = `${N8N_BASE_URL}/webhook/inpaint_image`;
    axios.post(n8nUrl, {
      image_url: imageUrl,
      mask_url: maskUrl,
      job_id: jobId,
      image_index: String(imageIndex),
      user_email: req.user.email,
      prompt: cleanPrompt,
      material_url: materialUrl || '',
      material_category: materialCategory || '',
      surface: cleanSurface,
      source_w: source_w || '',
      source_h: source_h || ''
    }, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 120000
    }).catch(err => {
      console.error('n8n inpaint fire-and-forget error:', err.message);
    });

    return res.status(200).json({
      status: 'processing',
      job_id: jobId,
      image_index: String(imageIndex)
    });

  } catch (error) {
    console.error('Inpaint error:', error.message);
    return res.status(500).json({ error: 'Inpaint request failed' });
  }
});

// ── §8E SAM3 Smart-select: Roboflow hosted workflow → per-concept masks ───────
// Decode COCO "compressed" RLE counts string into an array of run lengths.
// (Direct port of pycocotools rleFrString; runs are < 2^31 here, 32-bit-safe.)
function decodeCocoCounts(s) {
  const cnts = [];
  let p = 0, m = 0;
  while (p < s.length) {
    let x = 0, k = 0, more = true;
    while (more) {
      const c = s.charCodeAt(p) - 48;
      x |= (c & 0x1f) << (5 * k);
      more = c & 0x20;
      p++; k++;
      if (!more && (c & 0x10)) x |= (-1 << (5 * k));
    }
    if (m > 2) x += cnts[m - 2];
    cnts.push(x);
    m++;
  }
  return cnts;
}

// OR a single COCO RLE mask (column-major) into a shared row-major Uint8 buffer,
// flipping the union bbox out by reference. 1 = foreground.
function orRleIntoBuffer(rle, out, w, h, bbox) {
  const cnts = decodeCocoCounts(rle.counts);
  let i = 0, val = 0; // COCO runs alternate starting with background (0)
  for (let r = 0; r < cnts.length; r++) {
    const run = cnts[r];
    if (val) {
      for (let n = 0; n < run; n++) {
        const idx = i + n;
        const row = idx % h;        // column-major: row varies fastest
        const col = (idx - row) / h;
        out[row * w + col] = 1;     // row-major target
        if (col < bbox.x0) bbox.x0 = col;
        if (col > bbox.x1) bbox.x1 = col;
        if (row < bbox.y0) bbox.y0 = row;
        if (row > bbox.y1) bbox.y1 = row;
      }
    }
    i += run;
    val ^= 1;
  }
}

// Turn a 1/0 row-major buffer into a white-on-TRANSPARENT PNG (data URL). White =
// the surface; transparent elsewhere so the browser can union concepts with plain
// source-over and tint the overlay without treating black as opaque.
async function bufferToMaskPng(buf, w, h) {
  const rgba = Buffer.alloc(w * h * 4); // zero-filled => transparent black
  for (let i = 0; i < buf.length; i++) {
    if (buf[i]) {
      const o = i * 4;
      rgba[o] = 255; rgba[o + 1] = 255; rgba[o + 2] = 255; rgba[o + 3] = 255;
    }
  }
  const png = await sharp(rgba, { raw: { width: w, height: h, channels: 4 } }).png().toBuffer();
  return 'data:image/png;base64,' + png.toString('base64');
}

app.post('/api/segment', requireAuth, async (req, res) => {
  const { imageUrl } = req.body || {};
  if (!imageUrl) return res.status(400).json({ error: 'Missing imageUrl' });
  if (!process.env.REPLICATE_API_TOKEN) {
    console.error('Segment error: REPLICATE_API_TOKEN not set');
    return res.status(503).json({ error: 'Smart select is not configured' });
  }

  // Replicate wants the bare 64-char version id in the REST body; strip any
  // owner/model: prefix so either form of REPLICATE_SEGMENT_VERSION works.
  const versionId = REPLICATE_SEGMENT_VERSION.includes(':')
    ? REPLICATE_SEGMENT_VERSION.split(':').pop()
    : REPLICATE_SEGMENT_VERSION;

  // Segment ONE surface concept via SAM3 (mattsays/sam3-image). Returns the same
  // per-concept object the old Roboflow path produced, or null on a miss/failure
  // so one bad concept never sinks the whole request (the chip just stays disabled,
  // exactly as before when a concept had zero predictions).
  async function segmentConcept(concept) {
    try {
      // Prefer: wait=60 keeps this a single blocking call (like the old Roboflow
      // request) instead of create-then-poll. mask_only + return_zip:false gives a
      // single B/W mask image (no zip to unpack, no RLE to decode).
      const pred = await axios.post(
        'https://api.replicate.com/v1/predictions',
        {
          version: versionId,
          input: {
            image: imageUrl,
            prompt: concept,
            threshold: SEGMENT_THRESHOLD,
            mask_only: true,
            return_zip: false,
            save_overlay: false
          }
        },
        {
          headers: {
            'Authorization': 'Bearer ' + process.env.REPLICATE_API_TOKEN,
            'Content-Type': 'application/json',
            'Prefer': 'wait=60'
          },
          timeout: 90000
        }
      );

      const status = pred.data && pred.data.status;
      const rawOut = pred.data && pred.data.output;
      const maskUrl = Array.isArray(rawOut) ? rawOut[0] : rawOut;
      // If the wait window elapsed before completion, treat as a miss rather than
      // blocking further (graceful — the surface just won't get a chip this pass).
      if (status !== 'succeeded' || !maskUrl) return null;

      // Fetch the B/W mask and convert white-on-black -> white-on-TRANSPARENT, which
      // is what the dashboard's tint (source-in on alpha) and union (source-over)
      // expect. Also derive a bbox + presence flag from the white pixels.
      const imgResp = await axios.get(maskUrl, { responseType: 'arraybuffer', timeout: 30000 });
      const { data, info } = await sharp(Buffer.from(imgResp.data))
        .greyscale().raw().toBuffer({ resolveWithObject: true });
      const w = info.width, h = info.height;
      const rgba = Buffer.alloc(w * h * 4); // zero-filled => transparent black
      const bbox = { x0: w, y0: h, x1: -1, y1: -1 };
      let count = 0;
      for (let i = 0; i < w * h; i++) {
        if (data[i] > 127) {
          const o = i * 4;
          rgba[o] = 255; rgba[o + 1] = 255; rgba[o + 2] = 255; rgba[o + 3] = 255;
          const row = (i / w) | 0, col = i % w;
          if (col < bbox.x0) bbox.x0 = col;
          if (col > bbox.x1) bbox.x1 = col;
          if (row < bbox.y0) bbox.y0 = row;
          if (row > bbox.y1) bbox.y1 = row;
          count++;
        }
      }
      if (!count) return null; // nothing grounded -> omit, so the chip stays disabled
      const png = await sharp(rgba, { raw: { width: w, height: h, channels: 4 } }).png().toBuffer();
      return {
        concept,
        // SAM3-image returns a merged mask, not per-instance counts; report presence.
        instances_found: 1,
        bbox: { x: bbox.x0, y: bbox.y0, w: bbox.x1 - bbox.x0 + 1, h: bbox.y1 - bbox.y0 + 1 },
        mask: 'data:image/png;base64,' + png.toString('base64'),
        _w: w, _h: h
      };
    } catch (e) {
      const detail = e.response ? JSON.stringify(e.response.data).slice(0, 200) : e.message;
      console.error('Segment concept "' + concept + '" failed:', detail);
      return null;
    }
  }

  try {
    // Fan out one prediction per concept in parallel. Wall-time ~ one cold start +
    // one inference (not N of them), and the first request warms the model for the rest.
    const results = await Promise.all(SF_SEGMENT_CONCEPTS.map(segmentConcept));
    const concepts = results.filter(Boolean);
    // Mask dims match the input image; the dashboard scales masks to its canvas, so
    // this is informational only. Fall back to 0 when nothing was detected.
    const first = concepts[0];
    const W = first ? first._w : 0, H = first ? first._h : 0;
    concepts.forEach(c => { delete c._w; delete c._h; });
    return res.status(200).json({ source_w: W, source_h: H, concepts });
  } catch (error) {
    console.error('Segment error:', error.message);
    return res.status(502).json({ error: 'Segmentation failed' });
  }
});

// ── Inpaint: Callback from n8n ───────────────────────────────────────────────
app.post('/api/inpaint-callback', async (req, res) => {
  const secret = req.headers['x-callback-secret'];
  if (secret !== CALLBACK_SECRET) {
    return res.status(403).json({ error: 'Invalid callback secret' });
  }

  const { job_id, image_index, status, inpainted_url, error_message } = req.body;

  if (!job_id || !image_index) {
    return res.status(400).json({ error: 'Missing job_id or image_index' });
  }

  try {
    const updateData = {
      status: status || 'completed',
      completed_at: new Date()
    };
    if (error_message) updateData.error_message = error_message;

    // Stamp status now; the final (composited) URL is written after compositing.
    const { error } = await supabase
      .from('inpaint_jobs')
      .update(updateData)
      .eq('job_id', job_id)
      .eq('image_index', String(image_index));

    if (error) {
      console.error('Inpaint callback update error:', error.message);
      return res.status(500).json({ error: 'Could not update job' });
    }

    // On success: composite the raw model output back through the mask so only
    // the painted region changes, then record that as the new current version.
    if (inpainted_url) {
      const { data: ij } = await supabase
        .from('inpaint_jobs')
        .select('source_url, mask_url, prompt')
        .eq('job_id', job_id)
        .eq('image_index', String(image_index))
        .maybeSingle();

      let finalUrl = inpainted_url;
      if (ij && ij.source_url && ij.mask_url) {
        try {
          finalUrl = await compositeInpaint(ij.source_url, ij.mask_url, inpainted_url, job_id, image_index);
        } catch (e) {
          // A mask was supplied, so the mask MUST be enforced. Degrading to the raw
          // model output here is the full-frame leak — never save that. Mark the job
          // failed and skip the version append so the user can simply retry.
          console.error('Inpaint composite failed (mask NOT enforced, refusing raw):', e.message);
          await supabase
            .from('inpaint_jobs')
            .update({ status: 'error', error_message: 'Mask composite failed — please retry' })
            .eq('job_id', job_id)
            .eq('image_index', String(image_index));
          return res.status(200).json({ received: true, composite: 'failed' });
        }
      }

      await supabase
        .from('inpaint_jobs')
        .update({ inpainted_url: finalUrl })
        .eq('job_id', job_id)
        .eq('image_index', String(image_index));

      const img = await getProjectImageByJob(job_id, image_index);
      if (img) {
        await appendVersion(img.id, {
          url: finalUrl,
          source: 'inpaint',
          prompt: ij && ij.prompt ? ij.prompt : null
        });
      }
    }

    console.log(`Inpaint ${status || 'completed'}: ${job_id} image ${image_index}`);
    return res.status(200).json({ received: true });

  } catch (error) {
    console.error('Inpaint callback error:', error.message);
    return res.status(500).json({ error: 'Callback processing failed' });
  }
});

// ── Inpaint: Status Check ────────────────────────────────────────────────────
app.get('/api/inpaint-status', requireAuth, async (req, res) => {
  const { jobId, imageIndex } = req.query;

  if (!jobId || !imageIndex) {
    return res.status(400).json({ error: 'Missing jobId or imageIndex' });
  }

  try {
    const { data, error } = await supabase
      .from('inpaint_jobs')
      .select('status, inpainted_url, error_message')
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
      inpainted_url: data.inpainted_url || null,
      error_message: data.error_message || null
    });

  } catch (error) {
    console.error('Inpaint status check error:', error.message);
    return res.status(500).json({ error: 'Status check failed' });
  }
});

// ── Heal: Callback from the standalone "Heal Image" workflow ─────────────────
app.post('/api/heal-callback', async (req, res) => {
  const secret = req.headers['x-callback-secret'];
  if (secret !== CALLBACK_SECRET) {
    return res.status(403).json({ error: 'Invalid callback secret' });
  }

  const { job_id, image_index, status, healed_url, heal_fallback, error_message } = req.body;
  if (!job_id || image_index === undefined) {
    return res.status(400).json({ error: 'Missing job_id or image_index' });
  }

  try {
    const updateData = { status: status || 'completed', completed_at: new Date() };
    if (healed_url) updateData.healed_url = healed_url;
    if (heal_fallback !== undefined) updateData.heal_fallback = !!heal_fallback;
    if (error_message) updateData.error_message = error_message;

    await supabase
      .from('heal_jobs')
      .update(updateData)
      .eq('job_id', job_id)
      .eq('image_index', String(image_index));

    // Store the alternate on the canonical image row — ONLY when a real healed image
    // exists. On fallback the workflow reused the enhanced image, so there is no genuine
    // alternate to compare; we leave healed_url null and Compare stays disabled.
    // Non-destructive: never touches current_url or the version chain (the user opts in
    // to healed via the Compare slider → /api/select-image). Scoped to one row by id.
    if (healed_url && !heal_fallback) {
      const img = await getProjectImageByJob(job_id, image_index);
      if (img) {
        await supabase
          .from('project_images')
          .update({ healed_url: healed_url })
          .eq('id', img.id);
      }
    }

    console.log(`Heal completed: ${job_id} image ${image_index}${heal_fallback ? ' (fallback)' : ''}`);
    return res.status(200).json({ received: true });
  } catch (error) {
    console.error('Heal callback error:', error.message);
    return res.status(500).json({ error: 'Callback processing failed' });
  }
});

// ── Heal: Status Check (dashboard polls until the alternate is ready) ────────
app.get('/api/heal-status', requireAuth, async (req, res) => {
  const { jobId, imageIndex } = req.query;
  if (!jobId || !imageIndex) {
    return res.status(400).json({ error: 'Missing jobId or imageIndex' });
  }
  try {
    const { data, error } = await supabase
      .from('heal_jobs')
      .select('status, healed_url, heal_fallback, error_message')
      .eq('job_id', jobId)
      .eq('image_index', String(imageIndex))
      .order('created_at', { ascending: false })
      .limit(1)
      .single();

    if (error || !data) return res.status(404).json({ error: 'Job not found' });

    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).json({
      status: data.status,
      healed_url: data.healed_url || null,
      heal_fallback: !!data.heal_fallback,
      error_message: data.error_message || null
    });
  } catch (error) {
    console.error('Heal status check error:', error.message);
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

    // Async Auto-Heal: the moment the ENHANCED result is written back, kick off the
    // Gemini Flash alternate in the background (its own job + workflow). Fire-and-forget
    // so the enhance writeback returns immediately — this is what halves batch time.
    if (enhanced_url) {
      enqueueHeal(job_id, image_index, enhanced_url)
        .catch(e => console.error('enqueueHeal error:', e.message));
    }

    return res.status(200).json({ received: true });

  } catch (error) {
    console.error('project-image-update error:', error.message);
    return res.status(500).json({ error: 'Update processing failed' });
  }
});

// ── Status Proxy (RETIRED at dashboard cutover) ──────────────────────────────
// The legacy Sheets gallery polled this. The front-end now redirects straight to
// /dashboard.html?album=<id> after a batch, which reads Supabase directly, so this
// n8n Sheets proxy is no longer used. The "Status Check" workflow can be deactivated.

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

// Async Auto-Heal enqueue: called from the enhanced-stage writeback. Resolves the
// canonical image (for its cropped ground-truth original_url + owner), records a
// heal_jobs row, and fires the standalone "Heal Image" workflow. Idempotent and
// non-blocking — guarded so retries / re-imports never double-fire a heal.
async function enqueueHeal(job_id, image_index, enhancedUrl) {
  if (!HEAL_ENABLED) return;

  const { data: projectRow } = await supabase
    .from('projects').select('id, user_id').eq('job_id', job_id).single();
  if (!projectRow) return;

  const { data: imgRow } = await supabase
    .from('project_images')
    .select('id, original_url, healed_url')
    .eq('project_id', projectRow.id)
    .eq('image_index', String(image_index))
    .single();
  if (!imgRow) return;
  if (imgRow.healed_url) return;        // a real alternate already exists
  if (!imgRow.original_url) return;     // no ground-truth (IMAGE_A) to audit against yet

  // Don't enqueue twice for the same image.
  const { data: existing } = await supabase
    .from('heal_jobs').select('id')
    .eq('job_id', job_id).eq('image_index', String(image_index))
    .maybeSingle();
  if (existing) return;

  const { error: insErr } = await supabase
    .from('heal_jobs')
    .insert({
      job_id,
      image_index: String(image_index),
      user_id: projectRow.user_id,
      source_url: enhancedUrl,
      original_url: imgRow.original_url,
      status: 'processing'
    });
  if (insErr) { console.error('heal_jobs insert error:', insErr.message); return; }

  // Fire the heal workflow (fire-and-forget — the alternate lands via /api/heal-callback).
  const n8nUrl = `${N8N_BASE_URL}/webhook/heal_image`;
  axios.post(n8nUrl, {
    job_id,
    image_index: String(image_index),
    enhanced_url: enhancedUrl,
    original_url: imgRow.original_url
  }, {
    headers: { 'Content-Type': 'application/json' },
    timeout: 120000
  }).catch(err => {
    console.error('n8n heal fire-and-forget error:', err.message);
  });
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
  let lastSeq = (last && last.seq) ? last.seq : 0;

  // Heal retired (1.0.8): the enhanced/healed pick used to seed the chain. With no
  // pick, seed the enhanced result as the baseline (seq 1) the first time any edit
  // appends, so undo always returns to the original enhance.
  if (lastSeq === 0) {
    const { data: imgRow } = await supabase
      .from('project_images').select('enhanced_url').eq('id', projectImageId).maybeSingle();
    if (imgRow && imgRow.enhanced_url && imgRow.enhanced_url !== url) {
      await supabase
        .from('project_image_versions')
        .insert({ project_image_id: projectImageId, url: imgRow.enhanced_url, source: 'enhanced', prompt: null, seq: 1 });
      lastSeq = 1;
    }
  }
  const nextSeq = lastSeq + 1;

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
      .select('id, job_id, project_name, status, logo_url')
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

// ── Version: delete one version from an image's history ──────────────────────
app.post('/api/version/delete', requireAuth, async (req, res) => {
  const { projectImageId, versionId } = req.body || {};
  if (!projectImageId || !versionId) {
    return res.status(400).json({ error: 'Missing projectImageId or versionId' });
  }
  try {
    const img = await getOwnedProjectImage(req.user.id, projectImageId);
    if (!img) return res.status(404).json({ error: 'Image not found' });

    const { data: versions } = await supabase
      .from('project_image_versions')
      .select('id, url, source, seq')
      .eq('project_image_id', projectImageId)
      .order('seq', { ascending: true });
    const list = versions || [];
    const idx = list.findIndex(function (v) { return v.id === versionId; });
    if (idx === -1) return res.status(404).json({ error: 'Version not found' });
    const removed = list[idx];

    const remaining = list.filter(function (v) { return v.id !== versionId; });
    // New cursor: prefer the previous version, else the new last, else none (revert to enhanced).
    let newActive = null;
    if (remaining.length) newActive = remaining[Math.max(0, idx - 1)] || remaining[remaining.length - 1];

    const update = {
      active_version_id: newActive ? newActive.id : null,
      current_url: newActive ? newActive.url : (img.enhanced_url || null)
    };
    // Deleting the logo version is also the per-image "remove logo" path — clear its state.
    if (removed.source === 'logo') { update.logo_placement = null; update.logo_base_url = null; }

    // Move the active-version pointer OFF this row BEFORE deleting it. There is a
    // foreign key on project_images.active_version_id, so deleting a row that's
    // still referenced as the active version is rejected. The old order deleted
    // first and swallowed the error, so on the ACTIVE version the cursor moved but
    // the row lingered in history (deleting a non-active version happened to work).
    await supabase.from('project_images').update(update).eq('id', projectImageId);

    const { error: delErr } = await supabase
      .from('project_image_versions').delete().eq('id', versionId);
    if (delErr) {
      console.error('version row delete failed:', delErr.message);
      return res.status(500).json({ error: 'Could not delete version' });
    }

    const newIdx = newActive ? remaining.findIndex(function (v) { return v.id === newActive.id; }) : -1;
    return res.status(200).json({
      ok: true,
      current_url: update.current_url,
      active_version_id: update.active_version_id,
      canUndo: newIdx > 0,
      canRedo: newActive ? newIdx < remaining.length - 1 : false
    });
  } catch (e) {
    console.error('version/delete error:', e.message);
    return res.status(500).json({ error: 'Could not delete version' });
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
        .in('project_id', projIds).is('deleted_at', null).order('image_index', { ascending: true });
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
      .from('albums').select('id, name, user_id, created_at, logo_placement').eq('id', id).single();
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
        .select('id, project_id, image_index, image_name, original_url, enhanced_url, healed_url, current_url, active_version_id, upscaled_url, resolution_badge, status, logo_placement')
        .in('project_id', projIds).is('deleted_at', null);

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
          logoOverride: i.logo_placement || null,
          versions: versionsByImage[i.id] || []
        };
      });
    }
    return res.status(200).json({
      album: { albumId: album.id, name: album.name, createdAt: album.created_at, totalItems: images.length, logoDefault: album.logo_placement || null },
      images: images
    });
  } catch (e) {
    console.error('album detail error:', e.message);
    return res.status(500).json({ error: 'Album load failed' });
  }
});

// ── Image: soft delete (move to Trash) ───────────────────────────────────────
app.post('/api/image/delete', requireAuth, async (req, res) => {
  const { projectImageId } = req.body;
  if (!projectImageId) return res.status(400).json({ error: 'Missing projectImageId' });
  try {
    const img = await getOwnedProjectImage(req.user.id, projectImageId);
    if (!img) return res.status(404).json({ error: 'Image not found' });
    const { error } = await supabase
      .from('project_images')
      .update({ deleted_at: new Date() })
      .eq('id', projectImageId);
    if (error) throw new Error(error.message);
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('image delete error:', e.message);
    return res.status(500).json({ error: 'Delete failed' });
  }
});

// ── Image: restore from Trash ────────────────────────────────────────────────
app.post('/api/image/restore', requireAuth, async (req, res) => {
  const { projectImageId } = req.body;
  if (!projectImageId) return res.status(400).json({ error: 'Missing projectImageId' });
  try {
    // getOwnedProjectImage does NOT filter deleted_at, so it still finds a trashed row.
    const img = await getOwnedProjectImage(req.user.id, projectImageId);
    if (!img) return res.status(404).json({ error: 'Image not found' });
    const { error } = await supabase
      .from('project_images')
      .update({ deleted_at: null })
      .eq('id', projectImageId);
    if (error) throw new Error(error.message);
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('image restore error:', e.message);
    return res.status(500).json({ error: 'Restore failed' });
  }
});

// ── Trash: list this user's soft-deleted images ──────────────────────────────
app.get('/api/trash', requireAuth, async (req, res) => {
  try {
    const { data: projects } = await supabase
      .from('projects').select('id, album_id').eq('user_id', req.user.id);
    const projIds = (projects || []).map(function (p) { return p.id; });
    if (!projIds.length) return res.status(200).json({ images: [] });
    const albumOfProj = {}; (projects || []).forEach(function (p) { albumOfProj[p.id] = p.album_id; });

    const { data: imgs } = await supabase
      .from('project_images')
      .select('id, project_id, image_index, current_url, enhanced_url, deleted_at')
      .in('project_id', projIds)
      .not('deleted_at', 'is', null)
      .order('deleted_at', { ascending: false });

    const albumIds = [...new Set((imgs || []).map(function (i) { return albumOfProj[i.project_id]; }).filter(Boolean))];
    const albumName = {};
    if (albumIds.length) {
      const { data: albums } = await supabase.from('albums').select('id, name').in('id', albumIds);
      (albums || []).forEach(function (a) { albumName[a.id] = a.name; });
    }

    const images = (imgs || []).map(function (i) {
      const aid = albumOfProj[i.project_id];
      return {
        projectImageId: i.id,
        albumId: aid || null,
        albumName: albumName[aid] || 'Album',
        image_index: i.image_index,
        thumb: i.current_url || i.enhanced_url || null,
        deleted_at: i.deleted_at
      };
    });
    return res.status(200).json({ images: images });
  } catch (e) {
    console.error('trash list error:', e.message);
    return res.status(500).json({ error: 'Trash load failed' });
  }
});

// ── Purge: hard-delete images trashed > 30 days ago (cron, secret-guarded) ────
// Called daily by the "Purge Deleted" n8n workflow. Removes the version rows,
// the image rows, and every S3 object owned by those images.
app.post('/api/purge-deleted', async (req, res) => {
  if (req.headers['x-callback-secret'] !== CALLBACK_SECRET) {
    return res.status(403).json({ error: 'Invalid callback secret' });
  }
  try {
    const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const { data: imgs } = await supabase
      .from('project_images')
      .select('id, original_url, enhanced_url, healed_url, current_url, upscaled_url')
      .not('deleted_at', 'is', null)
      .lt('deleted_at', cutoff);

    if (!imgs || !imgs.length) return res.status(200).json({ purged: 0, s3Deleted: 0 });
    const imageIds = imgs.map(function (i) { return i.id; });

    // Gather every S3 URL tied to these images: column URLs + all version URLs.
    const urls = new Set();
    imgs.forEach(function (i) {
      ['original_url', 'enhanced_url', 'healed_url', 'current_url', 'upscaled_url'].forEach(function (k) {
        if (i[k]) urls.add(i[k]);
      });
    });
    const { data: versions } = await supabase
      .from('project_image_versions').select('url').in('project_image_id', imageIds);
    (versions || []).forEach(function (v) { if (v.url) urls.add(v.url); });

    // Delete only objects in OUR bucket; ignore anything else.
    const prefix = `https://${S3_BUCKET}.s3.${S3_REGION}.amazonaws.com/`;
    let s3Deleted = 0;
    for (const u of urls) {
      if (!u.startsWith(prefix)) continue;
      const key = decodeURIComponent(u.slice(prefix.length));
      try {
        await s3Client.send(new DeleteObjectCommand({ Bucket: S3_BUCKET, Key: key }));
        s3Deleted++;
      } catch (e) {
        console.error('purge S3 delete failed for key', key, '-', e.message);
      }
    }

    // Remove DB rows (versions first to respect the FK).
    await supabase.from('project_image_versions').delete().in('project_image_id', imageIds);
    await supabase.from('project_images').delete().in('id', imageIds);

    console.log(`Purge: removed ${imageIds.length} image(s), ${s3Deleted} S3 object(s).`);
    return res.status(200).json({ purged: imageIds.length, s3Deleted: s3Deleted });
  } catch (e) {
    console.error('purge error:', e.message);
    return res.status(500).json({ error: 'Purge failed' });
  }
});

// ── Logos: per-user logo library ─────────────────────────────────────────────
app.get('/api/logos', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('logos').select('id, name, image_url, created_at')
      .eq('user_id', req.user.id).order('created_at', { ascending: false });
    if (error) throw new Error(error.message);
    return res.status(200).json({
      logos: (data || []).map(function (l) {
        return { id: l.id, name: l.name || 'Logo', imageUrl: l.image_url, createdAt: l.created_at };
      })
    });
  } catch (e) {
    console.error('logos list error:', e.message);
    return res.status(500).json({ error: 'Could not load logos' });
  }
});

app.post('/api/logos', requireAuth, upload.single('logo'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No logo file' });
    const ct = req.file.mimetype || 'image/png';
    if (!ct.startsWith('image/')) return res.status(400).json({ error: 'File must be an image' });
    const ext = (ct.split('/')[1] || 'png').replace('+xml', '');
    const key = `logos/${req.user.id}_${Date.now()}.${ext}`;
    const imageUrl = await uploadBufferToS3(req.file.buffer, key, ct);
    const name = (req.body && req.body.name)
      ? String(req.body.name).slice(0, 80)
      : String(req.file.originalname || 'Logo').replace(/\.[^.]+$/, '').slice(0, 80);
    const { data, error } = await supabase
      .from('logos').insert({ user_id: req.user.id, name: name, image_url: imageUrl })
      .select('id, name, image_url, created_at').single();
    if (error) throw new Error(error.message);
    return res.status(200).json({ id: data.id, name: data.name, imageUrl: data.image_url, createdAt: data.created_at });
  } catch (e) {
    console.error('logo upload error:', e.message);
    return res.status(500).json({ error: 'Logo upload failed' });
  }
});

app.post('/api/logos/delete', requireAuth, async (req, res) => {
  const { logoId } = req.body;
  if (!logoId) return res.status(400).json({ error: 'Missing logoId' });
  try {
    const { data: logo } = await supabase
      .from('logos').select('id, user_id, image_url').eq('id', logoId).maybeSingle();
    if (!logo || logo.user_id !== req.user.id) return res.status(404).json({ error: 'Logo not found' });

    const prefix = `https://${S3_BUCKET}.s3.${S3_REGION}.amazonaws.com/`;
    if (logo.image_url && logo.image_url.startsWith(prefix)) {
      const k = decodeURIComponent(logo.image_url.slice(prefix.length));
      try { await s3Client.send(new DeleteObjectCommand({ Bucket: S3_BUCKET, Key: k })); }
      catch (e) { console.error('logo S3 delete failed:', e.message); }
    }
    const { error } = await supabase.from('logos').delete().eq('id', logoId);
    if (error) throw new Error(error.message);
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('logo delete error:', e.message);
    return res.status(500).json({ error: 'Delete failed' });
  }
});

// ── Materials: per-user material library (tile / paver / stone swatches) ─────
//    Near-identical to the logo library, but consumed by the material-aware
//    inpaint instead of the deterministic sharp composite.
const MATERIAL_CATEGORIES = ['paver', 'tile', 'decking', 'stone', 'gravel', 'other'];

app.get('/api/materials', requireAuth, async (req, res) => {
  try {
    // First load for a new user copies the shared catalog into their library.
    // No-op once seeded.
    await seedUserMaterials(req.user.id);
    const { data, error } = await supabase
      .from('materials').select('id, name, category, image_url, created_at')
      .eq('user_id', req.user.id).order('created_at', { ascending: false });
    if (error) throw new Error(error.message);
    return res.status(200).json({
      materials: (data || []).map(function (m) {
        return { id: m.id, name: m.name || 'Material', category: m.category || 'other', imageUrl: m.image_url, createdAt: m.created_at };
      })
    });
  } catch (e) {
    console.error('materials list error:', e.message);
    return res.status(500).json({ error: 'Could not load materials' });
  }
});

app.post('/api/materials', requireAuth, upload.single('material'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No material file' });
    const ct = req.file.mimetype || 'image/jpeg';
    if (!ct.startsWith('image/')) return res.status(400).json({ error: 'File must be an image' });
    const ext = (ct.split('/')[1] || 'jpg').replace('+xml', '');
    const key = `materials/${req.user.id}_${Date.now()}.${ext}`;
    const imageUrl = await uploadBufferToS3(req.file.buffer, key, ct);
    const name = (req.body && req.body.name)
      ? String(req.body.name).slice(0, 80)
      : String(req.file.originalname || 'Material').replace(/\.[^.]+$/, '').slice(0, 80);
    let category = (req.body && req.body.category) ? String(req.body.category).toLowerCase() : 'other';
    if (MATERIAL_CATEGORIES.indexOf(category) === -1) category = 'other';
    const { data, error } = await supabase
      .from('materials').insert({ user_id: req.user.id, name: name, category: category, image_url: imageUrl })
      .select('id, name, category, image_url, created_at').single();
    if (error) throw new Error(error.message);
    return res.status(200).json({ id: data.id, name: data.name, category: data.category, imageUrl: data.image_url, createdAt: data.created_at });
  } catch (e) {
    console.error('material upload error:', e.message);
    return res.status(500).json({ error: 'Material upload failed' });
  }
});

app.post('/api/materials/delete', requireAuth, async (req, res) => {
  const { materialId } = req.body;
  if (!materialId) return res.status(400).json({ error: 'Missing materialId' });
  try {
    const { data: material } = await supabase
      .from('materials').select('id, user_id, image_url').eq('id', materialId).maybeSingle();
    if (!material || material.user_id !== req.user.id) return res.status(404).json({ error: 'Material not found' });

    const prefix = `https://${S3_BUCKET}.s3.${S3_REGION}.amazonaws.com/`;
    if (material.image_url && material.image_url.startsWith(prefix)) {
      const k = decodeURIComponent(material.image_url.slice(prefix.length));
      try { await s3Client.send(new DeleteObjectCommand({ Bucket: S3_BUCKET, Key: k })); }
      catch (e) { console.error('material S3 delete failed:', e.message); }
    }
    const { error } = await supabase.from('materials').delete().eq('id', materialId);
    if (error) throw new Error(error.message);
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('material delete error:', e.message);
    return res.status(500).json({ error: 'Delete failed' });
  }
});

// ── Catalog: shared seed library, populated by the "Generate Texture Catalog"
//    n8n workflow. Secret-protected (same convention as the *-callback handlers).
app.post('/api/catalog-upsert', async (req, res) => {
  const secret = req.headers['x-callback-secret'];
  if (secret !== CALLBACK_SECRET) return res.status(401).json({ error: 'Unauthorized' });
  const { slug, name, category, image_url } = req.body || {};
  if (!slug || !image_url) return res.status(400).json({ error: 'Missing slug or image_url' });
  let cat = (category || 'other').toLowerCase();
  if (MATERIAL_CATEGORIES.indexOf(cat) === -1) cat = 'other';
  try {
    const { error } = await supabase
      .from('material_catalog')
      .upsert({ slug: String(slug), name: name || 'Material', category: cat, image_url: String(image_url) }, { onConflict: 'slug' });
    if (error) throw new Error(error.message);
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('catalog upsert error:', e.message);
    return res.status(500).json({ error: 'Catalog upsert failed' });
  }
});

// ── Catalog slugs: lets the generator skip textures already produced, so reruns
//    only spend on what's missing (and no-image failures self-heal next run).
app.get('/api/catalog-slugs', async (req, res) => {
  const secret = req.headers['x-callback-secret'];
  if (secret !== CALLBACK_SECRET) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const { data, error } = await supabase.from('material_catalog').select('slug');
    if (error) throw new Error(error.message);
    return res.status(200).json({ slugs: (data || []).map(function (r) { return r.slug; }) });
  } catch (e) {
    console.error('catalog-slugs error:', e.message);
    return res.status(500).json({ error: 'Could not list catalog slugs' });
  }
});

// ── Seed a new user's material library from the shared catalog (TRUE COPY).
//    Each user gets their own S3 objects + their own `materials` rows, so the
//    existing delete endpoint (which removes the backing S3 object) is safe and
//    never touches another user's copy or the shared catalog. Idempotent: the
//    user_seed insert doubles as a concurrency claim, so parallel first-loads
//    won't double-seed. No-op (fast) once a user is already seeded.
async function seedUserMaterials(userId) {
  const { error: claimErr } = await supabase.from('user_seed').insert({ user_id: userId });
  if (claimErr) return false; // already seeded (or claim already held) → skip
  try {
    const { data: catalog, error } = await supabase
      .from('material_catalog').select('slug, name, category, image_url');
    if (error) throw new Error(error.message);
    if (!catalog || !catalog.length) {
      // Nothing to seed yet (catalog not generated). Release the claim so the
      // user gets seeded once the catalog exists.
      await supabase.from('user_seed').delete().eq('user_id', userId);
      return false;
    }
    const base = `https://${S3_BUCKET}.s3.${S3_REGION}.amazonaws.com/`;
    const stamp = Date.now();
    const results = await Promise.all(catalog.map(async function (c) {
      if (!c.image_url || !c.image_url.startsWith(base)) return null;
      const srcKey = decodeURIComponent(c.image_url.slice(base.length));
      const destKey = `materials/${userId}_seed_${c.slug}_${stamp}.png`;
      try {
        await s3Client.send(new CopyObjectCommand({
          Bucket: S3_BUCKET,
          CopySource: `/${S3_BUCKET}/${srcKey}`,
          Key: destKey,
          ACL: 'public-read',
          MetadataDirective: 'COPY'
        }));
        return { user_id: userId, name: c.name || 'Material', category: c.category || 'other', image_url: `${base}${destKey}` };
      } catch (e) {
        console.error('seed copy failed for', c.slug, e.message);
        return null;
      }
    }));
    const rows = results.filter(Boolean);
    if (rows.length) {
      const { error: insErr } = await supabase.from('materials').insert(rows);
      if (insErr) throw new Error(insErr.message);
    }
    return true;
  } catch (e) {
    console.error('seedUserMaterials error:', e.message);
    // Release the claim so the user can be retried on their next materials load.
    await supabase.from('user_seed').delete().eq('user_id', userId);
    return false;
  }
}

// ── Logo placement: composite + stamp/remove helpers ────────────────────────
function n(v) { const x = Number(v); return isFinite(x) ? x : 0; }

// Deterministic overlay (NOT generative): stamp the logo PNG onto the base at a
// fractional position/size/opacity. Respects the logo's own transparency.
// Render the logo onto a base image and return the JPEG BYTES. Pure pixels — no S3
// write, no DB — so the same code serves on-the-fly export at download time.
async function renderLogoBuffer(baseUrl, placement) {
  const [baseRes, logoRes] = await Promise.all([
    axios.get(baseUrl, { responseType: 'arraybuffer' }),
    axios.get(placement.logoUrl, { responseType: 'arraybuffer' })
  ]);
  const baseBuf = Buffer.from(baseRes.data);
  const logoBuf = Buffer.from(logoRes.data);
  const meta = await sharp(baseBuf).metadata();
  const W = meta.width, H = meta.height;

  const wFrac = Math.min(Math.max(n(placement.w) || 0.18, 0.02), 1);
  const opacity = Math.min(Math.max(placement.opacity == null ? 1 : n(placement.opacity), 0), 1);
  const logoW = Math.max(1, Math.round(wFrac * W));

  // Fit the logo INSIDE the base in both dimensions (preserve aspect). Without the
  // height cap, a tall logo or a large drag can exceed the base height and sharp
  // throws ("image to composite must be same size or smaller").
  let pipe = sharp(logoBuf).resize({ width: logoW, height: H, fit: 'inside' }).ensureAlpha();
  if (opacity < 1) pipe = pipe.linear([1, 1, 1, opacity], [0, 0, 0, 0]); // scale alpha only
  const logoPng = await pipe.png().toBuffer();
  const lmeta = await sharp(logoPng).metadata();

  let left = Math.round(n(placement.x) * W);
  let top = Math.round(n(placement.y) * H);
  left = Math.min(Math.max(left, 0), Math.max(0, W - lmeta.width));
  top = Math.min(Math.max(top, 0), Math.max(0, H - lmeta.height));

  const out = await sharp(baseBuf)
    .composite([{ input: logoPng, top: top, left: left }])
    .jpeg({ quality: 95 })
    .toBuffer();
  return out;
}

// Legacy helper: render + persist to S3. Retained for callers that need a stored URL.
async function compositeLogoOnImage(baseUrl, placement, jobId, imageIndex) {
  const out = await renderLogoBuffer(baseUrl, placement);
  const key = `${jobId}_logo_${imageIndex}_${Date.now()}.jpg`;
  return await uploadBufferToS3(out, key, 'image/jpeg');
}

// Latest non-logo version url (the clean image), else a fallback.
async function cleanBaseUrl(projectImageId, fallbackUrl) {
  const { data: versions } = await supabase
    .from('project_image_versions')
    .select('url, source, seq')
    .eq('project_image_id', projectImageId)
    .order('seq', { ascending: false });
  const clean = (versions || []).find(function (v) { return v.source !== 'logo'; });
  return clean ? clean.url : fallbackUrl;
}

// Stamp (or re-stamp) the logo onto one image. Always composites from the clean
// base so re-positioning never stacks. Keeps a single source='logo' version.
async function stampLogoOnImage(image, jobId, placement) {
  let base = image.logo_base_url;
  if (!base) base = await cleanBaseUrl(image.id, image.current_url || image.enhanced_url);
  if (!base) return;

  const brandedUrl = await compositeLogoOnImage(base, placement, jobId || 'job', image.image_index);

  const { data: existing } = await supabase
    .from('project_image_versions')
    .select('id').eq('project_image_id', image.id).eq('source', 'logo').maybeSingle();

  let versionId;
  if (existing) {
    await supabase.from('project_image_versions').update({ url: brandedUrl }).eq('id', existing.id);
    versionId = existing.id;
  } else {
    const { data: last } = await supabase
      .from('project_image_versions').select('seq')
      .eq('project_image_id', image.id).order('seq', { ascending: false }).limit(1).maybeSingle();
    const nextSeq = (last && last.seq ? last.seq : 0) + 1;
    const { data: v, error: insErr } = await supabase
      .from('project_image_versions')
      .insert({ project_image_id: image.id, url: brandedUrl, source: 'logo', seq: nextSeq })
      .select('id').single();
    if (insErr || !v) throw new Error('logo version insert failed: ' + (insErr ? insErr.message : 'no row returned'));
    versionId = v.id;
  }
  await supabase.from('project_images')
    .update({ current_url: brandedUrl, active_version_id: versionId, logo_base_url: base })
    .eq('id', image.id);
}

// Remove the logo from one image: drop the logo version, revert to clean base.
async function removeLogoFromImage(image) {
  await supabase.from('project_image_versions')
    .delete().eq('project_image_id', image.id).eq('source', 'logo');
  const base = image.logo_base_url || await cleanBaseUrl(image.id, image.current_url || image.enhanced_url);
  const { data: remaining } = await supabase
    .from('project_image_versions').select('id, seq')
    .eq('project_image_id', image.id).order('seq', { ascending: false }).limit(1).maybeSingle();
  await supabase.from('project_images')
    .update({ current_url: base, active_version_id: remaining ? remaining.id : null, logo_base_url: null, logo_placement: null })
    .eq('id', image.id);
}

// ── Logo: set the ALBUM DEFAULT placement (restamps non-override images) ──────
app.post('/api/album/:id/logo', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { logoId, placement } = req.body || {};
  if (!logoId || !placement) return res.status(400).json({ error: 'Missing logoId or placement' });
  try {
    const { data: album } = await supabase.from('albums').select('id, user_id').eq('id', id).maybeSingle();
    if (!album || album.user_id !== req.user.id) return res.status(404).json({ error: 'Album not found' });
    const { data: logo } = await supabase.from('logos').select('id, user_id, image_url').eq('id', logoId).maybeSingle();
    if (!logo || logo.user_id !== req.user.id) return res.status(404).json({ error: 'Logo not found' });

    const full = { logoUrl: logo.image_url, x: n(placement.x), y: n(placement.y), w: n(placement.w), opacity: placement.opacity == null ? 1 : n(placement.opacity) };
    // EXPORT-ONLY WATERMARK: the album default is just a stored placement. Every image
    // in the album inherits it at export time unless it has its own logo_placement
    // override. No stamping loop, so applying an album logo no longer rewrites any
    // image's history or current_url.
    await supabase.from('albums').update({ logo_placement: full }).eq('id', id);
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('album logo error:', e.message);
    return res.status(500).json({ error: 'Could not apply album logo' });
  }
});

// ── Logo: set a PER-IMAGE OVERRIDE placement (restamps that image) ────────────
app.post('/api/image/:id/logo', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { logoId, placement } = req.body || {};
  if (!placement) return res.status(400).json({ error: 'Missing placement' });
  try {
    const { data: image } = await supabase
      .from('project_images')
      .select('id, project_id, image_index, current_url, enhanced_url, logo_base_url, projects!inner(user_id, job_id, album_id)')
      .eq('id', id).maybeSingle();
    if (!image || !image.projects || image.projects.user_id !== req.user.id) return res.status(404).json({ error: 'Image not found' });

    let logoUrl;
    if (logoId) {
      const { data: logo } = await supabase.from('logos').select('id, user_id, image_url').eq('id', logoId).maybeSingle();
      if (!logo || logo.user_id !== req.user.id) return res.status(404).json({ error: 'Logo not found' });
      logoUrl = logo.image_url;
    } else {
      const { data: album } = await supabase.from('albums').select('logo_placement').eq('id', image.projects.album_id).maybeSingle();
      logoUrl = album && album.logo_placement ? album.logo_placement.logoUrl : null;
      if (!logoUrl) return res.status(400).json({ error: 'No logo selected' });
    }

    const full = { logoUrl: logoUrl, x: n(placement.x), y: n(placement.y), w: n(placement.w), opacity: placement.opacity == null ? 1 : n(placement.opacity) };
    // EXPORT-ONLY WATERMARK: store the placement and stop. We do NOT composite here,
    // do NOT create a source='logo' version, and do NOT touch current_url /
    // active_version_id. The logo is applied on the fly at download/share time
    // (/api/image/:id/export) over whatever version is active then. This is what
    // keeps the history chain purely real results and makes the logo version-agnostic.
    await supabase.from('project_images').update({ logo_placement: full }).eq('id', id);
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('image logo error:', e.message);
    return res.status(500).json({ error: 'Could not apply logo' });
  }
});

// ── Logo: remove from the whole album (revert every image to its clean base) ──
app.post('/api/album/:id/logo/remove', requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const { data: album } = await supabase.from('albums').select('id, user_id').eq('id', id).maybeSingle();
    if (!album || album.user_id !== req.user.id) return res.status(404).json({ error: 'Album not found' });
    await supabase.from('albums').update({ logo_placement: null }).eq('id', id);

    // EXPORT-ONLY WATERMARK: removing is just clearing stored placements — there are
    // no baked-in logo versions to unwind. Clear per-image overrides too so "remove
    // logo" means the whole album exports clean.
    const { data: projects } = await supabase.from('projects').select('id').eq('album_id', id);
    const projIds = (projects || []).map(function (p) { return p.id; });
    if (projIds.length) {
      await supabase.from('project_images')
        .update({ logo_placement: null })
        .in('project_id', projIds).is('deleted_at', null);
    }
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('album logo remove error:', e.message);
    return res.status(500).json({ error: 'Could not remove logo' });
  }
});

// ── Logo: clear a single image's override placement ──────────────────────────
app.post('/api/image/:id/logo/remove', requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const { data: image } = await supabase
      .from('project_images')
      .select('id, projects!inner(user_id)')
      .eq('id', id).maybeSingle();
    if (!image || !image.projects || image.projects.user_id !== req.user.id) return res.status(404).json({ error: 'Image not found' });
    await supabase.from('project_images').update({ logo_placement: null }).eq('id', id);
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('image logo remove error:', e.message);
    return res.status(500).json({ error: 'Could not remove logo' });
  }
});

// ── Export: the ACTIVE version with the watermark applied on the fly ──────────
// Returns JPEG BYTES (not a URL). The logo is composited at request time over
// whichever version is currently active, using the image's own placement or the
// album default. No placement -> the untouched active image is returned. Because
// this streams from our own origin, downloads are not subject to the S3 CORS
// limitation that forced the open-in-a-tab fallback.
app.post('/api/image/:id/export', requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const { data: image } = await supabase
      .from('project_images')
      .select('id, image_index, current_url, enhanced_url, logo_placement, projects!inner(user_id, album_id)')
      .eq('id', id).maybeSingle();
    if (!image || !image.projects || image.projects.user_id !== req.user.id) return res.status(404).json({ error: 'Image not found' });

    const baseUrl = image.current_url || image.enhanced_url;
    if (!baseUrl) return res.status(404).json({ error: 'No image to export' });

    // Per-image override wins; otherwise inherit the album default.
    let placement = image.logo_placement;
    if (!placement && image.projects.album_id) {
      const { data: album } = await supabase
        .from('albums').select('logo_placement').eq('id', image.projects.album_id).maybeSingle();
      placement = album ? album.logo_placement : null;
    }

    let buf;
    if (placement && placement.logoUrl) {
      buf = await renderLogoBuffer(baseUrl, placement);
    } else {
      const r = await axios.get(baseUrl, { responseType: 'arraybuffer' });
      buf = Buffer.from(r.data);
    }

    res.setHeader('Content-Type', 'image/jpeg');
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).send(buf);
  } catch (e) {
    console.error('image export error:', e.message);
    return res.status(500).json({ error: 'Could not export image' });
  }
});

// ── Maintenance: unwind legacy baked-in logo versions (one-time, idempotent) ──
// Pre-export-watermark, applying a logo wrote a source='logo' version and pointed
// current_url/active_version_id at it. This removes those versions and restores each
// image to its newest real result. logo_placement is KEPT, so the same logo simply
// applies at export instead. Safe to run repeatedly; only touches source='logo' rows.
app.post('/api/maintenance/unstamp-logos', async (req, res) => {
  if (req.headers['x-callback-secret'] !== CALLBACK_SECRET) {
    return res.status(403).json({ error: 'Invalid callback secret' });
  }
  try {
    const { data: rows } = await supabase
      .from('project_image_versions').select('project_image_id').eq('source', 'logo');
    const ids = Array.from(new Set((rows || []).map(function (r) { return r.project_image_id; })));
    let fixed = 0;
    for (const imageId of ids) {
      const { data: vs } = await supabase
        .from('project_image_versions').select('id, url, source, seq')
        .eq('project_image_id', imageId).order('seq', { ascending: false });
      const clean = (vs || []).find(function (v) { return v.source !== 'logo'; });
      const { data: im } = await supabase
        .from('project_images').select('id, enhanced_url').eq('id', imageId).maybeSingle();
      // Point the image away from the logo version FIRST — project_images
      // .active_version_id has a foreign key onto the versions table.
      await supabase.from('project_images').update({
        current_url: clean ? clean.url : (im ? im.enhanced_url : null),
        active_version_id: clean ? clean.id : null,
        logo_base_url: null
      }).eq('id', imageId);
      await supabase.from('project_image_versions')
        .delete().eq('project_image_id', imageId).eq('source', 'logo');
      fixed++;
    }
    return res.status(200).json({ ok: true, images_unstamped: fixed });
  } catch (e) {
    console.error('unstamp-logos error:', e.message);
    return res.status(500).json({ error: 'Unstamp failed' });
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
