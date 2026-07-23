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

// Max trials granted per originating IP per rolling 24h. Blunt but effective against
// the cheap attack (script signs up N throwaway accounts from one box).
const TRIAL_MAX_PER_IP_PER_DAY = Number(process.env.TRIAL_MAX_PER_IP_PER_DAY || 3);

// Days before unspent TRIAL credits expire. Creates urgency and caps exposure to
// dormant accounts. Set TRIAL_DAYS=0 to disable expiry. Purchased credits NEVER
// expire — a purchase clears trial_expires_at (see the Stripe webhook).
const TRIAL_DAYS = Number(process.env.TRIAL_DAYS || 14);

// Balance at or below which the dashboard nudges the user to top up.
const LOW_CREDIT_THRESHOLD = Number(process.env.LOW_CREDIT_THRESHOLD || 10);

// Disposable / throwaway email providers. Blocked at signup and again at grant time.
// Extend without a deploy via EXTRA_BLOCKED_EMAIL_DOMAINS (comma-separated).
const DISPOSABLE_EMAIL_DOMAINS = new Set([
  'mailinator.com', 'guerrillamail.com', 'guerrillamail.net', 'sharklasers.com',
  '10minutemail.com', '10minutemail.net', 'tempmail.com', 'temp-mail.org',
  'yopmail.com', 'yopmail.net', 'throwawaymail.com', 'trashmail.com', 'trashmail.de',
  'getnada.com', 'nada.email', 'dispostable.com', 'maildrop.cc', 'fakeinbox.com',
  'mailnesia.com', 'moakt.com', 'emailondeck.com', 'spamgourmet.com', 'mintemail.com',
  'tempr.email', 'discard.email', 'mailcatch.com', 'mytemp.email', 'inboxbear.com',
  'burnermail.io', 'einrot.com', 'fakemail.net', 'tempinbox.com', 'mohmal.com',
  'anonaddy.me', 'mailtemp.net', 'tmpmail.org', 'luxusmail.org'
].concat(
  (process.env.EXTRA_BLOCKED_EMAIL_DOMAINS || '')
    .split(',').map(function (s) { return s.trim().toLowerCase(); }).filter(Boolean)
));

// Suffix families that spawn endless subdomains (a.temp-mail.org, b.temp-mail.org…).
const DISPOSABLE_EMAIL_SUFFIXES = ['.temp-mail.org', '.yopmail.com', '.mailinator.com'];

function isDisposableEmail(email) {
  const at = String(email || '').lastIndexOf('@');
  if (at < 0) return false;
  const domain = String(email).slice(at + 1).toLowerCase().trim();
  if (!domain) return false;
  if (DISPOSABLE_EMAIL_DOMAINS.has(domain)) return true;
  return DISPOSABLE_EMAIL_SUFFIXES.some(function (s) { return domain.endsWith(s); });
}

// Railway terminates TLS at a proxy, so req.ip is the proxy. Take the first hop of
// x-forwarded-for (the real client) and fall back to the socket address.
function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) {
    const first = String(fwd).split(',')[0].trim();
    if (first) return first;
  }
  return (req.socket && req.socket.remoteAddress) || req.ip || null;
}

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
  // Cheapest possible abuse control: throwaway inboxes never reach the trial grant.
  if (isDisposableEmail(email)) {
    return res.status(400).json({ error: 'Please sign up with a permanent email address.' });
  }
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
    .select('balance, trial_granted_at, trial_expires_at')
    .eq('user_id', req.user.id)
    .maybeSingle();

  if (existing) {
    let balance = existing.balance;
    const expired = existing.trial_expires_at && new Date(existing.trial_expires_at) < new Date();
    if (expired && balance > 0) { await expireTrialCredits(req.user.id, balance); balance = 0; }
    const onTrial = !!existing.trial_expires_at;
    return res.json({
      balance: balance,
      trial_only: onTrial ? true : await isTrialOnly(req.user.id),
      trial_expires_at: existing.trial_expires_at || null,
      trial_expired: !!expired,
      low_threshold: LOW_CREDIT_THRESHOLD
    });
  }

  const trial = await grantTrialIfEligible(req.user, req);
  // No row and not eligible (e.g. unverified email) -> report 0 rather than a 500,
  // which is what used to happen to every brand-new user.
  return res.json({
    balance: trial.balance == null ? 0 : trial.balance,
    trial_granted: trial.granted,
    low_threshold: LOW_CREDIT_THRESHOLD
  });
});

// Explicit claim endpoint, for a client that wants to trigger/confirm the grant
// directly (e.g. right after email verification) rather than wait for a balance read.
app.post('/api/trial/claim', requireAuth, async (req, res) => {
  const trial = await grantTrialIfEligible(req.user, req);
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
async function grantTrialIfEligible(user, req) {
  if (!TRIAL_CREDITS || TRIAL_CREDITS <= 0) return { granted: false, balance: null, reason: 'trial_disabled' };
  if (!user) return { granted: false, balance: null, reason: 'no_user' };

  const verified = user.email_confirmed_at || user.confirmed_at;
  if (!verified) return { granted: false, balance: null, reason: 'email_unverified' };

  // Defense in depth: signup already rejects these, but an account could predate the
  // blocklist or have been created another way.
  if (isDisposableEmail(user.email)) {
    return { granted: false, balance: null, reason: 'disposable_email' };
  }

  // A credits row may already exist with a ZERO balance and no trial — some stacks
  // create one at signup (DB trigger, earlier code path, manual insert). Treating that
  // as "already has credits" silently blocks the trial for every such user, so we
  // distinguish an EMPTY placeholder row from a real one.
  const { data: existing } = await supabase
    .from('credits').select('balance, trial_granted_at').eq('user_id', user.id).maybeSingle();

  if (existing) {
    // Trial already granted (including one that was spent or expired) — never re-grant.
    if (existing.trial_granted_at) {
      return { granted: false, balance: existing.balance, reason: 'already_granted' };
    }
    // Real credits present -> nothing to do.
    if ((existing.balance || 0) > 0) {
      return { granted: false, balance: existing.balance, reason: 'has_credits' };
    }
    // Zero balance and never granted. Only top up if they've never PURCHASED —
    // otherwise this is a paying customer who simply spent down to 0.
    const { data: purchase } = await supabase
      .from('credit_transactions').select('id')
      .eq('user_id', user.id).eq('type', 'purchase').limit(1).maybeSingle();
    if (purchase) {
      return { granted: false, balance: existing.balance, reason: 'spent_purchased_credits' };
    }
  }

  // Per-IP cap over a rolling 24h window. Unknown IP skips the check rather than
  // blocking a legitimate user (the verified-email gate still applies).
  const ip = req ? clientIp(req) : null;
  if (ip && TRIAL_MAX_PER_IP_PER_DAY > 0) {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const { count } = await supabase
      .from('trial_grant_log')
      .select('id', { count: 'exact', head: true })
      .eq('ip', ip).gte('created_at', since);
    if ((count || 0) >= TRIAL_MAX_PER_IP_PER_DAY) {
      console.warn('Trial blocked (IP cap):', ip, user.id);
      return { granted: false, balance: null, reason: 'ip_rate_limited' };
    }
  }

  const expiresAt = TRIAL_DAYS > 0
    ? new Date(Date.now() + TRIAL_DAYS * 24 * 60 * 60 * 1000)
    : null;

  // UPDATE when a placeholder row already exists, INSERT when it doesn't. The UPDATE is
  // guarded by trial_granted_at IS NULL so two concurrent calls can't both grant (the
  // second matches no rows); the INSERT is guarded by the UNIQUE constraint on user_id.
  let error = null;
  if (existing) {
    const { data: updated, error: uErr } = await supabase
      .from('credits')
      .update({ balance: TRIAL_CREDITS, trial_granted_at: new Date(), trial_expires_at: expiresAt, updated_at: new Date() })
      .eq('user_id', user.id)
      .is('trial_granted_at', null)
      .select('user_id');
    error = uErr;
    if (!uErr && (!updated || !updated.length)) {
      const { data: now } = await supabase
        .from('credits').select('balance').eq('user_id', user.id).maybeSingle();
      return { granted: false, balance: now ? now.balance : null, reason: 'race_or_error' };
    }
  } else {
    const ins = await supabase
      .from('credits')
      .insert({
        user_id: user.id,
        balance: TRIAL_CREDITS,
        trial_granted_at: new Date(),
        trial_expires_at: expiresAt
      });
    error = ins.error;
  }

  if (error) {
    // Almost always the unique-constraint race: another request granted it first.
    const { data: now } = await supabase
      .from('credits').select('balance').eq('user_id', user.id).maybeSingle();
    return { granted: false, balance: now ? now.balance : null, reason: 'race_or_error' };
  }

  // Log AFTER the successful insert so blocked/failed attempts don't burn the IP quota.
  await supabase.from('trial_grant_log').insert({ user_id: user.id, ip: ip, email: user.email });

  await supabase.from('credit_transactions').insert({
    user_id: user.id, amount: TRIAL_CREDITS, type: 'trial', description: 'Free trial credits'
  });
  console.log('Trial granted:', user.id, TRIAL_CREDITS, 'credits, ip:', ip);
  return { granted: true, balance: TRIAL_CREDITS, reason: 'granted' };
}

// True when the user is running purely on trial credits — trial was granted and they
// have never made a purchase. Used to gate premium actions out of the trial.
async function isTrialOnly(userId) {
  const { data: c } = await supabase
    .from('credits').select('trial_granted_at').eq('user_id', userId).maybeSingle();
  if (!c || !c.trial_granted_at) return false;
  const { data: purchase } = await supabase
    .from('credit_transactions').select('id')
    .eq('user_id', userId).eq('type', 'purchase').limit(1).maybeSingle();
  return !purchase;
}

// Zero out unspent trial credits once the window has closed, and leave an audit row.
// Idempotent in practice: after this runs balance is 0, so it won't log again.
async function expireTrialCredits(userId, balance) {
  await supabase.from('credits')
    .update({ balance: 0, updated_at: new Date() })
    .eq('user_id', userId);
  await supabase.from('credit_transactions').insert({
    user_id: userId, amount: -balance, type: 'trial_expired',
    description: 'Unused trial credits expired'
  });
  console.log('Trial expired:', userId, 'forfeited', balance);
}

async function deductCredits(userId, amount, type, description) {
  const { data: credits } = await supabase
    .from('credits')
    .select('balance, trial_expires_at')
    .eq('user_id', userId)
    .maybeSingle();

  if (!credits) return false;

  // Expiry is enforced here so it applies to every spend path, not just the balance
  // read. trial_expires_at is non-null ONLY while a user is on unpurchased trial
  // credits (a purchase clears it), so this can never zero out paid credits.
  if (credits.trial_expires_at && new Date(credits.trial_expires_at) < new Date()) {
    if (credits.balance > 0) await expireTrialCredits(userId, credits.balance);
    return false;
  }

  if (credits.balance < amount) return false;

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
        .maybeSingle();

      if (existing) {
        await supabase
          .from('credits')
          .update({ balance: existing.balance + creditsToAdd, updated_at: new Date(), trial_expires_at: null })
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
  // Animation is excluded from the free trial: 8 credits ≈ a $2 Veo clip, which is far
  // too much hard cost to hand to an unconverted signup, and video isn't what sells the
  // product. Checked BEFORE deducting so trial users are never charged for a refusal,
  // and returns a distinct code so the client can show an upgrade prompt rather than a
  // generic "insufficient credits".
  if (await isTrialOnly(req.user.id)) {
    return res.status(402).json({
      error: 'Animation isn\'t included in the free trial. Add credits to unlock it.',
      code: 'trial_excluded'
    });
  }

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
// Trial watermark. Composited onto EXPORTS ONLY (never stored), so upgrading instantly
// removes it from every future download with no reprocessing. Drawn as SVG text so
// there's no asset to host, sized relative to image width so it scales with any render.
async function applyTrialMark(jpegBuf) {
  try {
    const meta = await sharp(jpegBuf).metadata();
    const W = meta.width || 1200;
    const fs = Math.max(14, Math.round(W / 30));
    const pad = Math.round(fs * 0.55);
    const text = 'Made with StudioFinish';
    const boxW = Math.round(text.length * fs * 0.54) + pad * 2;
    const boxH = fs + pad * 2;
    const svg = `<svg width="${boxW}" height="${boxH}" xmlns="http://www.w3.org/2000/svg">
  <text x="${pad}" y="${Math.round(boxH * 0.68)}"
        font-family="Helvetica, Arial, sans-serif" font-size="${fs}" font-weight="600"
        fill="#ffffff" fill-opacity="0.85"
        stroke="#000000" stroke-opacity="0.30" stroke-width="${Math.max(1, Math.round(fs / 14))}"
        paint-order="stroke">${text}</text>
</svg>`;
    return await sharp(jpegBuf)
      .composite([{ input: Buffer.from(svg), gravity: 'southeast' }])
      .jpeg({ quality: 95 })
      .toBuffer();
  } catch (e) {
    // Never fail a download because the mark couldn't render.
    console.error('trial mark error:', e.message);
    return jpegBuf;
  }
}

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

    // Trial downloads carry our mark. Applied last so it sits on top of the user's own
    // logo, and only at export — nothing branded is ever written to their saved image.
    if (await isTrialOnly(req.user.id)) buf = await applyTrialMark(buf);

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

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Studio — Your Albums</title>
<style>
  :root{
    /* Ocean palette (cohesive with the marketing site) */
    --bg:#06101A;
    --bg-2:#081826;
    --surface:rgba(255,255,255,.045);
    --surface-2:rgba(255,255,255,.07);
    --hairline:rgba(255,255,255,.09);
    --hairline-strong:rgba(255,255,255,.16);
    --aqua:#00C2C7;
    --aqua-soft:rgba(0,194,199,.16);
    --ocean:#0077A8;
    --yellow:#F5C842;
    --text:#EAF4F8;
    --text-muted:#8AA6B6;
    --text-dim:#4A6675;
    --red:#E0625A;
    --green:#2ABF7A;
    /* Apple-grade craft */
    --r-lg:24px; --r-md:16px; --r-sm:11px;
    --ease:cubic-bezier(.22,.61,.36,1);
    --shadow:0 12px 40px rgba(0,0,0,.45);
    --shadow-hi:0 22px 60px rgba(0,0,0,.55);
    --font:-apple-system,BlinkMacSystemFont,"SF Pro Display","SF Pro Text",system-ui,"Segoe UI",sans-serif;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  html,body{height:100%}
  body{
    font-family:var(--font);
    color:var(--text);
    background:
      radial-gradient(1100px 700px at 78% -8%, rgba(0,119,168,.20), transparent 60%),
      radial-gradient(900px 600px at 6% 4%, rgba(0,194,199,.10), transparent 55%),
      var(--bg);
    -webkit-font-smoothing:antialiased;
    letter-spacing:-.01em;
    min-height:100%;
  }
  img{display:block;max-width:100%}
  button{font-family:inherit;cursor:pointer;border:none;background:none;color:inherit}
  a{color:inherit;text-decoration:none}
  :focus-visible{outline:2px solid var(--aqua);outline-offset:2px;border-radius:6px}

  /* ── Top bar ── */
  .topbar{
    position:sticky;top:0;z-index:40;
    display:flex;align-items:center;gap:16px;
    padding:14px clamp(18px,4vw,40px);
    background:rgba(6,16,26,.62);
    backdrop-filter:blur(22px) saturate(160%);
    -webkit-backdrop-filter:blur(22px) saturate(160%);
    border-bottom:1px solid var(--hairline);
  }
  .brand{display:flex;align-items:center;gap:11px;font-weight:600;font-size:17px}
  .brand .dot{width:11px;height:11px;border-radius:50%;
    background:radial-gradient(circle at 30% 30%,var(--aqua),var(--ocean));
    box-shadow:0 0 16px var(--aqua-soft)}
  .brand small{color:var(--text-muted);font-weight:500}
  .spacer{flex:1}
  .credits{
    display:flex;align-items:center;gap:7px;
    padding:8px 14px;border-radius:999px;
    background:var(--surface);border:1px solid var(--hairline);
    font-size:13.5px;font-weight:600;
  }
  .credits b{color:var(--yellow)}
  .trial-badge{
    display:inline-block;margin-left:8px;padding:3px 9px;border-radius:999px;
    font-size:11.5px;font-weight:600;letter-spacing:.2px;
    background:rgba(255,255,255,.08);color:var(--text-muted);
    border:1px solid rgba(255,255,255,.14);white-space:nowrap;cursor:default
  }
  .low-credit-bar{
    display:flex;align-items:center;gap:12px;flex-wrap:wrap;
    margin:0 0 16px;padding:11px 14px;border-radius:12px;
    background:rgba(255,196,0,.10);border:1px solid rgba(255,196,0,.30);
    font-size:13.5px;color:var(--text)
  }
  .low-credit-bar .lc-x{
    margin-left:auto;background:none;border:0;color:var(--text-muted);
    font-size:16px;line-height:1;cursor:pointer;padding:2px 6px
  }
  .ghost-btn{
    padding:8px 15px;border-radius:999px;font-size:13.5px;font-weight:600;
    background:var(--surface);border:1px solid var(--hairline);
    transition:background .25s var(--ease),border-color .25s var(--ease);
  }
  .ghost-btn:hover{background:var(--surface-2);border-color:var(--hairline-strong)}

  /* ── Layout shell ── */
  .wrap{max-width:1320px;margin:0 auto;padding:clamp(22px,4vw,46px) clamp(18px,4vw,40px) 96px}
  .page-head{display:flex;align-items:flex-end;gap:18px;margin-bottom:30px}
  .page-head h1{font-size:clamp(26px,4vw,38px);font-weight:700;letter-spacing:-.03em}
  .page-head p{color:var(--text-muted);font-size:15px;margin-top:6px}
  .back{
    display:inline-flex;align-items:center;gap:8px;margin-bottom:18px;
    color:var(--text-muted);font-size:14.5px;font-weight:600;
    transition:color .2s var(--ease),transform .2s var(--ease);
  }
  .back:hover{color:var(--text);transform:translateX(-2px)}

  /* ── Album tiles ── */
  .album-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(420px,1fr));gap:26px}
  @media (max-width:520px){ .album-grid{grid-template-columns:1fr} }
  /* "build your Library" banner (albums view) */
  .lib-banner{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:24px;
    padding:14px 18px;border-radius:var(--r-md);
    background:linear-gradient(90deg,var(--aqua-soft),rgba(0,119,168,.10));
    border:1px solid var(--hairline-strong)}
  .lib-banner-txt{flex:1;min-width:220px;font-size:14px;line-height:1.5;color:var(--text)}
  .lib-banner-txt b{font-weight:700}
  .lib-banner-actions{display:flex;align-items:center;gap:10px}
  .lib-banner-x{width:30px;height:30px;border-radius:8px;background:var(--surface);
    border:1px solid var(--hairline);color:var(--text-muted);font-size:13px}
  .lib-banner-x:hover{background:var(--surface-2);color:var(--text)}
  /* album sort control */
  .album-sort{margin-left:auto}
  /* library (reusable assets — deliberately distinct from album tiles) */
  .lib-tabs{display:flex;gap:6px;margin-bottom:26px;border-bottom:1px solid var(--hairline)}
  .lib-tab{padding:10px 16px;font-size:14px;font-weight:600;color:var(--text-muted);border-bottom:2px solid transparent;margin-bottom:-1px;transition:color .2s var(--ease),border-color .2s var(--ease)}
  .lib-tab:hover{color:var(--text)}
  .lib-tab.active{color:var(--text);border-bottom-color:var(--aqua)}
  .asset-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:18px}
  .asset{position:relative;border-radius:var(--r-md);overflow:hidden;background:var(--surface);border:1px solid var(--hairline);transition:border-color .2s var(--ease)}
  .asset:hover{border-color:var(--hairline-strong)}
  .asset-img{aspect-ratio:1/1;display:flex;align-items:center;justify-content:center;overflow:hidden;
    background:repeating-conic-gradient(#16242f 0% 25%,#0f1c26 0% 50%) 50% / 22px 22px}
  .asset-img img{max-width:78%;max-height:78%;object-fit:contain}
  .asset-name{padding:8px 11px;font-size:12.5px;color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .asset-del{position:absolute;top:8px;right:8px;width:28px;height:28px;border-radius:8px;
    background:rgba(6,16,26,.72);border:1px solid var(--hairline);color:var(--text);
    display:grid;place-items:center;font-size:13px;opacity:0;transition:opacity .2s var(--ease)}
  .asset:hover .asset-del{opacity:1}
  .asset-add{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;
    aspect-ratio:1/1;border:1.5px dashed var(--hairline-strong);border-radius:var(--r-md);
    color:var(--text-muted);cursor:pointer;background:var(--surface);transition:all .2s var(--ease);font-size:13px}
  .asset-add:hover{border-color:var(--aqua);color:var(--text)}
  .asset-add .plus{font-size:26px;line-height:1}
  .tile{
    position:relative;border-radius:var(--r-lg);overflow:hidden;
    background:var(--surface);border:1px solid var(--hairline);
    box-shadow:var(--shadow);
    transition:transform .4s var(--ease),box-shadow .4s var(--ease),border-color .3s var(--ease);
    cursor:pointer;
  }
  .tile:hover{transform:translateY(-6px);box-shadow:var(--shadow-hi);border-color:var(--hairline-strong)}
  .tile-cover{aspect-ratio:16/10;background:var(--bg-2);overflow:hidden;position:relative}
  .tile-cover img{width:100%;height:100%;object-fit:cover;transition:transform .6s var(--ease)}
  .tile:hover .tile-cover img{transform:scale(1.045)}
  .tile-cover.empty{display:flex;align-items:center;justify-content:center;color:var(--text-dim);font-size:13px}
  .tile-scrim{position:absolute;inset:0;background:linear-gradient(to top,rgba(6,16,26,.86) 4%,transparent 46%)}
  .tile-body{position:absolute;left:0;right:0;bottom:0;padding:15px 16px;display:flex;align-items:flex-end;gap:10px}
  .tile-body .meta{flex:1;min-width:0}
  .tile-body h3{font-size:16px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .tile-body .sub{color:var(--text-muted);font-size:12.5px;margin-top:3px}
  .tile-rename{
    opacity:0;flex:0 0 auto;width:32px;height:32px;border-radius:10px;
    background:rgba(6,16,26,.5);border:1px solid var(--hairline);
    display:grid;place-items:center;transition:opacity .25s var(--ease),background .2s var(--ease);
  }
  .tile:hover .tile-rename{opacity:1}
  .tile-rename:hover{background:rgba(6,16,26,.8)}
  .status-dot{position:absolute;top:13px;left:13px;display:flex;align-items:center;gap:6px;
    padding:5px 10px;border-radius:999px;background:rgba(6,16,26,.55);
    backdrop-filter:blur(8px);font-size:11.5px;font-weight:600;color:var(--text-muted)}
  .status-dot i{width:7px;height:7px;border-radius:50%;background:var(--text-dim)}
  .status-dot.done i{background:var(--green);box-shadow:0 0 9px rgba(42,191,122,.7)}
  .status-dot.proc i{background:var(--yellow);box-shadow:0 0 9px rgba(245,200,66,.7)}

  /* ── Image cards (album detail) ── */
  .card-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:24px}
  .card{
    border-radius:var(--r-lg);overflow:hidden;
    background:var(--surface);border:1px solid var(--hairline);box-shadow:var(--shadow);
    display:flex;flex-direction:column;
  }
  .stage{position:relative;background:var(--bg-2);aspect-ratio:3/2;overflow:hidden}
  .stage>img{width:100%;height:100%;object-fit:cover}
  .badge{position:absolute;top:12px;right:12px;padding:5px 11px;border-radius:999px;
    font-size:11.5px;font-weight:700;letter-spacing:.02em;
    background:rgba(6,16,26,.55);backdrop-filter:blur(8px);border:1px solid var(--hairline)}
  .badge.k4{color:var(--yellow);border-color:rgba(245,200,66,.4)}
  .expand{position:absolute;top:12px;left:12px;width:34px;height:34px;border-radius:10px;
    background:rgba(6,16,26,.5);backdrop-filter:blur(8px);border:1px solid var(--hairline);
    display:grid;place-items:center;opacity:0;transition:opacity .25s var(--ease)}
  .stage:hover .expand{opacity:1}

  /* compare slider */
  .compare{position:absolute;inset:0;user-select:none;touch-action:none}
  .compare img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}
  .compare .top{clip-path:inset(0 calc(100% - var(--pct,50%)) 0 0)}
  .cmp-divider{position:absolute;top:0;bottom:0;left:var(--pct,50%);width:2px;
    background:rgba(255,255,255,.85);transform:translateX(-1px);box-shadow:0 0 12px rgba(0,0,0,.5)}
  .cmp-handle{position:absolute;top:50%;left:var(--pct,50%);transform:translate(-50%,-50%);
    width:38px;height:38px;border-radius:50%;background:rgba(6,16,26,.7);backdrop-filter:blur(6px);
    border:1.5px solid rgba(255,255,255,.85);display:grid;place-items:center;font-size:13px;color:#fff;pointer-events:none}
  .cmp-range{position:absolute;inset:0;width:100%;height:100%;opacity:0;cursor:ew-resize;margin:0}
  .cmp-tag{position:absolute;bottom:12px;padding:4px 10px;border-radius:999px;font-size:11px;font-weight:700;
    background:rgba(6,16,26,.6);backdrop-filter:blur(6px);letter-spacing:.04em}
  .cmp-tag.l{left:12px;color:var(--text)} .cmp-tag.r{right:12px;color:var(--aqua)}

  .card-body{padding:15px 16px 17px;display:flex;flex-direction:column;gap:13px;min-width:0}
  .card-title-row{display:flex;align-items:center;gap:10px}
  .card-title-row h4{font-size:15px;font-weight:600;flex:1}
  .pick-row{display:flex;gap:9px}
  .pick-row button{
    flex:1;padding:10px;border-radius:var(--r-sm);font-size:13px;font-weight:600;
    background:var(--surface-2);border:1px solid var(--hairline);transition:.2s var(--ease);
  }
  .pick-row button:hover{border-color:var(--aqua);color:var(--aqua)}
  .pick-row button.active{background:var(--aqua);color:#04222b;border-color:transparent}
  .pick-row button[disabled]{opacity:.4;cursor:not-allowed}

  .tool{display:flex;gap:9px;align-items:stretch}
  .refine-in{
    flex:1;resize:none;border-radius:var(--r-sm);padding:10px 12px;font-size:13px;line-height:1.45;
    background:var(--bg-2);border:1px solid var(--hairline);color:var(--text);font-family:inherit;
    transition:border-color .2s var(--ease);
  }
  .refine-in:focus{outline:none;border-color:var(--aqua)}
  .refine-in::placeholder{color:var(--text-dim)}
  .btn{
    border-radius:var(--r-sm);font-size:13px;font-weight:600;padding:10px 14px;white-space:nowrap;
    border:1px solid var(--hairline);background:var(--surface-2);transition:.2s var(--ease);
    display:inline-flex;align-items:center;justify-content:center;gap:6px;
  }
  .btn:hover:not([disabled]){border-color:var(--hairline-strong);background:rgba(255,255,255,.1)}
  .btn[disabled]{opacity:.5;cursor:not-allowed}
  .btn.primary{background:var(--aqua);color:#04222b;border-color:transparent}
  .btn.primary:hover:not([disabled]){filter:brightness(1.08)}
  .btn-row{display:flex;gap:9px;flex-wrap:wrap}
  .btn.icon{padding:10px 12px}
  .btn.wide{flex:1}
  /* stacked, self-describing action groups in the image card */
  .tool-group{display:flex;flex-direction:column;gap:8px}
  .tool-hint{font-size:12px;line-height:1.5;color:var(--text-muted);margin:0}
  .tool-hint .eg{display:block;margin-top:5px;color:var(--text-dim);font-style:italic;font-size:11.5px}
  .btn-row.pair{flex-wrap:nowrap}
  .btn-row.pair .btn{flex:1}
  .share-row .btn{flex:1}

  .history{display:flex;align-items:center;gap:9px;min-width:0}
  .hist-nav{display:flex;gap:6px}
  .hist-strip{display:flex;gap:7px;overflow-x:auto;padding:2px 0;flex:1;min-width:0;scroll-behavior:smooth;scrollbar-width:none}
  .hist-strip::-webkit-scrollbar{display:none}
  .hist-thumb{flex:0 0 auto;width:80px;height:80px;border-radius:12px;overflow:hidden;
    border:2px solid transparent;opacity:.6;transition:.2s var(--ease);position:relative}
  .hist-thumb img{width:100%;height:100%;object-fit:cover}
  .hist-thumb:hover{opacity:1}
  .hist-thumb.active{opacity:1;border-color:var(--aqua)}
  .hist-thumb span{position:absolute;bottom:0;right:0;font-size:10px;font-weight:700;
    padding:1px 4px;background:rgba(6,16,26,.75);border-top-left-radius:6px;color:var(--text-muted)}
  .divider{height:1px;background:var(--hairline);margin:1px 0}
  .muted{color:var(--text-muted);font-size:12.5px}

  /* async-heal "generating alternate" pill */
  .heal-hint{display:inline-flex;align-items:center;gap:6px;flex:0 0 auto;
    font-size:11px;font-weight:600;color:var(--text-muted);
    padding:5px 10px;border-radius:999px;background:var(--surface);border:1px solid var(--hairline)}
  .heal-hint::before{content:"";width:7px;height:7px;border-radius:50%;
    background:var(--aqua);box-shadow:0 0 8px var(--aqua-soft);animation:heal-pulse 1.2s var(--ease) infinite}
  @keyframes heal-pulse{0%,100%{opacity:.35}50%{opacity:1}}

  /* enhance-in-progress card state (auto-load straight after a batch) */
  .proc-overlay{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:11px;
    background:linear-gradient(180deg,rgba(8,24,38,.45),rgba(6,16,26,.72));color:var(--text-muted);font-size:12.5px;font-weight:600;letter-spacing:.02em}
  .proc-overlay .spin{width:26px;height:26px;border-radius:50%;border:2.5px solid var(--hairline);border-top-color:var(--aqua);animation:spin .8s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
  .card.is-processing .card-body{opacity:.45;pointer-events:none;filter:saturate(.55)}

  /* animate row */
  .anim{display:flex;gap:9px}
  .anim input{flex:1;border-radius:var(--r-sm);padding:10px 12px;font-size:13px;
    background:var(--bg-2);border:1px solid var(--hairline);color:var(--text)}
  .anim input:focus{outline:none;border-color:var(--aqua)}
  .anim input::placeholder{color:var(--text-dim)}

  /* empty / loading */
  .empty{text-align:center;padding:80px 20px;color:var(--text-muted)}
  .empty h2{color:var(--text);font-size:21px;font-weight:600;margin-bottom:8px}
  .empty a{color:var(--aqua);font-weight:600}
  .skeleton{border-radius:var(--r-lg);background:linear-gradient(100deg,var(--surface) 30%,var(--surface-2) 50%,var(--surface) 70%);
    background-size:200% 100%;animation:sk 1.4s infinite linear;aspect-ratio:16/10}
  @keyframes sk{to{background-position:-200% 0}}

  /* lightbox */
  .lightbox{position:fixed;inset:0;z-index:60;background:rgba(3,9,15,.92);
    backdrop-filter:blur(8px);display:none;align-items:center;justify-content:center;padding:30px}
  .lightbox.open{display:flex}
  .lightbox img{max-width:94vw;max-height:90vh;border-radius:14px;box-shadow:var(--shadow-hi)}

  /* compare modal (pop-out) */
  .cmp-modal{position:fixed;inset:0;z-index:65;background:rgba(3,9,15,.93);
    backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
    display:none;align-items:center;justify-content:center;padding:24px}
  .cmp-modal.open{display:flex}
  .cmp-modal-inner{width:min(1080px,95vw);display:flex;flex-direction:column;gap:16px}
  .cmp-modal-head{display:flex;align-items:center;justify-content:space-between;font-size:15px;font-weight:600;color:var(--text-muted)}
  .cmp-close{width:36px;height:36px;border-radius:10px;background:var(--surface);border:1px solid var(--hairline);color:var(--text);font-size:15px}
  .cmp-close:hover{background:var(--surface-2)}
  .cmp-stage-wrap{position:relative;width:100%;aspect-ratio:3/2;max-height:72vh;border-radius:18px;overflow:hidden;background:var(--bg-2);box-shadow:var(--shadow-hi)}
  .cmp-modal-actions{display:flex;gap:12px}
  .cmp-modal-actions .btn{flex:1;padding:14px;font-size:14px}
  .cmp-modal-actions .btn.active{background:var(--aqua);color:#04222b;border-color:transparent}
  @media (max-width:560px){ .cmp-stage-wrap{aspect-ratio:1/1} .cmp-modal-actions{flex-direction:column} }

  /* inpaint modal (mask editor) */
  .ip-modal{position:fixed;inset:0;z-index:66;background:rgba(3,9,15,.93);
    backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
    display:none;align-items:center;justify-content:center;padding:24px}
  .ip-modal.open{display:flex}
  .ip-modal-inner{width:min(1100px,96vw);max-height:94vh;overflow:auto;display:flex;flex-direction:column;gap:14px}
  .ip-head{display:flex;align-items:center;justify-content:space-between;font-size:15px;font-weight:600;color:var(--text-muted);gap:12px}
  .ip-close{width:36px;height:36px;border-radius:10px;background:var(--surface);border:1px solid var(--hairline);color:var(--text);font-size:15px;flex:none}
  .ip-close:hover{background:var(--surface-2)}
  .ip-stage{position:relative;align-self:center;max-width:100%;line-height:0;border-radius:16px;overflow:hidden;background:var(--bg-2);box-shadow:var(--shadow-hi)}
  .ip-stage img{display:block;max-width:100%;max-height:64vh;width:auto;height:auto;user-select:none;-webkit-user-drag:none}
  .ip-stage canvas{position:absolute;inset:0;width:100%;height:100%;cursor:crosshair;touch-action:none}
  .ip-tools{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  .ip-tools .btn.active{background:var(--aqua);color:#04222b;border-color:transparent}
  .ip-size{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text-muted)}
  .ip-size input{width:140px}
  .ip-hint{font-size:12px;color:var(--text-dim);margin-left:auto}
  .ip-actions{display:flex;gap:12px}
  .ip-actions .btn{flex:1;padding:14px;font-size:14px}
  @media (max-width:560px){ .ip-hint{display:none} .ip-actions{flex-direction:column} }

  /* logo placement modal (reuses .ip-modal shell) */
  .lg-box{position:absolute;border:1.5px dashed rgba(0,194,199,.95);cursor:move;touch-action:none;box-sizing:border-box;display:none}
  .lg-box img{width:100%;height:100%;object-fit:contain;pointer-events:none;display:block}
  .lg-resize{position:absolute;right:-8px;bottom:-8px;width:17px;height:17px;border-radius:50%;background:var(--aqua);border:2px solid #06101A;cursor:nwse-resize}
  .lg-pickrow{display:flex;gap:10px;flex-wrap:wrap;align-items:center;min-height:54px}
  .lg-swatch{width:54px;height:54px;border-radius:10px;overflow:hidden;border:2px solid var(--hairline);cursor:pointer;
    background:repeating-conic-gradient(#16242f 0 25%,#0f1c26 0 50%) 50%/14px 14px;display:flex;align-items:center;justify-content:center}
  .lg-swatch.active{border-color:var(--aqua)}
  .lg-swatch img{max-width:80%;max-height:80%;object-fit:contain}
  .lg-pick-empty{font-size:13px;color:var(--text-muted)}

  /* materials library toolbar + inpaint material picker */
  .lib-toolbar{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:18px}
  .lib-field{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text-muted)}
  .lib-field select{background:var(--surface);color:var(--text);border:1px solid var(--hairline);
    border-radius:9px;padding:7px 10px;font-size:13px;cursor:pointer}
  .asset-cat{padding:0 11px 9px;font-size:11px;color:var(--text-muted);text-transform:capitalize;opacity:.8;margin-top:-4px}
  .ip-material{display:flex;flex-direction:column;gap:8px}
  .ip-material-label{font-size:13px;font-weight:600;color:var(--text)}
  .ip-mat-pick{display:flex;gap:10px;flex-wrap:wrap;align-items:center;min-height:54px}
  .ip-mat-swatch{position:relative;width:54px;height:54px;border-radius:10px;overflow:hidden;border:2px solid var(--hairline);
    cursor:pointer;background:var(--bg-2);display:flex;align-items:center;justify-content:center;flex-direction:column}
  .ip-mat-swatch img{width:100%;height:100%;object-fit:cover}
  .ip-mat-swatch.active{border-color:var(--aqua)}
  .ip-mat-none{width:54px;height:54px;border-radius:10px;border:2px solid var(--hairline);cursor:pointer;
    display:flex;align-items:center;justify-content:center;font-size:12px;color:var(--text-muted);background:var(--surface)}
  .ip-mat-none.active{border-color:var(--aqua);color:var(--text)}
  .ip-mat-empty{font-size:13px;color:var(--text-muted)}
  /* inpaint: two-column shell — material rail on the left, image + controls on the right */
  .ip-body{display:flex;gap:18px;align-items:flex-start}
  .ip-main{flex:1;min-width:0;display:flex;flex-direction:column;gap:14px}
  .ip-mat-rail{flex:0 0 auto;align-self:stretch;max-height:64vh;overflow-y:auto;overflow-x:hidden;padding-right:6px}
  .ip-mat-rail .ip-material-label{display:block;margin-bottom:10px}
  .ip-mat-rail .ip-mat-cats{margin-bottom:12px}
  .ip-mat-rail .ip-mat-pick{display:grid;grid-template-columns:repeat(3,54px);gap:8px;min-height:0}
  .ip-mat-rail::-webkit-scrollbar{width:8px}
  .ip-mat-rail::-webkit-scrollbar-thumb{background:var(--hairline-strong);border-radius:8px}
  .ip-guidance{font-size:12px;line-height:1.55;color:var(--text-muted);margin:0;
    padding:11px 13px;background:var(--surface);border:1px solid var(--hairline);border-radius:var(--r-sm)}
  /* inpaint: previous-results strip + trash */
  .ip-history-row{display:flex;align-items:center;gap:10px}
  .ip-history{display:flex;gap:8px;overflow-x:auto;flex:1;min-width:0;padding:2px 0;scrollbar-width:thin}
  .ip-history::-webkit-scrollbar{height:7px}
  .ip-history::-webkit-scrollbar-thumb{background:var(--hairline-strong);border-radius:7px}
  .ip-history .muted{align-self:center}
  .ip-hist-thumb{flex:0 0 auto;width:64px;height:64px;border-radius:10px;overflow:hidden;
    border:2px solid transparent;opacity:.7;transition:.15s var(--ease);position:relative;background:var(--bg-2)}
  .ip-hist-thumb img{width:100%;height:100%;object-fit:cover}
  .ip-hist-thumb:hover{opacity:1}
  .ip-hist-thumb.active{opacity:1;border-color:var(--aqua)}
  .ip-hist-thumb span{position:absolute;bottom:0;right:0;font-size:9px;font-weight:700;
    padding:1px 4px;background:rgba(6,16,26,.78);border-top-left-radius:5px;color:var(--text-muted)}
  #ipTrash{flex:0 0 auto}
  @media (max-width:760px){
    .ip-body{flex-direction:column}
    .ip-mat-rail{flex:0 0 auto;align-self:stretch;max-height:none;overflow:visible;padding-right:0;width:100%}
    .ip-mat-rail .ip-mat-pick{grid-template-columns:repeat(auto-fill,54px)}
  }
  /* material library category sections */
  .mat-section{margin-bottom:24px}
  .mat-section-head{font-size:12px;font-weight:700;color:var(--text);text-transform:uppercase;
    letter-spacing:.05em;margin:0 0 12px;display:flex;align-items:baseline;gap:8px}
  .mat-section-head .count{font-weight:500;color:var(--text-dim);font-size:11px;letter-spacing:0;text-transform:none}
  .mat-upload-row{margin-bottom:22px;max-width:170px}
  /* inpaint picker category chips */
  .ip-mat-cats{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:2px}
  .ip-mat-cat{padding:6px 12px;border-radius:999px;font-size:12.5px;cursor:pointer;background:var(--surface);
    color:var(--text-muted);border:1px solid var(--hairline);transition:.15s var(--ease)}
  .ip-mat-cat:hover{border-color:var(--hairline-strong);color:var(--text)}
  .ip-mat-cat.active{background:var(--aqua);color:#04201f;border-color:var(--aqua);font-weight:600}
  .ip-surface{display:flex;flex-direction:column;gap:8px}
  .ip-seg{display:inline-flex;gap:4px;background:var(--bg-2);border:1px solid var(--hairline);border-radius:10px;padding:4px;width:fit-content}
  .ip-seg-btn{background:transparent;border:0;color:var(--text-muted);font-size:13px;padding:7px 14px;border-radius:7px;cursor:pointer}
  .ip-seg-btn.active{background:var(--surface);color:var(--text);box-shadow:0 1px 2px rgba(0,0,0,.2)}
  /* §8E smart-select chips */
  .ip-chips{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:8px}
  .ip-chips[hidden]{display:none}
  .ip-chip{padding:7px 13px;border-radius:999px;font-size:13px;cursor:pointer;
    background:var(--surface);color:var(--text);border:1px solid var(--hairline);transition:.15s var(--ease)}
  .ip-chip:hover{border-color:var(--hairline-strong)}
  .ip-chip.active{background:var(--aqua);color:#04201f;border-color:var(--aqua);font-weight:600}
  .ip-chip.disabled{opacity:.4;cursor:not-allowed;pointer-events:none}
  .ip-chip-note{font-size:12px;color:var(--text-muted)}
  .refine-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
  .refine-actions .btn.primary{margin-left:auto}
  .ref-chip{position:relative;width:40px;height:40px;border-radius:8px;overflow:hidden;border:1px solid var(--hairline);flex:0 0 auto}
  .ref-chip img{width:100%;height:100%;object-fit:cover;display:block}
  .ref-x{position:absolute;top:-6px;right:-6px;width:18px;height:18px;border-radius:50%;border:0;background:#000;color:#fff;font-size:12px;line-height:1;cursor:pointer;padding:0}

  /* toast */
  .toast{position:fixed;left:50%;bottom:30px;transform:translateX(-50%) translateY(20px);
    z-index:70;padding:12px 20px;border-radius:14px;font-size:14px;font-weight:600;
    background:rgba(10,24,38,.92);backdrop-filter:blur(14px);border:1px solid var(--hairline-strong);
    box-shadow:var(--shadow-hi);opacity:0;pointer-events:none;transition:.3s var(--ease)}
  .toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
  .toast.err{border-color:rgba(224,98,90,.5)}

  /* out-of-credits modal */
  .credit-modal{position:fixed;inset:0;z-index:75;background:rgba(3,9,15,.93);
    backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
    display:none;align-items:center;justify-content:center;padding:24px}
  .credit-modal.open{display:flex}
  .credit-box{width:min(420px,92vw);background:var(--bg-2);border:1px solid var(--hairline-strong);
    border-radius:18px;box-shadow:var(--shadow-hi);padding:28px 26px;text-align:center}
  .credit-box h3{font-size:19px;font-weight:700;color:var(--text);margin:0 0 8px}
  .credit-box p{font-size:13px;color:var(--text-muted);line-height:1.55;margin:0 0 22px}
  .credit-box .btn-row{flex-direction:column;gap:10px}
  .credit-box .btn{width:100%;padding:13px}

  .hidden{display:none!important}

  @media (prefers-reduced-motion:reduce){
    *{animation-duration:.001ms!important;transition-duration:.001ms!important}
  }
  @media (max-width:520px){
    .card-grid,.album-grid{grid-template-columns:1fr}
    .page-head{flex-direction:column;align-items:flex-start;gap:4px}
  }
</style>
</head>
<body>
  <header class="topbar">
    <a class="brand" href="/"><span class="dot"></span>Studio<small>&nbsp;/ Albums</small></a>
    <span class="spacer"></span>
    <span class="credits">⚡ <b id="creditCount">—</b> credits</span>
    <span class="trial-badge" id="trialBadge" hidden></span>
    <a class="ghost-btn" href="/">＋ New design</a>
    <button class="ghost-btn" id="libraryBtn">Library</button>
    <button class="ghost-btn" id="trashBtn">🗑 Trash</button>
    <button class="ghost-btn" id="signOut">Sign out</button>
  </header>

  <main class="wrap">
    <!-- Albums view -->
    <section id="albumsView">
      <div class="low-credit-bar" id="lowCreditBar" hidden>
        <span id="lowCreditText"></span>
        <button class="btn primary" onclick="goBuyCredits()">Buy credits</button>
        <button class="lc-x" id="lowCreditX" aria-label="Dismiss">✕</button>
      </div>
      <div class="lib-banner" id="libBanner" hidden>
        <div class="lib-banner-txt"><b>Build your brand Library.</b> Upload your <b>logos</b> and <b>material swatches</b> once — open the <b>Library</b> chip up top to reuse them across every album.</div>
        <div class="lib-banner-actions">
          <button class="btn primary" id="libBannerOpen">Open Library</button>
          <button class="lib-banner-x" id="libBannerX" aria-label="Dismiss tip">✕</button>
        </div>
      </div>
      <div class="page-head">
        <div>
          <h1>Your Albums</h1>
          <p>Every enhancement batch, saved with its full edit history.</p>
        </div>
        <label class="lib-field album-sort" id="albumSortWrap" hidden>Sort
          <select id="albumSort">
            <option value="newest">Newest first</option>
            <option value="oldest">Oldest first</option>
            <option value="az">Name A–Z</option>
            <option value="za">Name Z–A</option>
          </select>
        </label>
      </div>
      <div id="albumGrid" class="album-grid">
        <div class="skeleton"></div><div class="skeleton"></div><div class="skeleton"></div>
      </div>
    </section>

    <!-- Album detail view -->
    <section id="albumView" class="hidden">
      <a class="back" id="backBtn">‹ All albums</a>
      <div class="page-head">
        <div>
          <h1 id="albumTitle">Album</h1>
          <p id="albumMeta"></p>
        </div>
        <button class="ghost-btn" id="renameBtn">Rename</button>
      </div>
      <div id="cardGrid" class="card-grid"></div>
    </section>

    <!-- Trash view -->
    <section id="trashView" class="hidden">
      <a class="back" id="trashBack">‹ All albums</a>
      <div class="page-head">
        <div>
          <h1>Trash</h1>
          <p>Deleted designs are kept for 30 days, then permanently removed.</p>
        </div>
      </div>
      <div id="trashGrid" class="album-grid"></div>
    </section>

    <!-- Library view (reusable brand assets) -->
    <section id="libraryView" class="hidden">
      <a class="back" id="libBack">‹ All albums</a>
      <div class="page-head">
        <div>
          <h1>Library</h1>
          <p>Reusable brand assets — applied across your albums.</p>
        </div>
      </div>
      <div class="lib-tabs">
        <button class="lib-tab active" data-lib="logos">Logos</button>
        <button class="lib-tab" data-lib="materials">Materials</button>
      </div>
      <div id="libLogos" class="lib-panel">
        <div id="logoGrid" class="asset-grid"></div>
      </div>
      <div id="libMaterials" class="lib-panel hidden">
        <div class="lib-toolbar">
          <label class="lib-field">New uploads are
            <select id="matCategory">
              <option value="paver">Paver</option>
              <option value="tile">Tile</option>
              <option value="decking">Decking</option>
              <option value="stone">Stone</option>
              <option value="gravel">Gravel</option>
              <option value="other">Other</option>
            </select>
          </label>
          <span class="muted">Use edge-to-edge texture swatches for the cleanest swaps.</span>
        </div>
        <div id="materialGrid"></div>
      </div>
    </section>
  </main>

  <div class="lightbox" id="lightbox"><img id="lightboxImg" alt=""></div>

  <div class="cmp-modal" id="cmpModal">
    <div class="cmp-modal-inner">
      <div class="cmp-modal-head">
        <span>Compare &amp; choose — drag the divider</span>
        <button class="cmp-close" id="cmpClose" aria-label="Close">✕</button>
      </div>
      <div class="cmp-stage-wrap"><div class="compare" id="cmpStage"></div></div>
      <div class="cmp-modal-actions">
        <button class="btn wide" id="cmpUseEnhanced">Use Enhanced</button>
        <button class="btn wide" id="cmpUseHealed">Use Healed</button>
      </div>
    </div>
  </div>
  <div class="toast" id="toast"></div>

  <div class="credit-modal" id="creditModal">
    <div class="credit-box">
      <h3 id="creditTitle">You're out of credits</h3>
      <p id="creditBody">This action needs credits you don't have right now. Top up to keep refining, inpainting, upscaling, and animating.</p>
      <div class="btn-row">
        <button class="btn primary" onclick="goBuyCredits()">Buy credits</button>
        <button class="btn" onclick="closeCreditModal()">Maybe later</button>
      </div>
    </div>
  </div>

  <div class="ip-modal" id="ipModal">
    <div class="ip-modal-inner">
      <div class="ip-head">
        <span>Inpaint — paint a specific area to add an object or swap a material in that exact spot</span>
        <button class="ip-close" id="ipClose" aria-label="Close">✕</button>
      </div>
      <div class="ip-body">
        <aside class="ip-mat-rail">
          <div class="ip-material">
            <span class="ip-material-label">Swap material <span class="muted">(optional)</span></span>
            <div id="ipMatCats" class="ip-mat-cats"></div>
            <div id="ipMatPick" class="ip-mat-pick"></div>
          </div>
        </aside>
        <div class="ip-main">
          <div class="ip-stage" id="ipStage">
            <img id="ipImg" alt="">
            <canvas id="ipView"></canvas>
          </div>
          <div class="ip-history-row">
            <div class="ip-history" id="ipHistory"></div>
            <button class="btn icon" id="ipTrash" title="Remove the current version from history">🗑</button>
          </div>
          <div class="ip-tools">
            <button class="btn active" id="ipBrush" data-mode="brush">🖌 Brush</button>
            <button class="btn" id="ipEraser" data-mode="eraser">🩹 Eraser</button>
            <button class="btn" id="ipSmart" data-mode="smart">🪄 Smart select</button>
            <label class="ip-size">Size <input type="range" id="ipSize" min="6" max="140" value="40"></label>
            <button class="btn" id="ipClear">Clear mask</button>
            <span class="ip-hint">Only the painted area changes — everything else is preserved exactly.</span>
          </div>
          <div class="ip-chips" id="ipChips" hidden></div>
          <div class="ip-surface">
            <span class="ip-material-label">Surface</span>
            <div class="ip-seg" id="ipSurface">
              <button type="button" class="ip-seg-btn active" data-surface="auto">Auto</button>
              <button type="button" class="ip-seg-btn" data-surface="floor">Floor / ground</button>
              <button type="button" class="ip-seg-btn" data-surface="wall">Wall / vertical</button>
            </div>
          </div>
          <p class="ip-guidance">A little bleed-over into the painted area is fine — results can be unpredictable. If a texture comes out too large, or an object lands in the wrong spot or plane, you can correct its size or position afterward with <b>Global refine</b> using prompt commands. Swapping waterline tile or decking is often better done with <b>Global refine</b> using a reference swatch and a detailed prompt.</p>
          <textarea id="ipPrompt" class="refine-in" rows="2" placeholder="Describe the fix for the painted area — e.g. replace with smooth travertine pavers, matching the surrounding shadows"></textarea>
          <div class="ip-actions">
            <button class="btn" id="ipCancel">Cancel</button>
            <button class="btn primary" id="ipGo">Generate inpaint</button>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="ip-modal" id="refModal">
    <div class="ip-modal-inner">
      <div class="ip-head">
        <span>Pick a reference image — your prompt decides what happens with it</span>
        <button class="ip-close" id="refClose" aria-label="Close">✕</button>
      </div>
      <p class="muted" style="margin:0 0 14px">Attach a library image, then write the instruction, e.g. "change all the stucco to this material" or "put this in the pool". No masking needed.</p>
      <div id="refGrid" class="asset-grid"></div>
      <div class="ip-actions">
        <button class="btn" id="refCancel">Cancel</button>
      </div>
    </div>
  </div>

  <div class="ip-modal" id="lgModal">
    <div class="ip-modal-inner">
      <div class="ip-head">
        <span>Logo — drag to position, drag the corner to resize</span>
        <button class="ip-close" id="lgClose" aria-label="Close">✕</button>
      </div>
      <p class="tool-hint" style="margin:0 0 10px">
        The logo is <b>not baked into your image</b>. You are saving a position, size and
        opacity — the logo is added to the file automatically when you download it, and it
        always lands on whichever version you are currently viewing in the history.
        Your saved results stay clean and unbranded, so you can keep editing at any time.
        <span class="eg">Apply to this image = just this one · Set as album default = every image in the album that doesn't have its own · Remove logo = clears both.</span>
      </p>
      <div class="ip-stage" id="lgStage">
        <img id="lgImg" alt="">
        <div class="lg-box" id="lgBox"><img id="lgBoxImg" alt=""><span class="lg-resize" id="lgResize"></span></div>
      </div>
      <div class="lg-pickrow" id="lgPick"></div>
      <div class="ip-tools">
        <label class="ip-size">Opacity <input type="range" id="lgOpacity" min="10" max="100" value="100"></label>
        <span class="ip-hint">Transparent PNG works best. Applied on download — nothing is written to your saved image.</span>
      </div>
      <div class="ip-actions">
        <button class="btn" id="lgRemove">Remove logo</button>
        <button class="btn" id="lgApplyOne">Apply to this image</button>
        <button class="btn primary" id="lgApplyAll">Set as album default</button>
      </div>
    </div>
  </div>

<script>
"use strict";
const TOKEN = localStorage.getItem('authToken');
if (!TOKEN) location.replace('/');

const $ = (s,r=document)=>r.querySelector(s);
const el=(tag,cls)=>{const e=document.createElement(tag);if(cls)e.className=cls;return e;};
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

let toastTimer;
function toast(msg,isErr){
  const t=$('#toast'); t.textContent=msg; t.classList.toggle('err',!!isErr); t.classList.add('show');
  clearTimeout(toastTimer); toastTimer=setTimeout(()=>t.classList.remove('show'),3200);
}

function openCreditModal(msg){
  const m=$('#creditModal'); if(!m) return;
  const h=$('#creditTitle'), p=$('#creditBody');
  if(h&&p){
    if(msg){ h.textContent='Upgrade to unlock this'; p.textContent=msg; }
    else{ h.textContent="You're out of credits"; p.textContent="This action needs credits you don't have right now. Top up to keep refining, inpainting, upscaling, and animating."; }
  }
  m.classList.add('open');
}
function closeCreditModal(){ const m=$('#creditModal'); if(m) m.classList.remove('open'); }
function goBuyCredits(){ location.href='/?buy=1'; }

async function api(path,opts){
  opts=opts||{};
  const headers=Object.assign({'Authorization':'Bearer '+TOKEN},opts.headers||{});
  if(opts.body && !headers['Content-Type']) headers['Content-Type']='application/json';
  const res=await fetch(path,{method:opts.method||'GET',headers,body:opts.body?JSON.stringify(opts.body):undefined});
  if(res.status===401){location.replace('/');throw new Error('unauthorized');}
  let data=null; try{data=await res.json();}catch(e){}
  if(res.status===402){
    // Two different 402s: genuinely out of credits, vs a premium action that the free
    // trial doesn't include. Showing "You're out of credits" for the latter is wrong.
    if(data&&data.code==='trial_excluded') openCreditModal(data.error);
    else openCreditModal();
    const err=new Error((data&&data.error)||'Insufficient credits'); err.code='INSUFFICIENT_CREDITS'; throw err;
  }
  if(!res.ok) throw new Error((data&&data.error)||('Request failed ('+res.status+')'));
  return data;
}

/* ── State ── */
let ALBUMS=[];
let current={jobId:null,projectId:null,name:'',images:[]};
const imgState={}; // projectImageId -> image object

/* ── Credits ── */
/* Trial users get a badge with days remaining, plus a one-per-session nudge once the
   balance runs low. The nudge is deliberately non-blocking — the blocking modal is
   reserved for an action that actually failed. */
let CREDIT_STATE={balance:null,trialOnly:false,expiresAt:null,low:10};
async function loadCredits(){
  try{
    const d=await api('/api/credits');
    const bal=(d.balance!=null?d.balance:(d.credits!=null?d.credits:null));
    CREDIT_STATE={balance:bal,trialOnly:!!d.trial_only,expiresAt:d.trial_expires_at||null,low:(d.low_threshold!=null?d.low_threshold:10)};
    $('#creditCount').textContent=(bal!=null?bal:'—');
    renderTrialBadge();
    maybeNudgeLowCredits();
  }catch(e){}
}
function renderTrialBadge(){
  const host=$('#trialBadge'); if(!host) return;
  if(!CREDIT_STATE.trialOnly){ host.hidden=true; host.textContent=''; return; }
  let txt='Free trial';
  if(CREDIT_STATE.expiresAt){
    const days=Math.ceil((new Date(CREDIT_STATE.expiresAt)-new Date())/86400000);
    txt = days>1 ? ('Free trial · '+days+' days left') : (days===1?'Free trial · last day':'Trial expired');
  }
  host.textContent=txt; host.hidden=false;
  host.title='Trial downloads include a small StudioFinish mark. Buying credits removes it.';
}
function maybeNudgeLowCredits(){
  const b=CREDIT_STATE.balance;
  if(b==null||b>CREDIT_STATE.low||b<0) return;
  if(sessionStorage.getItem('lowCreditNudged')) return;
  sessionStorage.setItem('lowCreditNudged','1');
  const bar=$('#lowCreditBar'); if(!bar) return;
  $('#lowCreditText').textContent = b===0
    ? "You're out of credits. Top up to keep editing."
    : ('Only '+b+' credit'+(b===1?'':'s')+' left'+(CREDIT_STATE.trialOnly?' in your free trial':'')+'.');
  bar.hidden=false;
}

/* ── Albums ── */
let albumSort = localStorage.getItem('albumSort') || 'newest';
function sortAlbums(list){
  const a=list.slice();
  const byName=(x,y)=>String(x.name||'').localeCompare(String(y.name||''),undefined,{sensitivity:'base',numeric:true});
  const byDate=(x,y)=>(new Date(x.createdAt||0))-(new Date(y.createdAt||0));
  switch(albumSort){
    case 'oldest': a.sort(byDate); break;
    case 'az':     a.sort(byName); break;
    case 'za':     a.sort((x,y)=>byName(y,x)); break;
    case 'newest':
    default:       a.sort((x,y)=>byDate(y,x)); break;
  }
  return a;
}
function renderAlbums(){
  const grid=$('#albumGrid'); grid.innerHTML='';
  sortAlbums(ALBUMS).forEach(a=>grid.appendChild(albumTile(a)));
}
async function loadAlbums(){
  const grid=$('#albumGrid'); const sortWrap=$('#albumSortWrap');
  try{
    const d=await api('/api/albums');
    ALBUMS=d.albums||[];
    if(!ALBUMS.length){
      if(sortWrap) sortWrap.hidden=true;
      grid.innerHTML='';
      const e=el('div','empty');
      e.innerHTML='<h2>No albums yet</h2><p>Enhance your first design and it’ll appear here.</p><p style="margin-top:14px"><a href="/">Start a new design ›</a></p>';
      grid.appendChild(e); return;
    }
    if(sortWrap) sortWrap.hidden=false;
    renderAlbums();
  }catch(e){ if(sortWrap) sortWrap.hidden=true; grid.innerHTML=''; const x=el('div','empty'); x.innerHTML='<h2>Couldn’t load albums</h2><p>'+esc(e.message)+'</p>'; grid.appendChild(x); }
}

function fmtDate(s){ if(!s)return''; try{return new Date(s).toLocaleDateString(undefined,{month:'short',day:'numeric',year:'numeric'});}catch(e){return'';} }

function albumTile(a){
  const t=el('div','tile');
  const done=(a.status==='completed');
  t.innerHTML=
    '<div class="status-dot '+(done?'done':'proc')+'"><i></i>'+(done?'Ready':'Processing')+'</div>'+
    (a.coverUrl
      ? '<div class="tile-cover"><img loading="lazy" src="'+esc(a.coverUrl)+'" alt=""></div>'
      : '<div class="tile-cover empty">No preview</div>')+
    '<div class="tile-scrim"></div>'+
    '<div class="tile-body"><div class="meta">'+
      '<h3>'+esc(a.name)+'</h3>'+
      '<div class="sub">'+a.imageCount+' image'+(a.imageCount===1?'':'s')+' · '+fmtDate(a.createdAt)+'</div>'+
    '</div>'+
    '<button class="tile-rename" title="Rename" aria-label="Rename album">✎</button></div>';
  t.querySelector('.tile-rename').addEventListener('click',ev=>{ev.stopPropagation();renameAlbum(a);});
  t.addEventListener('click',()=>openAlbum(a));
  return t;
}

async function renameAlbum(a){
  const name=prompt('Rename album',a.name);
  if(name==null||!name.trim()||name.trim()===a.name) return;
  try{
    await api('/api/album/'+a.albumId,{method:'PATCH',body:{name:name.trim()}});
    a.name=name.trim();
    if(current.albumId===a.albumId){ current.name=a.name; $('#albumTitle').textContent=a.name; }
    loadAlbums(); toast('Album renamed');
  }catch(e){ toast(e.message,true); }
}

/* ── Album detail ── */
async function openAlbum(a){
  if(albumPollTimer){ clearTimeout(albumPollTimer); albumPollTimer=null; }
  current={albumId:a.albumId,name:a.name,images:[]};
  $('#albumsView').classList.add('hidden');
  $('#trashView').classList.add('hidden');
  $('#libraryView').classList.add('hidden');
  $('#albumView').classList.remove('hidden');
  $('#albumTitle').textContent=a.name||'Album';
  $('#albumMeta').textContent='Loading…';
  $('#cardGrid').innerHTML='<div class="skeleton" style="aspect-ratio:3/2"></div><div class="skeleton" style="aspect-ratio:3/2"></div>';
  window.scrollTo({top:0,behavior:'smooth'});
  try{
    const d=await api('/api/album/'+encodeURIComponent(a.albumId));
    current.images=d.images||[];
    current.logoDefault=d.album?d.album.logoDefault:null;
    if(d.album&&d.album.name){ current.name=d.album.name; $('#albumTitle').textContent=d.album.name; }
    $('#albumMeta').textContent=(d.album?d.album.totalItems+' images':current.images.length+' images');
    const grid=$('#cardGrid'); grid.innerHTML='';
    let anyProcessing=false;
    current.images.forEach(img=>{
      imgState[img.projectImageId]=img;
      const c=buildCard(img); grid.appendChild(c); maybeStartHeal(c,img);
      if(!(img.status==='completed' && (img.current_url||img.enhanced_url))) anyProcessing=true;
    });
    if(!current.images.length){ grid.innerHTML='<div class="empty"><h2>No images</h2></div>'; }
    if(anyProcessing) pollAlbumProgress();
  }catch(e){ $('#cardGrid').innerHTML='<div class="empty"><h2>Couldn’t load album</h2><p>'+esc(e.message)+'</p></div>'; }
}
$('#backBtn').addEventListener('click',()=>{
  if(albumPollTimer){ clearTimeout(albumPollTimer); albumPollTimer=null; }
  $('#albumView').classList.add('hidden'); $('#albumsView').classList.remove('hidden');
  window.scrollTo({top:0,behavior:'smooth'}); loadAlbums();
});
$('#renameBtn').addEventListener('click',()=>{ const a=ALBUMS.find(x=>x.albumId===current.albumId); if(a) renameAlbum(a); });

/* ── Image card ── */
function activeIdx(img){
  if(!img.versions||!img.versions.length) return -1;
  return img.versions.findIndex(v=>v.id===img.active_version_id);
}
function buildCard(img){
  const card=el('div','card'+(( img.status==='completed' && (img.current_url||img.enhanced_url) )?'':' is-processing'));
  card.dataset.id=img.projectImageId;
  const cur=img.current_url||img.enhanced_url||'';
  const idx=parseInt(img.image_index,10); const num=isNaN(idx)?'':(idx+1);
  const hasHealed=!!img.healed_url, hasEnh=!!img.enhanced_url;
  const processing=!(img.status==='completed' && (img.current_url||img.enhanced_url));
  const rb=badgeFor(img);
  const badge=(rb==='4K')?'<span class="badge k4">4K</span>':'<span class="badge">'+esc(rb)+'</span>';
  const stageExtra=processing
    ? '<div class="proc-overlay" data-proc><span class="spin"></span><span>Enhancing…</span></div>'
    : badge;

  card.innerHTML=
    '<div class="stage" data-stage>'+
      '<img data-main src="'+esc(cur)+'" alt="Design '+num+'">'+
      stageExtra+
      '<button class="expand" title="View full" aria-label="View full size">⤢</button>'+
    '</div>'+
    '<div class="card-body">'+
      '<div class="card-title-row"><h4>Design '+num+'</h4>'+
        '<button class="btn icon" data-delete title="Move to Trash">🗑</button></div>'+
      '<div class="divider"></div>'+
      '<div class="tool-group">'+
        '<p class="tool-hint"><b>Global refine</b> — for big, scene-wide changes: decking, background, time of day, pebble interior color, a property-line wall or hedges. A reference swatch is optional.'+
          '<span class="eg">e.g. “Change the decking to gray tumbled limestone pavers. Make it a night scene with a starry sky and full moon, and add a soft glow to the pool water. Add a full-length 15-ft leafy ficus hedge wall behind the foreground shrubs but in front of the background mountains.”</span></p>'+
        '<div class="tool">'+
          '<textarea class="refine-in" rows="2" placeholder="Describe a change — e.g. warmer lighting, change all the stucco to this material, put this in the pool"></textarea>'+
          '<div class="refine-actions">'+
            '<div class="ref-chip" data-ref-chip hidden><img data-ref-thumb alt=""><button class="ref-x" data-ref-clear title="Remove reference">×</button></div>'+
            '<button class="btn" data-ref-add title="Attach a library swatch to reference in your prompt">🖼 Reference</button>'+
            '<button class="btn primary" data-refine>Refine</button>'+
          '</div>'+
        '</div>'+
      '</div>'+
      '<div class="history" data-history></div>'+
      '<div class="divider"></div>'+
      '<div class="btn-row pair">'+
        '<button class="btn wide" data-upscale>⬆ Upscale to 4K</button>'+
        '<button class="btn wide" data-download>⬇ Download</button>'+
      '</div>'+
      '<div class="tool-group">'+
        '<p class="tool-hint"><b>Inpaint</b> — paint over one specific spot to add an object or swap a material in just that location.</p>'+
        '<button class="btn wide" data-inpaint>✎ Inpaint a specific area</button>'+
      '</div>'+
      '<div class="tool-group">'+
        '<p class="tool-hint"><b>Logo</b> — position one of your saved brand logos or watermarks. It is not baked into the image: it stays a saved placement and is added automatically when you download, always over whichever version you are viewing.</p>'+
        '<button class="btn wide" data-logo>🏷 Add logo / watermark</button>'+
      '</div>'+
      '<div class="btn-row share-row">'+
        '<button class="btn" data-pin title="Share to Pinterest">📌 Pinterest</button>'+
        '<button class="btn" data-fb title="Share to Facebook">f Facebook</button>'+
      '</div>'+
      '<div class="anim">'+
        '<input type="email" placeholder="Email for 5s animation…">'+
        '<button class="btn" data-animate>🎬 Animate</button>'+
      '</div>'+
    '</div>';

  // wire
  const stage=card.querySelector('[data-stage]');
  card.querySelector('.expand').addEventListener('click',()=>openLightbox(card.querySelector('[data-main]').src));
  card.querySelector('[data-delete]').addEventListener('click',()=>deleteImage(card,img));
  card.querySelector('[data-refine]').addEventListener('click',e=>refine(card,img,e.currentTarget));
  card.querySelector('[data-ref-add]').addEventListener('click',()=>openRefModal(card));
  card.querySelector('[data-ref-clear]').addEventListener('click',()=>clearRef(card));
  card.querySelector('[data-upscale]').addEventListener('click',e=>upscale(card,img,e.currentTarget));
  card.querySelector('[data-inpaint]').addEventListener('click',()=>openInpaintModal(card,img));
  card.querySelector('[data-logo]').addEventListener('click',()=>openLogoModal(card,img));
  card.querySelector('[data-download]').addEventListener('click',()=>download(img.projectImageId,'design-'+num+'.jpg',card.querySelector('[data-main]').src));
  card.querySelector('[data-pin]').addEventListener('click',()=>window.open('https://pinterest.com/pin/create/button/?media='+encodeURIComponent(card.querySelector('[data-main]').src),'_blank'));
  card.querySelector('[data-fb]').addEventListener('click',()=>window.open('https://www.facebook.com/sharer/sharer.php?u='+encodeURIComponent(card.querySelector('[data-main]').src),'_blank'));
  card.querySelector('[data-animate]').addEventListener('click',e=>animate(card,img,e.currentTarget));

  renderHistory(card,img);
  updateCompareState(card);
  return card;
}

/* ── Compare availability: enabled only when an enhanced/healed pair exists AND
   the user has not yet committed to a version. The append-only `versions` chain
   is the signal — any pick, refine, or upscale appends a version, which locks
   the comparison (you've chosen; further work happens on the version history). */
function updateCompareState(card){
  const img=imgState[card.dataset.id]; if(!img) return;
  const btn=card.querySelector('[data-compare]'); if(!btn) return;
  const hasPair=!!img.enhanced_url && !!img.healed_url;
  const chosen=!!(img.versions && img.versions.length);
  btn.disabled=(!hasPair || chosen);
  btn.title=!hasPair ? 'No alternate to compare'
          : chosen ? 'Choice locked in — your edit history is now driving this image'
          : 'Compare enhanced vs healed';
}

/* ── Compare (pop-out modal) ── */
let cmpCurrent = { card:null, img:null };
function openCompareModal(card,img){
  // Always work off the freshest copy (handlers close over the original object).
  const latest = imgState[img.projectImageId] || img;
  if(!latest.enhanced_url || !latest.healed_url) return;
  if(latest.versions && latest.versions.length) return; // choice locked — nothing to compare
  cmpCurrent = { card:card, img:latest };
  const stage = $('#cmpStage');
  stage.style.setProperty('--pct','50%');
  // clip-path reveals the TOP image on the LEFT, BASE shows on the RIGHT.
  // So: top = Enhanced (left, matches left tag), base = Healed (right, matches right tag).
  stage.innerHTML =
    '<img class="base" src="'+esc(latest.healed_url)+'" alt="Healed result">'+
    '<img class="top" src="'+esc(latest.enhanced_url)+'" alt="Enhanced result">'+
    '<div class="cmp-divider"></div><div class="cmp-handle">⇋</div>'+
    '<span class="cmp-tag l">Enhanced</span><span class="cmp-tag r">Healed</span>'+
    '<input class="cmp-range" type="range" min="0" max="100" value="50" aria-label="Drag to compare enhanced and healed">';
  const range = stage.querySelector('.cmp-range');
  range.addEventListener('input',()=>stage.style.setProperty('--pct',range.value+'%'));
  const idx = activeIdx(latest);
  const activeSource = (idx>=0 && latest.versions[idx]) ? latest.versions[idx].source : null;
  $('#cmpUseEnhanced').classList.toggle('active', activeSource==='enhanced');
  $('#cmpUseHealed').classList.toggle('active', activeSource==='healed');
  $('#cmpModal').classList.add('open');
}
function closeCompareModal(){ $('#cmpModal').classList.remove('open'); $('#cmpStage').innerHTML=''; cmpCurrent={card:null,img:null}; }
$('#cmpClose').addEventListener('click', closeCompareModal);
$('#cmpModal').addEventListener('click', e=>{ if(e.target.id==='cmpModal') closeCompareModal(); });
document.addEventListener('keydown', e=>{ if(e.key==='Escape' && $('#cmpModal').classList.contains('open')) closeCompareModal(); });
$('#cmpUseEnhanced').addEventListener('click', async ()=>{ if(cmpCurrent.card){ await pick(cmpCurrent.card,cmpCurrent.img,'enhanced'); closeCompareModal(); } });
$('#cmpUseHealed').addEventListener('click', async ()=>{ if(cmpCurrent.card){ await pick(cmpCurrent.card,cmpCurrent.img,'healed'); closeCompareModal(); } });

// retained as a safe no-op (in-card pick row was replaced by the modal)
function highlightPick(card,img){
  const idx=activeIdx(img);
  const activeSource=(idx>=0&&img.versions[idx])?img.versions[idx].source:null;
  card.querySelectorAll('[data-pick] button').forEach(b=>b.classList.toggle('active',b.dataset.choice===activeSource));
}

async function pick(card,img,choice){
  try{
    const d=await api('/api/select-image',{method:'POST',body:{projectImageId:img.projectImageId,choice}});
    img.current_url=d.current_url; img.active_version_id=d.active_version_id;
    await refreshImage(img.projectImageId);
    toast('Saved the '+choice+' version');
  }catch(e){ toast(e.message,true); }
}

/* ── History strip + undo/redo ── */
function renderHistory(card,img){
  const h=card.querySelector('[data-history]'); h.innerHTML='';
  const idx=activeIdx(img);
  const nav=el('div','hist-nav');
  const undo=el('button','btn icon'); undo.textContent='↩'; undo.title='Undo';
  const redo=el('button','btn icon'); redo.textContent='↪'; redo.title='Redo';
  undo.disabled=!(idx>0); redo.disabled=!(img.versions&&idx>=0&&idx<img.versions.length-1);
  undo.addEventListener('click',()=>moveVersion(card,img,'undo'));
  redo.addEventListener('click',()=>moveVersion(card,img,'redo'));
  const del=el('button','btn icon'); del.textContent='🗑'; del.title='Remove this version from history';
  del.disabled=!(img.versions&&img.versions.length&&idx>=0);
  del.addEventListener('click',()=>deleteVersion(card,img));
  nav.appendChild(undo); nav.appendChild(redo); nav.appendChild(del); h.appendChild(nav);

  const strip=el('div','hist-strip');
  // mouse wheel: translate vertical wheel into horizontal scroll (native only does this for trackpad deltaX)
  strip.addEventListener('wheel',(e)=>{
    if(strip.scrollWidth<=strip.clientWidth) return;        // nothing to scroll
    const dy=e.deltaY; if(!dy) return;                       // horizontal wheels scroll natively
    const atStart=strip.scrollLeft<=0, atEnd=strip.scrollLeft+strip.clientWidth>=strip.scrollWidth-1;
    if((dy<0&&atStart)||(dy>0&&atEnd)) return;               // at an edge → let the page scroll
    strip.scrollLeft+=dy; e.preventDefault();
  },{passive:false});
  if(img.versions&&img.versions.length){
    img.versions.forEach(v=>{
      const th=el('button','hist-thumb'+(v.id===img.active_version_id?' active':''));
      th.title=(v.source||'')+(v.prompt?' — '+v.prompt:'');
      th.innerHTML='<img src="'+esc(v.url)+'" alt=""><span>v'+v.seq+'</span>';
      th.addEventListener('click',()=>setVersion(card,img,v.id));
      strip.appendChild(th);
    });
  }else{
    const note=el('span','muted'); note.textContent='No saved versions yet — compare and pick, or refine to start the history.';
    strip.appendChild(note);
  }
  h.appendChild(strip);
  // keep the active thumbnail in view (the strip scrolls horizontally within the card)
  const act=strip.querySelector('.hist-thumb.active');
  if(act){ requestAnimationFrame(()=>{ strip.scrollLeft = act.offsetLeft - (strip.clientWidth/2) + (act.clientWidth/2); }); }
}
async function deleteVersion(card,img){
  const latest=imgState[img.projectImageId]||img;
  const vid=latest.active_version_id;
  if(!vid){ toast('Pick a version to remove first',true); return; }
  if(!confirm('Remove this version from the history? This cannot be undone.')) return;
  try{
    await api('/api/version/delete',{method:'POST',body:{projectImageId:img.projectImageId,versionId:vid}});
    await refreshImage(img.projectImageId);
    toast('Version removed');
  }catch(e){ toast(e.message,true); }
}
/* Resolution badge reflects the ACTIVE version, not the image row. Only an upscale
   produces 4K; enhanced / healed / refine / inpaint are all 1K. This fixes the badge
   reading 4K while browsing back through pre-upscale 1K versions in the history. */
function badgeFor(img){
  if(img && img.versions && img.versions.length && img.active_version_id){
    const v=img.versions.find(x=>x.id===img.active_version_id);
    if(v) return v.source==='upscale' ? '4K' : '1K';
  }
  return '1K'; // base enhanced state, or no versions yet
}
function setBadge(card,img){
  const stage=card&&card.querySelector('[data-stage]'); if(!stage) return;
  const old=stage.querySelector('.badge'); if(old) old.remove();
  const rb=badgeFor(img);
  const nb=el('span','badge'+(rb==='4K'?' k4':'')); nb.textContent=rb; stage.appendChild(nb);
}
function applyCursor(card,img,d){
  img.current_url=d.current_url; img.active_version_id=d.active_version_id;
  if(imgState[img.projectImageId]){ imgState[img.projectImageId].current_url=d.current_url; imgState[img.projectImageId].active_version_id=d.active_version_id; }
  card.querySelector('[data-main]').src=d.current_url;
  setBadge(card,img); renderHistory(card,img); highlightPick(card,img); updateCompareState(card);
}
async function moveVersion(card,img,dir){
  try{ const d=await api('/api/version/'+dir,{method:'POST',body:{projectImageId:img.projectImageId}}); applyCursor(card,img,d);}catch(e){toast(e.message,true);}
}
async function setVersion(card,img,versionId){
  try{ const d=await api('/api/version/set',{method:'POST',body:{projectImageId:img.projectImageId,versionId}}); applyCursor(card,img,d);}catch(e){toast(e.message,true);}
}

/* ── Refresh one image from the server (after async tools) ── */
async function refreshImage(projectImageId){
  try{
    const d=await api('/api/album/'+encodeURIComponent(current.albumId));
    const fresh=(d.images||[]).find(i=>i.projectImageId===projectImageId);
    if(!fresh) return;
    imgState[projectImageId]=fresh;
    const card=$('#cardGrid').querySelector('.card[data-id="'+projectImageId+'"]');
    if(!card) return;
    card.querySelector('[data-main]').src=fresh.current_url||fresh.enhanced_url||'';
    setBadge(card,fresh);
    renderHistory(card,fresh); highlightPick(card,fresh); updateCompareState(card);
  }catch(e){}
}

/* ── Refine (async + poll) ── */
let refTargetCard=null;
function openRefModal(card){
  refTargetCard=card;
  const grid=$('#refGrid');
  grid.innerHTML='<div class="skeleton" style="aspect-ratio:1/1"></div><div class="skeleton" style="aspect-ratio:1/1"></div><div class="skeleton" style="aspect-ratio:1/1"></div>';
  $('#refModal').classList.add('open');
  api('/api/materials').then(function(d){
    const materials=d.materials||[]; grid.innerHTML='';
    if(!materials.length){ grid.innerHTML='<div class="empty"><h2>No library images yet</h2><p class="muted">Add some in Library → Materials.</p></div>'; return; }
    materials.forEach(function(m){
      const a=el('div','asset');
      a.innerHTML='<div class="asset-img"><img src="'+esc(m.imageUrl)+'" alt="" style="max-width:100%;max-height:100%;object-fit:cover"></div><div class="asset-name">'+esc(m.name||'Image')+'</div>';
      a.style.cursor='pointer';
      a.addEventListener('click',function(){ selectRef(m); });
      grid.appendChild(a);
    });
  }).catch(function(){ grid.innerHTML='<div class="empty"><h2>Could not load library</h2></div>'; });
}
function closeRefModal(){ $('#refModal').classList.remove('open'); refTargetCard=null; }
function selectRef(m){
  const card=refTargetCard; if(!card) return;
  card._refMaterialId=m.id;
  const chip=card.querySelector('[data-ref-chip]');
  card.querySelector('[data-ref-thumb]').src=m.imageUrl;
  chip.hidden=false;
  closeRefModal();
  toast('Reference attached — describe what to do with it');
}
function clearRef(card){
  card._refMaterialId=null;
  const chip=card.querySelector('[data-ref-chip]'); if(chip) chip.hidden=true;
}
async function refine(card,img,btn){
  const ta=card.querySelector('.refine-in'); const prompt=ta.value.trim();
  if(!prompt){ toast('Enter an instruction first',true); return; }
  const mainImg=card.querySelector('[data-main]');
  const src=mainImg.src;
  const materialId=card._refMaterialId||null;
  btn.disabled=true; btn.textContent='Starting…';
  try{
    await api('/api/refine',{method:'POST',body:{imageUrl:src,jobId:img.jobId,imageIndex:String(img.image_index),prompt,materialId,source_w:mainImg.naturalWidth||'',source_h:mainImg.naturalHeight||''}});
    loadCredits();
    btn.textContent='Refining…';
    pollStatus('/api/refine-status',img.jobId,img.image_index,'refined_url',async()=>{
      ta.value=''; clearRef(card); btn.disabled=false; btn.textContent='Refine';
      await refreshImage(img.projectImageId); toast('Refine saved as a new version');
    },()=>{ btn.disabled=false; btn.textContent='Refine'; });
  }catch(e){ btn.disabled=false; btn.textContent='Refine'; if(e.code!=='INSUFFICIENT_CREDITS') toast(e.message,true); }
}

/* ── Upscale (async + poll) ── */
async function upscale(card,img,btn){
  const src=card.querySelector('[data-main]').src;
  btn.disabled=true; btn.textContent='Starting…';
  try{
    await api('/api/upscale',{method:'POST',body:{imageUrl:src,jobId:img.jobId,imageIndex:String(img.image_index),outputQuality:80}});
    loadCredits();
    btn.textContent='Upscaling…';
    pollStatus('/api/upscale-status',img.jobId,img.image_index,'upscaled_url',async()=>{
      btn.disabled=false; btn.textContent='⬆ Upscale to 4K';
      await refreshImage(img.projectImageId); toast('Upscaled to 4K');
    },()=>{ btn.disabled=false; btn.textContent='⬆ Upscale to 4K'; });
  }catch(e){ btn.disabled=false; btn.textContent='⬆ Upscale to 4K'; if(e.code!=='INSUFFICIENT_CREDITS') toast(e.message,true); }
}

function pollStatus(base,jobId,imageIndex,urlKey,onDone,onFail){
  let n=0; const max=90;
  const tick=async()=>{
    n++;
    try{
      const d=await api(base+'?jobId='+encodeURIComponent(jobId)+'&imageIndex='+encodeURIComponent(String(imageIndex)));
      if(d.status==='completed'&&d[urlKey]){ onDone(); return; }
      if(d.status==='failed'||d.status==='error'){ toast('Operation failed: '+(d.error_message||'unknown'),true); onFail&&onFail(); return; }
    }catch(e){}
    if(n>=max){ toast('Still working — check back shortly',true); onFail&&onFail(); return; }
    setTimeout(tick,2000);
  };
  setTimeout(tick,2000);
}

/* ── Async auto-heal watch: show "Generating alternate…" while the Flash heal runs
   in the background, then refresh so the Compare slider lights up. Quiet by design:
   404 (no heal job — e.g. legacy images) or a fallback (no genuine alternate) just
   hide the pill and leave Compare disabled. */
async function startHealWatch(card,img){
  const latest=imgState[img.projectImageId]||img;
  if(latest.healed_url) return;                 // a real alternate already exists
  const hint=card.querySelector('[data-heal-hint]');
  let n=0; const max=120;
  const tick=async()=>{
    n++;
    let d;
    try{
      d=await api('/api/heal-status?jobId='+encodeURIComponent(img.jobId)+'&imageIndex='+encodeURIComponent(String(img.image_index)));
    }catch(e){ if(hint)hint.classList.add('hidden'); return; } // 404 / no job → stop quietly
    if(d.status==='completed'){
      if(hint)hint.classList.add('hidden');
      if(d.healed_url && !d.heal_fallback){ await refreshImage(img.projectImageId); } // Compare enables via updateCompareState
      return;
    }
    if(d.status==='failed'){ if(hint)hint.classList.add('hidden'); return; }
    if(hint)hint.classList.remove('hidden');     // still processing
    if(n>=max){ if(hint)hint.classList.add('hidden'); return; }
    setTimeout(tick,2500);
  };
  tick();
}

/* heal watches are deduped so repeated polls/loads never stack timers */
const healWatching=new Set();
let albumPollTimer=null;

function maybeStartHeal(card,img){
  return; // Heal retired (1.0.8): no alternate is generated; nothing to watch.
}

/* Transition a still-enhancing card to its finished state (no fetch — caller supplies fresh). */
function applyReady(card,fresh){
  card.classList.remove('is-processing');
  const ov=card.querySelector('[data-proc]'); if(ov) ov.remove();
  card.querySelector('[data-main]').src=fresh.current_url||fresh.enhanced_url||'';
  setBadge(card,fresh);
  renderHistory(card,fresh); highlightPick(card,fresh); updateCompareState(card);
}

/* Poll the album while any image is still enhancing — we land here straight after a
   batch. Updates cards in place; as each enhance completes it hands off to the heal watch. */
function pollAlbumProgress(){
  if(albumPollTimer){ clearTimeout(albumPollTimer); albumPollTimer=null; }
  let n=0; const max=150;
  const tick=async()=>{
    n++;
    let d;
    try{ d=await api('/api/album/'+encodeURIComponent(current.albumId)); }
    catch(e){ albumPollTimer=setTimeout(tick,5000); return; }
    const imgs=d.images||[]; let anyProcessing=false;
    imgs.forEach(fresh=>{
      imgState[fresh.projectImageId]=fresh;
      const card=$('#cardGrid').querySelector('.card[data-id="'+fresh.projectImageId+'"]');
      if(!card) return;
      const ready=fresh.status==='completed' && (fresh.current_url||fresh.enhanced_url);
      if(ready){
        if(card.classList.contains('is-processing')) applyReady(card,fresh);
        maybeStartHeal(card,fresh);
      }else{ anyProcessing=true; }
    });
    if(anyProcessing && n<max){ albumPollTimer=setTimeout(tick,5000); } else { albumPollTimer=null; }
  };
  tick();
}

/* ── Animate ── */
async function animate(card,img,btn){
  const input=card.querySelector('.anim input'); const email=input.value.trim();
  if(!email||email.indexOf('@')<0){ toast('Enter a valid email',true); return; }
  const src=card.querySelector('[data-main]').src;
  btn.disabled=true; btn.textContent='Sending…';
  try{
    await api('/api/animate',{method:'POST',body:{email,image:src,name:'design-'+((parseInt(img.image_index,10)||0)+1)+'.jpg'}});
    btn.textContent='Sent'; toast('Animation is rendering — we’ll email it in 1–2 min');
    loadCredits();
  }catch(e){ btn.disabled=false; btn.textContent='🎬 Animate'; if(e.code!=='INSUFFICIENT_CREDITS') toast(e.message,true); }
}

/* ── Download (blob, to force save of cross-origin S3) ── */
/* Downloads go through /api/image/:id/export, which composites the saved logo
   placement onto the ACTIVE version at request time and streams the bytes from our
   own origin (so S3 CORS can't block the save). No placement = the plain image. */
async function download(projectImageId,name,fallbackUrl){
  try{
    const res=await fetch('/api/image/'+encodeURIComponent(projectImageId)+'/export',
      {method:'POST',headers:{'Authorization':'Bearer '+TOKEN}});
    if(res.status===401){ location.replace('/'); return; }
    if(!res.ok) throw new Error('Export failed');
    const b=await res.blob(); const u=URL.createObjectURL(b);
    const a=el('a'); a.href=u; a.download=name||'image.jpg'; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(()=>URL.revokeObjectURL(u),1500);
    toast('Saved to your Downloads');
  }catch(e){
    if(fallbackUrl){ window.open(fallbackUrl,'_blank'); toast('Opened in a new tab — right-click to save',true); }
    else toast('Download failed',true);
  }
}

/* ── Inpaint (roomy modal mask editor → Path A + server-side composite) ──
   The S3 image is a plain <img> backdrop; the canvas on top only ever holds the
   user's own mask strokes, so toDataURL() is never tainted (no S3 CORS needed).
   We keep a visible aqua overlay + a hidden white-on-black mask in lockstep, and
   export the mask as a PNG to /api/inpaint. */
/* §8E smart-select lexicon: the surfaces that get chips. `concept` MUST match the
   SAM3 `class` string returned by /api/segment verbatim (the chip stays disabled on
   any mismatch); `label` is what the user reads; `orientation` auto-sets the v8
   Surface control so the Z-axis prompt is right without the user thinking about it.
   Workflow confidence threshold is set to 0.25 for these to ground reliably. Coping /
   waterline tile stay on the brush for now (SAM3 won't ground them zero-shot — a
   future fine-tune or exemplar-box pass adds them). */
const SF_LEXICON=[
  {concept:'pool water',                label:'pool water',    orientation:'floor'},
  {concept:'raised wall',               label:'wall',          orientation:'wall'},
  {concept:'paver floor',               label:'decking',       orientation:'floor'},
  {concept:'paver border',              label:'paver border',  orientation:'floor'},
  {concept:'raised spa spillway wall',  label:'raised wall',   orientation:'wall'},
  {concept:'raised wall paver cap',     label:'wall cap',      orientation:'floor'}
];
let ipState={card:null,img:null,view:null,mask:null,drawing:false,mode:'brush',last:null,painted:false,materialId:null,materialCategory:null,surface:'auto',seg:null,smartSel:new Set()};
let ipMaterials=[]; let ipMatCat='all';

function openInpaintModal(card,img){
  const latest=imgState[img.projectImageId]||img;
  ipState.card=card; ipState.img=latest; ipState.painted=false; ipState.last=null;
  ipState.materialId=null; ipState.materialCategory=null; ipState.surface='auto';
  ipState.seg=null; ipState.smartSel=new Set();
  $('#ipChips').hidden=true; $('#ipChips').innerHTML='';
  setIpMode('brush');
  ipSetSurface('auto');
  $('#ipPrompt').value='';
  ipLoadMaterials();
  const im=$('#ipImg');
  im.onload=()=>ipSetupCanvas(im);
  im.src=card.querySelector('[data-main]').src;
  $('#ipModal').classList.add('open');
  ipRenderHistory();
}
function ipSetSurface(s){
  ipState.surface=s;
  document.querySelectorAll('#ipSurface .ip-seg-btn').forEach(function(b){
    b.classList.toggle('active', b.dataset.surface===s);
  });
}
async function ipLoadMaterials(){
  const cats=$('#ipMatCats'); const pick=$('#ipMatPick');
  cats.innerHTML=''; pick.innerHTML='<span class="ip-mat-empty">Loading…</span>';
  try{ const d=await api('/api/materials'); ipMaterials=d.materials||[]; }catch(e){ ipMaterials=[]; }
  ipMatCat='all';
  ipRenderMatCats();
  ipRenderMatSwatches();
}
function ipRenderMatCats(){
  const wrap=$('#ipMatCats'); wrap.innerHTML='';
  if(!ipMaterials.length) return;
  const cats=['all'].concat(matCatsPresent(ipMaterials));
  cats.forEach(function(c){
    const n=c==='all'?ipMaterials.length:ipMaterials.filter(function(m){return (m.category||'other').toLowerCase()===c;}).length;
    const chip=el('button','ip-mat-cat'+(c===ipMatCat?' active':''));
    chip.innerHTML=esc(MAT_LABELS[c]||c)+' <span style="opacity:.7">'+n+'</span>';
    chip.addEventListener('click',function(){ ipMatCat=c; ipRenderMatCats(); ipRenderMatSwatches(); });
    wrap.appendChild(chip);
  });
}
function ipRenderMatSwatches(){
  const pick=$('#ipMatPick'); pick.innerHTML='';
  // "None" tile — plain text inpaint — always available regardless of filter.
  const none=el('button','ip-mat-none'+((ipState.materialId==null)?' active':''));
  none.textContent='None';
  none.addEventListener('click',()=>ipSelectMaterial(null,none));
  pick.appendChild(none);
  if(!ipMaterials.length){
    const sp=el('span','ip-mat-empty');
    sp.innerHTML='No materials yet — add some in <b>Library → Materials</b>.';
    pick.appendChild(sp);
    return;
  }
  const list=ipMatCat==='all'?ipMaterials:ipMaterials.filter(function(m){return (m.category||'other').toLowerCase()===ipMatCat;});
  list.forEach(function(m){
    const sw=el('button','ip-mat-swatch'+((ipState.materialId===m.id)?' active':''));
    sw.title=(m.name||'Material')+' · '+(m.category||'other');
    sw.innerHTML='<img src="'+esc(m.imageUrl)+'" alt="">';
    sw.addEventListener('click',()=>ipSelectMaterial(m,sw));
    pick.appendChild(sw);
  });
}
function ipSelectMaterial(m,node){
  document.querySelectorAll('#ipMatPick .ip-mat-swatch, #ipMatPick .ip-mat-none')
    .forEach(s=>s.classList.remove('active'));
  node.classList.add('active');
  ipState.materialId=m?m.id:null;
  ipState.materialCategory=m?m.category:null;
  const pr=$('#ipPrompt');
  pr.placeholder=m
    ? 'Optional — add scale or layout notes (e.g. large 18×18 pavers, running-bond pattern). The swatch drives the look.'
    : 'Describe the fix for the painted area — e.g. replace with smooth travertine pavers, matching the surrounding shadows';
}
function closeInpaintModal(){
  $('#ipModal').classList.remove('open');
  ipState.drawing=false; ipState.last=null; ipState.painted=false;
}
/* In-modal result history: step back through saved versions and keep inpainting
   without leaving the editor. Backed by the same version endpoints the card uses. */
function ipRenderHistory(){
  const wrap=$('#ipHistory'); if(!wrap) return;
  wrap.innerHTML='';
  const img=ipState.img||{};
  const vers=img.versions||[];
  if(!vers.length){
    const note=el('span','muted');
    note.textContent='Your inpaint results will stack up here — tap one to step back.';
    wrap.appendChild(note);
    return;
  }
  vers.forEach(function(v){
    const th=el('button','ip-hist-thumb'+(v.id===img.active_version_id?' active':''));
    th.title=(v.source||'version')+(v.prompt?' — '+v.prompt:'');
    th.innerHTML='<img src="'+esc(v.url)+'" alt=""><span>v'+v.seq+'</span>';
    th.addEventListener('click',function(){ if(v.id!==ipState.img.active_version_id) ipSetVersion(v.id); });
    wrap.appendChild(th);
  });
  const act=wrap.querySelector('.ip-hist-thumb.active');
  if(act){ requestAnimationFrame(function(){ wrap.scrollLeft=act.offsetLeft-(wrap.clientWidth/2)+(act.clientWidth/2); }); }
}
/* Re-point the editor at the freshest version of the current image (after a generate,
   a version switch, or a delete) without closing the modal. */
function ipSyncFromState(preserveSmart){
  const fresh=ipState.img && imgState[ipState.img.projectImageId];
  if(!fresh){ ipRenderHistory(); return; }
  ipState.img=fresh;
  const newSrc=fresh.current_url||fresh.enhanced_url||'';
  // After an inpaint generation the composite pins every UNMASKED pixel identical to
  // the source and keeps the same resolution, so the detected surface masks are still
  // valid on the new result. Keep the segmentation cache (re-pointed to the new src so
  // we never re-segment), clear only the just-used selection, and stay in Smart mode —
  // the user can pick another surface and generate again without re-running Smart select.
  // The version-step / delete-version paths call this WITHOUT preserveSmart, because
  // stepping to a different version does change geometry, so those still re-segment.
  if(preserveSmart && ipState.seg){
    ipState.seg.src=newSrc;
    ipState.smartSel=new Set();
    const im=$('#ipImg');
    im.onload=()=>{ ipSetupCanvas(im); if(ipState.mode==='smart'){ $('#ipChips').hidden=false; ipRenderChips(); } };
    im.src=newSrc;
    ipRenderHistory();
    return;
  }
  ipState.seg=null; ipState.smartSel=new Set();
  $('#ipChips').hidden=true; $('#ipChips').innerHTML='';
  setIpMode('brush');
  const im=$('#ipImg');
  im.onload=()=>ipSetupCanvas(im);
  im.src=newSrc;
  ipRenderHistory();
}
async function ipSetVersion(versionId){
  const id=ipState.img&&ipState.img.projectImageId; if(!id) return;
  try{
    await api('/api/version/set',{method:'POST',body:{projectImageId:id,versionId}});
    await refreshImage(id);
    ipSyncFromState();
  }catch(e){ toast(e.message,true); }
}
async function ipDeleteCurrent(){
  const cur=(ipState.img&&imgState[ipState.img.projectImageId])||ipState.img;
  const id=cur&&cur.projectImageId; const vid=cur&&cur.active_version_id;
  if(!id) return;
  if(!vid){ toast('No saved version to remove yet',true); return; }
  if(!confirm('Remove this version from the history? This cannot be undone.')) return;
  try{
    await api('/api/version/delete',{method:'POST',body:{projectImageId:id,versionId:vid}});
    await refreshImage(id);
    ipSyncFromState();
    toast('Version removed');
  }catch(e){ toast(e.message,true); }
}
function ipSetupCanvas(im){
  const W=im.naturalWidth||im.width, H=im.naturalHeight||im.height;
  const view=$('#ipView'); view.width=W; view.height=H;
  view.getContext('2d').clearRect(0,0,W,H);
  const mask=document.createElement('canvas'); mask.width=W; mask.height=H;
  const mctx=mask.getContext('2d'); mctx.fillStyle='#000'; mctx.fillRect(0,0,W,H);
  ipState.view=view; ipState.mask=mask; ipState.painted=false;
}
function setIpMode(mode){
  ipState.mode=mode;
  $('#ipBrush').classList.toggle('active',mode==='brush');
  $('#ipEraser').classList.toggle('active',mode==='eraser');
  $('#ipSmart').classList.toggle('active',mode==='smart');
  const chips=$('#ipChips');
  if(mode==='smart'){ chips.hidden=false; ipEnsureSegmented(); }
  else { chips.hidden=true; }
}
/* Build a once-per-concept aqua-tinted canvas from a white-on-transparent mask PNG,
   so the visible overlay can be composited cheaply on every chip toggle. */
function ipTintCanvas(img){
  const c=document.createElement('canvas'); c.width=img.naturalWidth; c.height=img.naturalHeight;
  const x=c.getContext('2d');
  x.drawImage(img,0,0);
  x.globalCompositeOperation='source-in';
  x.fillStyle='rgba(0,194,199,1)';
  x.fillRect(0,0,c.width,c.height);
  return c;
}
/* One Roboflow call per image, cached on ipState.seg keyed by the image src. */
async function ipEnsureSegmented(){
  const chips=$('#ipChips');
  const src=ipState.img && (ipState.card.querySelector('[data-main]').src);
  if(ipState.seg && ipState.seg.src===src){ ipRenderChips(); return; }
  chips.innerHTML='<span class="ip-chip-note">Detecting surfaces…</span>';
  try{
    const d=await api('/api/segment',{method:'POST',body:{imageUrl:src}});
    const concepts={};
    (d.concepts||[]).forEach(function(c){
      const img=new Image(); img.src=c.mask;
      const entry={found:c.instances_found,orientation:null,img:img,tint:null,bbox:c.bbox};
      img.onload=function(){ entry.tint=ipTintCanvas(img); };
      concepts[c.concept]=entry;
    });
    // attach orientation from the lexicon so chip clicks can auto-set Floor/Wall
    SF_LEXICON.forEach(function(l){ if(concepts[l.concept]) concepts[l.concept].orientation=l.orientation; });
    ipState.seg={src:src, concepts:concepts};
    ipRenderChips();
  }catch(e){
    chips.innerHTML='';
    const note=el('span','ip-chip-note');
    note.textContent='Smart select unavailable — use Brush. ('+e.message+')';
    chips.appendChild(note);
  }
}
function ipRenderChips(){
  const chips=$('#ipChips'); chips.innerHTML='';
  const concepts=(ipState.seg&&ipState.seg.concepts)||{};
  SF_LEXICON.forEach(function(l){
    const c=concepts[l.concept];
    const found=c&&c.found>0;
    const chip=el('button','ip-chip'+(found?'':' disabled')+(ipState.smartSel.has(l.concept)?' active':''));
    chip.textContent=l.label+(found?' ('+c.found+')':'');
    chip.dataset.concept=l.concept;
    if(!found) chip.title='Not detected in this image';
    chips.appendChild(chip);
  });
  const hint=el('span','ip-chip-note');
  hint.textContent='Pick a surface — Brush still works to refine the selection.';
  chips.appendChild(hint);
}
function ipToggleConcept(name){
  const c=ipState.seg&&ipState.seg.concepts[name];
  if(!c||!c.found) return;
  if(ipState.smartSel.has(name)) ipState.smartSel.delete(name);
  else { ipState.smartSel.add(name); if(c.orientation) ipSetSurface(c.orientation); }
  ipRebuildSmart();
  ipRenderChips();
}
/* Rebuild mask + visible overlay from the selected concepts. Union is just stacking
   the white-on-transparent masks (source-over) over the black mask backdrop, which
   is exactly the white-on-black PNG /api/inpaint already expects. */
function ipRebuildSmart(){
  const mask=ipState.mask, view=ipState.view; if(!mask||!view) return;
  const W=mask.width, H=mask.height;
  const m=mask.getContext('2d'); m.globalCompositeOperation='source-over';
  m.fillStyle='#000'; m.fillRect(0,0,W,H);
  const v=view.getContext('2d'); v.clearRect(0,0,W,H);
  let any=false;
  ipState.smartSel.forEach(function(name){
    const c=ipState.seg.concepts[name]; if(!c||!c.img||!c.img.complete) return;
    m.drawImage(c.img,0,0,W,H);
    if(c.tint){ v.save(); v.globalAlpha=.5; v.drawImage(c.tint,0,0,W,H); v.restore(); }
    any=true;
  });
  ipState.painted=any;
}
function ipClearMask(){
  if(!ipState.view||!ipState.mask) return;
  const W=ipState.view.width, H=ipState.view.height;
  ipState.view.getContext('2d').clearRect(0,0,W,H);
  const mctx=ipState.mask.getContext('2d'); mctx.fillStyle='#000'; mctx.fillRect(0,0,W,H);
  ipState.painted=false;
  if(ipState.smartSel.size){ ipState.smartSel.clear(); ipRenderChips(); }
}
function ipPos(e){
  const v=ipState.view, r=v.getBoundingClientRect();
  const sx=v.width/r.width, sy=v.height/r.height;
  return { x:(e.clientX-r.left)*sx, y:(e.clientY-r.top)*sy, scale:sx };
}
function ipStroke(p){
  if(!ipState.view||!ipState.mask) return;
  if(ipState.mode==='smart') return; // chips drive the mask in smart-select mode
  const lw=Math.max(1,(+$('#ipSize').value)*p.scale);
  const erase=ipState.mode==='eraser';
  const from=ipState.last||p;
  // visible aqua overlay
  const v=ipState.view.getContext('2d');
  v.lineCap='round'; v.lineJoin='round'; v.lineWidth=lw;
  v.globalCompositeOperation=erase?'destination-out':'source-over';
  v.strokeStyle=erase?'rgba(0,0,0,1)':'rgba(0,194,199,.5)';
  v.fillStyle=v.strokeStyle;
  v.beginPath(); v.moveTo(from.x,from.y); v.lineTo(p.x,p.y); v.stroke();
  v.beginPath(); v.arc(p.x,p.y,lw/2,0,Math.PI*2); v.fill();
  // hidden white-on-black mask (source of truth)
  const m=ipState.mask.getContext('2d');
  m.lineCap='round'; m.lineJoin='round'; m.lineWidth=lw;
  m.globalCompositeOperation='source-over';
  m.strokeStyle=erase?'#000':'#fff'; m.fillStyle=m.strokeStyle;
  m.beginPath(); m.moveTo(from.x,from.y); m.lineTo(p.x,p.y); m.stroke();
  m.beginPath(); m.arc(p.x,p.y,lw/2,0,Math.PI*2); m.fill();
  v.globalCompositeOperation='source-over';
  ipState.last=p;
  if(!erase) ipState.painted=true;
}
async function runInpaint(){
  if(!ipState.painted){ toast('Paint over the area to fix first',true); return; }
  const prompt=$('#ipPrompt').value.trim();
  const materialId=ipState.materialId;
  if(!prompt && !materialId){ toast('Pick a material or describe the correction first',true); return; }
  const img=ipState.img, card=ipState.card;
  const maskData=ipState.mask.toDataURL('image/png');
  const mainImg=card.querySelector('[data-main]');
  const src=mainImg.src;
  const go=$('#ipGo'); go.disabled=true; go.textContent='Starting…';
  try{
    await api('/api/inpaint',{method:'POST',body:{imageUrl:src,jobId:img.jobId,imageIndex:String(img.image_index),prompt,maskData,materialId,surface:ipState.surface,source_w:mainImg.naturalWidth||'',source_h:mainImg.naturalHeight||''}});
    loadCredits();
    go.textContent='Generating…';
    pollStatus('/api/inpaint-status',img.jobId,img.image_index,'inpainted_url',async()=>{
      go.disabled=false; go.textContent='Generate inpaint';
      await refreshImage(img.projectImageId);
      if($('#ipModal').classList.contains('open')){
        ipSyncFromState(true);             // stay in the editor, keep smart-select masks, show the new result + history
        $('#ipPrompt').value='';
        toast(materialId?'Material swap saved — keep editing or close':'Inpaint saved — keep editing or close');
      }else{
        toast(materialId?'Material swap saved as a new version':'Inpaint saved as a new version');
      }
    },()=>{ go.disabled=false; go.textContent='Generate inpaint'; });
  }catch(e){ go.disabled=false; go.textContent='Generate inpaint'; if(e.code!=='INSUFFICIENT_CREDITS') toast(e.message,true); }
}
// wire modal controls once
$('#ipView').addEventListener('pointerdown',e=>{ ipState.drawing=true; ipState.last=null; ipStroke(ipPos(e)); e.preventDefault(); });
window.addEventListener('pointermove',e=>{ if(ipState.drawing) ipStroke(ipPos(e)); });
window.addEventListener('pointerup',()=>{ ipState.drawing=false; ipState.last=null; });
$('#ipBrush').addEventListener('click',()=>setIpMode('brush'));
$('#ipEraser').addEventListener('click',()=>setIpMode('eraser'));
$('#ipSmart').addEventListener('click',()=>setIpMode('smart'));
$('#ipChips').addEventListener('click',e=>{ const b=e.target.closest('.ip-chip'); if(b&&!b.classList.contains('disabled')) ipToggleConcept(b.dataset.concept); });
$('#ipSurface').addEventListener('click',e=>{ const b=e.target.closest('.ip-seg-btn'); if(b) ipSetSurface(b.dataset.surface); });
$('#ipClear').addEventListener('click',ipClearMask);
$('#ipGo').addEventListener('click',runInpaint);
$('#ipTrash').addEventListener('click',ipDeleteCurrent);
$('#ipClose').addEventListener('click',closeInpaintModal);
$('#ipCancel').addEventListener('click',closeInpaintModal);
$('#ipModal').addEventListener('click',e=>{ if(e.target.id==='ipModal') closeInpaintModal(); });
$('#refClose').addEventListener('click',closeRefModal);
$('#refCancel').addEventListener('click',closeRefModal);
$('#refModal').addEventListener('click',e=>{ if(e.target.id==='refModal') closeRefModal(); });
document.addEventListener('keydown',e=>{
  if(e.key!=='Escape') return;
  if($('#refModal').classList.contains('open')) closeRefModal();
  else if($('#ipModal').classList.contains('open')) closeInpaintModal();
});

/* ── Library: per-user brand assets (logos now; materials next phase) ── */
function showOnlyView(id){
  ['albumsView','albumView','trashView','libraryView'].forEach(function(v){
    var n=document.getElementById(v); if(n) n.classList.toggle('hidden', v!==id);
  });
}
function openLibrary(){
  showOnlyView('libraryView');
  window.scrollTo({top:0,behavior:'smooth'});
  switchLibTab('logos');
}
function switchLibTab(tab){
  document.querySelectorAll('.lib-tab').forEach(function(b){ b.classList.toggle('active', b.dataset.lib===tab); });
  $('#libLogos').classList.toggle('hidden', tab!=='logos');
  $('#libMaterials').classList.toggle('hidden', tab!=='materials');
  if(tab==='logos') loadLogos();
  if(tab==='materials') loadMaterials();
}
async function loadLogos(){
  const grid=$('#logoGrid');
  grid.innerHTML='<div class="skeleton" style="aspect-ratio:1/1"></div><div class="skeleton" style="aspect-ratio:1/1"></div><div class="skeleton" style="aspect-ratio:1/1"></div>';
  try{
    const d=await api('/api/logos'); const logos=d.logos||[];
    grid.innerHTML='';
    const add=el('button','asset-add');
    add.innerHTML='<span class="plus">＋</span><span>Upload logo</span>';
    add.addEventListener('click',pickLogoFile);
    grid.appendChild(add);
    logos.forEach(function(l){ grid.appendChild(buildAsset(l)); });
  }catch(e){ grid.innerHTML='<div class="empty"><h2>Could not load logos</h2></div>'; }
}
function buildAsset(l){
  const a=el('div','asset');
  a.innerHTML=
    '<div class="asset-img"><img src="'+esc(l.imageUrl)+'" alt=""></div>'+
    '<div class="asset-name">'+esc(l.name||'Logo')+'</div>'+
    '<button class="asset-del" title="Delete logo">🗑</button>';
  a.querySelector('.asset-del').addEventListener('click',function(){ deleteLogo(l,a); });
  return a;
}
function pickLogoFile(){
  const inp=document.createElement('input');
  inp.type='file'; inp.accept='image/png,image/svg+xml,image/webp,image/jpeg,image/*';
  inp.addEventListener('change',function(){ if(inp.files&&inp.files[0]) uploadLogo(inp.files[0]); });
  inp.click();
}
async function uploadLogo(file){
  if(file.size>5*1024*1024){ toast('Logo must be under 5MB',true); return; }
  toast('Uploading logo…');
  try{
    const fd=new FormData(); fd.append('logo',file);
    const res=await fetch('/api/logos',{method:'POST',headers:{'Authorization':'Bearer '+TOKEN},body:fd});
    if(res.status===401){ location.replace('/'); return; }
    let d=null; try{ d=await res.json(); }catch(e){}
    if(!res.ok) throw new Error((d&&d.error)||'Upload failed');
    toast('Logo added'); loadLogos();
  }catch(e){ toast(e.message,true); }
}
async function deleteLogo(l,node){
  if(!confirm('Delete this logo? Images you have already branded keep their logo.')) return;
  try{ await api('/api/logos/delete',{method:'POST',body:{logoId:l.id}}); node.remove(); toast('Logo deleted'); }
  catch(e){ toast(e.message,true); }
}

/* ── Library: Materials (per-user texture swatches for material-aware inpaint) ── */
const MAT_ORDER=['paver','tile','stone','decking','gravel','other'];
const MAT_LABELS={paver:'Pavers',tile:'Tile',stone:'Stone',decking:'Decking',gravel:'Gravel',other:'Other',all:'All'};
function matCatsPresent(materials){
  const present=[]; materials.forEach(function(m){ const c=(m.category||'other').toLowerCase(); if(present.indexOf(c)<0) present.push(c); });
  const ordered=MAT_ORDER.filter(function(c){return present.indexOf(c)>=0;});
  present.forEach(function(c){ if(ordered.indexOf(c)<0) ordered.push(c); });
  return ordered;
}
async function loadMaterials(){
  const host=$('#materialGrid');
  host.innerHTML='<div class="asset-grid"><div class="skeleton" style="aspect-ratio:1/1"></div><div class="skeleton" style="aspect-ratio:1/1"></div><div class="skeleton" style="aspect-ratio:1/1"></div></div>';
  try{
    const d=await api('/api/materials'); const materials=d.materials||[];
    host.innerHTML='';
    // Upload control (its category comes from the toolbar select, so keep it standalone on top).
    const row=el('div','mat-upload-row');
    const add=el('button','asset-add');
    add.innerHTML='<span class="plus">＋</span><span>Upload material</span>';
    add.addEventListener('click',pickMaterialFile);
    row.appendChild(add); host.appendChild(row);
    if(!materials.length) return;
    const groups={};
    materials.forEach(function(m){ const c=(m.category||'other').toLowerCase(); (groups[c]=groups[c]||[]).push(m); });
    matCatsPresent(materials).forEach(function(c){
      const sec=el('div','mat-section');
      const h=el('div','mat-section-head');
      h.innerHTML=esc(MAT_LABELS[c]||c)+' <span class="count">'+groups[c].length+'</span>';
      sec.appendChild(h);
      const g=el('div','asset-grid');
      groups[c].forEach(function(m){ g.appendChild(buildMaterialAsset(m)); });
      sec.appendChild(g); host.appendChild(sec);
    });
  }catch(e){ host.innerHTML='<div class="empty"><h2>Could not load materials</h2></div>'; }
}
function buildMaterialAsset(m){
  const a=el('div','asset');
  a.innerHTML=
    '<div class="asset-img"><img src="'+esc(m.imageUrl)+'" alt="" style="max-width:100%;max-height:100%;object-fit:cover"></div>'+
    '<div class="asset-name">'+esc(m.name||'Material')+'</div>'+
    '<div class="asset-cat">'+esc(m.category||'other')+'</div>'+
    '<button class="asset-del" title="Delete material">🗑</button>';
  a.querySelector('.asset-del').addEventListener('click',function(){ deleteMaterial(m,a); });
  return a;
}
function pickMaterialFile(){
  const inp=document.createElement('input');
  inp.type='file'; inp.accept='image/jpeg,image/png,image/webp,image/*';
  inp.addEventListener('change',function(){ if(inp.files&&inp.files[0]) uploadMaterial(inp.files[0]); });
  inp.click();
}
async function uploadMaterial(file){
  if(file.size>5*1024*1024){ toast('Material must be under 5MB',true); return; }
  const category=($('#matCategory')&&$('#matCategory').value)||'other';
  toast('Uploading material…');
  try{
    const fd=new FormData(); fd.append('material',file); fd.append('category',category);
    const res=await fetch('/api/materials',{method:'POST',headers:{'Authorization':'Bearer '+TOKEN},body:fd});
    if(res.status===401){ location.replace('/'); return; }
    let d=null; try{ d=await res.json(); }catch(e){}
    if(!res.ok) throw new Error((d&&d.error)||'Upload failed');
    toast('Material added'); loadMaterials();
  }catch(e){ toast(e.message,true); }
}
async function deleteMaterial(m,node){
  if(!confirm('Delete this material? Inpaints you already generated are unaffected.')) return;
  try{ await api('/api/materials/delete',{method:'POST',body:{materialId:m.id}}); node.remove(); toast('Material deleted'); }
  catch(e){ toast(e.message,true); }
}
$('#libraryBtn').addEventListener('click',openLibrary);
/* album sort control */
(function(){
  const sel=$('#albumSort'); if(!sel) return;
  sel.value=albumSort;
  sel.addEventListener('change',function(){
    albumSort=sel.value; localStorage.setItem('albumSort',albumSort);
    if(ALBUMS.length) renderAlbums();
  });
})();
/* "build your Library" banner — dismissible, remembered per browser */
(function(){
  const b=$('#libBanner'); if(!b) return;  if(localStorage.getItem('libBannerDismissed')!=='1') b.hidden=false;
  const open=$('#libBannerOpen'); if(open) open.addEventListener('click',openLibrary);
  const x=$('#libBannerX'); if(x) x.addEventListener('click',function(){
    b.hidden=true; localStorage.setItem('libBannerDismissed','1');
  });
})();
$('#libBack').addEventListener('click',function(){ showOnlyView('albumsView'); loadAlbums(); });
document.querySelectorAll('.lib-tab').forEach(function(b){ b.addEventListener('click',function(){ switchLibTab(b.dataset.lib); }); });

/* ── Trash: soft delete + restore (30-day purge runs server-side via cron) ── */
async function deleteImage(card,img){
  if(!confirm('Move this design to Trash? You can restore it within 30 days.')) return;
  try{
    await api('/api/image/delete',{method:'POST',body:{projectImageId:img.projectImageId}});
    card.remove(); delete imgState[img.projectImageId];
    toast('Moved to Trash');
    const grid=$('#cardGrid');
    if(grid && !grid.querySelector('.card')){ grid.innerHTML='<div class="empty"><h2>No images</h2></div>'; }
  }catch(e){ toast(e.message,true); }
}
async function openTrash(){
  $('#albumsView').classList.add('hidden');
  $('#albumView').classList.add('hidden');
  $('#libraryView').classList.add('hidden');
  $('#trashView').classList.remove('hidden');
  window.scrollTo({top:0,behavior:'smooth'});
  const grid=$('#trashGrid'); grid.innerHTML='<div class="skeleton"></div><div class="skeleton"></div>';
  try{
    const d=await api('/api/trash'); const imgs=d.images||[];
    grid.innerHTML='';
    if(!imgs.length){ grid.innerHTML='<div class="empty"><h2>Trash is empty</h2></div>'; return; }
    imgs.forEach(im=>{
      const days=Math.max(0,30-Math.floor((Date.now()-new Date(im.deleted_at).getTime())/86400000));
      const tile=el('div','tile');
      tile.innerHTML=
        '<div class="tile-cover"><img src="'+esc(im.thumb||'')+'" alt=""><div class="tile-scrim"></div></div>'+
        '<div style="padding:12px 14px;display:flex;align-items:center;justify-content:space-between;gap:10px">'+
          '<div><div style="font-weight:600">'+esc(im.albumName)+'</div>'+
          '<div class="muted" style="font-size:12px">Removed in '+days+' day'+(days===1?'':'s')+'</div></div>'+
          '<button class="ghost-btn" data-restore>Restore</button>'+
        '</div>';
      tile.querySelector('[data-restore]').addEventListener('click',async()=>{
        try{
          await api('/api/image/restore',{method:'POST',body:{projectImageId:im.projectImageId}});
          tile.remove(); toast('Restored');
          if(!grid.querySelector('.tile')){ grid.innerHTML='<div class="empty"><h2>Trash is empty</h2></div>'; }
        }catch(e){ toast(e.message,true); }
      });
      grid.appendChild(tile);
    });
  }catch(e){ grid.innerHTML='<div class="empty"><h2>Could not load Trash</h2></div>'; }
}
$('#trashBtn').addEventListener('click',openTrash);
$('#trashBack').addEventListener('click',()=>{ $('#trashView').classList.add('hidden'); $('#albumsView').classList.remove('hidden'); loadAlbums(); });

/* ── Logo placement modal (deterministic composite — server-side sharp) ── */
let lgState={card:null,img:null,logoId:null,logoUrl:null,aspect:1,drag:null};
function cleanBaseClient(img){
  if(img.versions&&img.versions.length){
    // Walk back from the ACTIVE version (the one currently displayed / stepped-to in
    // the history strip), not the newest in the chain, so the logo modal previews the
    // image the user is actually on. We still skip logo versions so a new logo overlays
    // the clean base beneath rather than stacking on an existing logo.
    let start=activeIdx(img);
    if(start<0) start=img.versions.length-1;
    for(let i=start;i>=0;i--){ if(img.versions[i].source!=='logo') return img.versions[i].url; }
  }
  return img.enhanced_url||img.current_url||'';
}
async function openLogoModal(card,img){
  const latest=imgState[img.projectImageId]||img;
  lgState={card:card,img:latest,logoId:null,logoUrl:null,aspect:1,drag:null};
  const box=$('#lgBox'); box.removeAttribute('style'); box.style.display='none';
  $('#lgOpacity').value=100;
  $('#lgImg').src=cleanBaseClient(latest);
  const pick=$('#lgPick'); pick.innerHTML='<span class="lg-pick-empty">Loading…</span>';
  $('#lgModal').classList.add('open');
  let logos=[];
  try{ const d=await api('/api/logos'); logos=d.logos||[]; }catch(e){}
  pick.innerHTML='';
  if(!logos.length){
    const sp=el('span','lg-pick-empty'); sp.innerHTML='No logos yet — add one in <b>Library → Logos</b>.'; pick.appendChild(sp);
    return;
  }
  const swatches=[];
  logos.forEach(l=>{
    const sw=el('button','lg-swatch'); sw.innerHTML='<img src="'+esc(l.imageUrl)+'" alt="">';
    sw.addEventListener('click',()=>selectLogo(l,sw)); pick.appendChild(sw); swatches.push(sw);
  });
  // preselect the effective placement (image override, else album default)
  const eff=latest.logoOverride||current.logoDefault||null;
  if(eff){
    const mi=logos.findIndex(l=>l.imageUrl===eff.logoUrl);
    if(mi>=0) selectLogo(logos[mi],swatches[mi],eff);
  }
}
function defaultBox(){
  const sr=$('#lgStage').getBoundingClientRect(), box=$('#lgBox');
  const w=0.18*sr.width, h=w/lgState.aspect;
  box.style.width=w+'px'; box.style.height=h+'px';
  box.style.left=(sr.width-w-0.05*sr.width)+'px'; box.style.top=(0.05*sr.height)+'px';
}
function positionBoxFromPlacement(p){
  const sr=$('#lgStage').getBoundingClientRect(), box=$('#lgBox');
  const w=(p.w||0.18)*sr.width, h=w/lgState.aspect;
  box.style.width=w+'px'; box.style.height=h+'px';
  box.style.left=((p.x||0)*sr.width)+'px'; box.style.top=((p.y||0)*sr.height)+'px';
  const op=(p.opacity==null?1:p.opacity); $('#lgOpacity').value=Math.round(op*100); box.style.opacity=op;
}
function selectLogo(logo,swatchEl,placement){
  lgState.logoId=logo.id; lgState.logoUrl=logo.imageUrl;
  document.querySelectorAll('.lg-swatch').forEach(s=>s.classList.remove('active'));
  if(swatchEl) swatchEl.classList.add('active');
  const box=$('#lgBox'), bi=$('#lgBoxImg');
  bi.onload=function(){
    lgState.aspect=(bi.naturalWidth||1)/(bi.naturalHeight||1);
    box.style.display='block';
    if(placement) positionBoxFromPlacement(placement);
    else if(!box.style.width) defaultBox();
    else { const w=parseFloat(box.style.width)||0; box.style.height=(w/lgState.aspect)+'px'; }
  };
  bi.src=logo.imageUrl;
}
function lgPointerDown(e){
  if(!lgState.logoUrl) return;
  const box=$('#lgBox'), sr=$('#lgStage').getBoundingClientRect();
  lgState.drag={ resize:(e.target===$('#lgResize')), startX:e.clientX, startY:e.clientY,
    left:parseFloat(box.style.left)||0, top:parseFloat(box.style.top)||0, w:parseFloat(box.style.width)||0, sr:sr };
  e.preventDefault(); e.stopPropagation();
}
function lgPointerMove(e){
  const d=lgState.drag; if(!d) return; const box=$('#lgBox'), sr=d.sr;
  const dx=e.clientX-d.startX, dy=e.clientY-d.startY;
  if(d.resize){
    let w=Math.max(20,d.w+dx); w=Math.min(w,sr.width-d.left);
    box.style.width=w+'px'; box.style.height=(w/lgState.aspect)+'px';
  } else {
    const w=parseFloat(box.style.width)||0, h=parseFloat(box.style.height)||0;
    let left=Math.min(Math.max(d.left+dx,0),sr.width-w), top=Math.min(Math.max(d.top+dy,0),sr.height-h);
    box.style.left=left+'px'; box.style.top=top+'px';
  }
  e.preventDefault();
}
function placementNow(){
  const sr=$('#lgStage').getBoundingClientRect(), br=$('#lgBox').getBoundingClientRect();
  return { x:(br.left-sr.left)/sr.width, y:(br.top-sr.top)/sr.height, w:br.width/sr.width, opacity:(+$('#lgOpacity').value)/100 };
}
function closeLogoModal(){ $('#lgModal').classList.remove('open'); lgState.drag=null; }
async function lgApply(scope){
  if(!lgState.logoUrl){ toast('Pick a logo first',true); return; }
  const p=placementNow(), img=lgState.img;
  const a=$('#lgApplyAll'), o=$('#lgApplyOne'); a.disabled=o.disabled=true; a.textContent='Applying…';
  try{
    if(scope==='all') await api('/api/album/'+encodeURIComponent(current.albumId)+'/logo',{method:'POST',body:{logoId:lgState.logoId,placement:p}});
    else await api('/api/image/'+encodeURIComponent(img.projectImageId)+'/logo',{method:'POST',body:{logoId:lgState.logoId,placement:p}});
    closeLogoModal(); toast(scope==='all'?'Album logo saved — added to downloads':'Logo saved — added when you download');
    openAlbum({albumId:current.albumId,name:current.name});
  }catch(e){ toast(e.message,true); }
  finally{ a.disabled=o.disabled=false; a.textContent='Set as album default'; }
}
async function lgRemove(){
  if(!confirm('Remove the logo from this album? Downloads will no longer include it.')) return;
  try{
    await api('/api/album/'+encodeURIComponent(current.albumId)+'/logo/remove',{method:'POST'});
    closeLogoModal(); toast('Logo removed'); openAlbum({albumId:current.albumId,name:current.name});
  }catch(e){ toast(e.message,true); }
}
$('#lgBox').addEventListener('pointerdown',lgPointerDown);
window.addEventListener('pointermove',lgPointerMove);
window.addEventListener('pointerup',()=>{ lgState.drag=null; });
$('#lgOpacity').addEventListener('input',()=>{ $('#lgBox').style.opacity=(+$('#lgOpacity').value)/100; });
$('#lgApplyAll').addEventListener('click',()=>lgApply('all'));
$('#lgApplyOne').addEventListener('click',()=>lgApply('one'));
$('#lgRemove').addEventListener('click',lgRemove);
$('#lgClose').addEventListener('click',closeLogoModal);
$('#lgModal').addEventListener('click',e=>{ if(e.target.id==='lgModal') closeLogoModal(); });
document.addEventListener('keydown',e=>{ if(e.key==='Escape'&&$('#lgModal').classList.contains('open')) closeLogoModal(); });

/* ── Lightbox ── */
function openLightbox(src){ $('#lightboxImg').src=src; $('#lightbox').classList.add('open'); }
$('#lightbox').addEventListener('click',()=>$('#lightbox').classList.remove('open'));
document.addEventListener('keydown',e=>{ if(e.key==='Escape')$('#lightbox').classList.remove('open'); });

$('#signOut').addEventListener('click',()=>{ localStorage.removeItem('authToken'); location.replace('/'); });

/* ── Boot ── */
const _lcx=document.getElementById('lowCreditX'); if(_lcx) _lcx.addEventListener('click',()=>{ const b=document.getElementById('lowCreditBar'); if(b) b.hidden=true; });
loadCredits();
loadAlbums();
const _autoAlbum=new URLSearchParams(location.search).get('album');
if(_autoAlbum) openAlbum({albumId:_autoAlbum,name:''});
</script>
</body>
</html>
