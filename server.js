const dns = require('dns');
dns.setDefaultResultOrder('ipv4first');

const express = require('express');
const axios = require('axios');
const FormData = require('form-data');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');
const Stripe = require('stripe');

const app = express();
const upload = multer();

const N8N_BASE_URL = 'https://courteous-solace-production-413f.up.railway.app';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

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
app.post('/api/enhance', requireAuth, upload.array('images'), async (req, res) => {
  const imageCount = req.files?.length || 1;
  const creditsNeeded = imageCount * CREDIT_COSTS.enhance;

  const deducted = await deductCredits(
    req.user.id,
    creditsNeeded,
    'enhance',
    `Enhanced ${imageCount} image(s)`
  );
  if (!deducted) return res.status(402).json({ error: 'Insufficient credits' });

  try {
    const n8nUrl = `${N8N_BASE_URL}/webhook/Batch_EnhancementOptionsWeb`;
    const form = new FormData();
    form.append('back_plane', req.body.back_plane || '');
    form.append('time_of_day', req.body.time_of_day || '');
    form.append('paver_style', req.body.paver_style || '');
    form.append('paver_pattern', req.body.paver_pattern || '');
    form.append('image_quality', req.body.image_quality || '');
    form.append('user_email', req.user.email || '');
    form.append('user_id', req.user.id || '');
    if (req.files?.length > 0) {
      req.files.forEach(file => {
        form.append('images', file.buffer, {
          filename: file.originalname,
          contentType: file.mimetype
        });
      });
    }
    const response = await axios.post(n8nUrl, form, {
      headers: { ...form.getHeaders() },
      maxContentLength: Infinity,
      maxBodyLength: Infinity
    });
    const responseData = response.data;
    if (!responseData.jobId) {
      console.warn('Warning: n8n responded without a jobId.');
    }
    return res.status(200).json(responseData);
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

// ── Upscale Proxy (no credit charge) ─────────────────────────────────────────
app.post('/api/upscale', requireAuth, async (req, res) => {
  try {
    const n8nUrl = `${N8N_BASE_URL}/webhook/upscale_image`;
    const response = await axios.post(n8nUrl, {
      image_url: req.body.imageUrl,
      job_id: req.body.jobId,
      image_index: req.body.imageIndex,
      user_email: req.user.email,
      output_quality: req.body.outputQuality || 80
    }, {
      headers: { 'Content-Type': 'application/json' }
    });
    return res.status(200).json(response.data);
  } catch (error) {
    console.error('Upscale error:', error.response?.data || error.message);
    return res.status(500).json({ error: 'Upscale request failed' });
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
