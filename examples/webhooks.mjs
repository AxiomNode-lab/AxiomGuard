// Verify provider webhooks and produce test signatures.
import {
  MemoryReplayStore,
  createSlackSignature,
  createStripeSignatureHeader,
  signHmacWebhook,
  verifyFreshHmacWebhook,
  verifyGitHubWebhookDelivery,
  verifySlackWebhook,
  verifyStandardWebhook,
  verifyStripeWebhook,
} from '../dist/index.js';

const replayStore = new MemoryReplayStore();
const body = JSON.stringify({ event: 'order.paid', id: 'ord_1' });
const now = Date.now();
const timestamp = Math.floor(now / 1000);

// GitHub: signature over the raw body + delivery id replay protection.
const githubSecret = 'github-secret';
const githubSignature = signHmacWebhook(body, githubSecret);
console.log('github', await verifyGitHubWebhookDelivery(body, githubSignature, githubSecret, 'delivery-1', { replayStore, now }));
console.log('github again', await verifyGitHubWebhookDelivery(body, githubSignature, githubSecret, 'delivery-1', { replayStore, now }));

// Stripe: literal t= text is signed together with the body.
const stripeSecret = 'whsec_example';
console.log('stripe', await verifyStripeWebhook(body, createStripeSignatureHeader(body, stripeSecret, timestamp), stripeSecret, { now, replayStore }));

// Slack: v0:timestamp:body.
const slackSecret = 'slack-signing-secret';
console.log('slack', await verifySlackWebhook(body, createSlackSignature(body, slackSecret, timestamp), timestamp, slackSecret, { now, replayStore }));

// Standard Webhooks (Svix): id.timestamp.body with whsec_ base64 secrets.
const standardSecret = `whsec_${Buffer.from('0123456789abcdef0123456789abcdef').toString('base64')}`;
const standardSignature = `v1,${signHmacWebhook(`msg_1.${timestamp}.${body}`, Buffer.from('0123456789abcdef0123456789abcdef'), { encoding: 'base64', prefix: '' })}`;
console.log('standard', await verifyStandardWebhook(body, { id: 'msg_1', timestamp, signature: standardSignature }, standardSecret, { now, replayStore }));

// Any other provider: generic HMAC with a separate timestamp header, binding the timestamp into the signature.
const genericSecret = 'generic-secret';
const genericSignature = signHmacWebhook(`${timestamp}.${body}`, genericSecret);
console.log('generic', await verifyFreshHmacWebhook({ payload: body, signature: genericSignature, secret: genericSecret, timestamp }, { now, replayStore, signedInput: 'timestamp.payload' }));
