const crypto = require('crypto');

const DB_URL = 'https://exchange-app-2cdeb-default-rtdb.europe-west1.firebasedatabase.app';

function deriveKey(secret, roomCode, party){
  return crypto.createHash('sha256').update(`${secret}:${roomCode}:${party}`).digest();
}
function decrypt(sealed, key){
  const [ivB64, tagB64, dataB64] = sealed.split('.');
  const iv = Buffer.from(ivB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');
  const data = Buffer.from(dataB64, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
}

exports.handler = async (event) => {
  if(event.httpMethod !== 'POST'){
    return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
  }
  try{
    const { roomCode, party } = JSON.parse(event.body || '{}'); // party = content owner being assessed
    if(!roomCode || (party !== 'A' && party !== 'B')){
      return { statusCode: 400, body: JSON.stringify({ error: 'roomCode and party (A or B) are required' }) };
    }
    const sealSecret = process.env.SEAL_SECRET;
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if(!sealSecret) return { statusCode: 500, body: JSON.stringify({ error: 'Server is missing SEAL_SECRET' }) };
    if(!apiKey) return { statusCode: 500, body: JSON.stringify({ error: 'Server is missing ANTHROPIC_API_KEY' }) };

    const roomRes = await fetch(`${DB_URL}/exchanges/${roomCode}.json`);
    if(!roomRes.ok) return { statusCode: 502, body: JSON.stringify({ error: 'Could not reach the room database' }) };
    const room = await roomRes.json();
    if(!room) return { statusCode: 404, body: JSON.stringify({ error: 'Room not found' }) };

    const owner = party === 'A' ? room.partyA : room.partyB;
    if(!owner || !owner.sealed){
      return { statusCode: 404, body: JSON.stringify({ error: 'No sealed content for that party yet' }) };
    }

    const key = deriveKey(sealSecret, roomCode, party);
    const plaintext = decrypt(owner.sealed, key);
    const promise = owner.offering || '(no description given)';

    const prompt = `You are checking one side of a two-party exchange before it is released. You will be shown two things: (1) what the person PROMISED they were giving, and (2) the ACTUAL content they submitted. Your job is to tell the other party — who cannot see the actual content yet — whether it plausibly matches the promise, in plain language.

Rules:
- NEVER quote or reproduce the actual content verbatim, in whole or in part, including passwords, keys, codes, or exact phrases from it. Describe it in your own words only.
- If the content contains what looks like a live credential (password, private key, seed phrase, API key, etc.), say so explicitly as a warning, and do not attempt to validate it further — just flag that a live secret is present.
- Judge plausibility and coherence: does this read like a genuine, complete version of what was promised, or does it look empty, garbled, off-topic, or suspiciously thin?
- Be concise: 2-4 sentences.

PROMISED: "${promise}"

ACTUAL CONTENT:
"""
${plaintext.slice(0, 6000)}
"""

Write your assessment now, addressed to the party who is deciding whether to proceed.`;

    const modelId = process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-5';
    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: modelId,
        max_tokens: 300,
        messages: [{ role: 'user', content: prompt }]
      })
    });
    const aiJson = await aiRes.json();
    if(!aiRes.ok){
      return { statusCode: 502, body: JSON.stringify({ error: 'AI assessment failed: ' + (aiJson.error?.message || aiRes.status) }) };
    }
    const textBlock = (aiJson.content || []).find(b => b.type === 'text');
    const assessment = textBlock ? textBlock.text : '(no assessment returned)';

    return { statusCode: 200, body: JSON.stringify({ assessment }) };
  }catch(e){
    return { statusCode: 500, body: JSON.stringify({ error: e.message }) };
  }
};
