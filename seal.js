const crypto = require('crypto');

function deriveKey(secret, roomCode, party){
  return crypto.createHash('sha256').update(`${secret}:${roomCode}:${party}`).digest();
}

exports.handler = async (event) => {
  if(event.httpMethod !== 'POST'){
    return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
  }
  try{
    const { roomCode, party, plaintext } = JSON.parse(event.body || '{}');
    if(!roomCode || !party || typeof plaintext !== 'string' || !plaintext.trim()){
      return { statusCode: 400, body: JSON.stringify({ error: 'roomCode, party, and plaintext are required' }) };
    }
    const secret = process.env.SEAL_SECRET;
    if(!secret){
      return { statusCode: 500, body: JSON.stringify({ error: 'Server is missing the SEAL_SECRET environment variable' }) };
    }

    const key = deriveKey(secret, roomCode, party);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    const sealed = [iv.toString('base64'), tag.toString('base64'), encrypted.toString('base64')].join('.');

    const trimmed = plaintext.trim();
    const words = trimmed.split(/\s+/).filter(Boolean).length;
    const preview = {
      chars: trimmed.length,
      words,
      firstBit: trimmed.slice(0, 2)
    };

    return { statusCode: 200, body: JSON.stringify({ sealed, preview }) };
  }catch(e){
    return { statusCode: 500, body: JSON.stringify({ error: e.message }) };
  }
};
