const crypto = require('crypto');

const DB_URL = 'https://exchange-app-2cdeb-default-rtdb.europe-west1.firebasedatabase.app';
const SOLANA_RPC = 'https://api.mainnet-beta.solana.com';

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

async function rpc(method, params){
  const res = await fetch(SOLANA_RPC, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params })
  });
  const json = await res.json();
  if(json.error) throw new Error(json.error.message || 'Solana RPC error');
  return json.result;
}

// Looks for a confirmed transaction that touches the given reference account
// and pays at least minLamports to payoutWallet. This is the standard
// Solana Pay "reference" verification pattern.
async function paymentConfirmed(reference, payoutWallet, minLamports){
  let sigs;
  try{
    sigs = await rpc('getSignaturesForAddress', [reference, { limit: 10 }]);
  }catch(e){
    return false;
  }
  if(!sigs || sigs.length === 0) return false;

  for(const s of sigs){
    if(s.err) continue;
    let tx;
    try{
      tx = await rpc('getTransaction', [s.signature, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0 }]);
    }catch(e){ continue; }
    if(!tx || !tx.meta || tx.meta.err) continue;

    const keys = tx.transaction.message.accountKeys.map(k => (typeof k === 'string' ? k : k.pubkey));
    const idx = keys.indexOf(payoutWallet);
    if(idx === -1) continue;

    const pre = tx.meta.preBalances[idx];
    const post = tx.meta.postBalances[idx];
    if((post - pre) >= minLamports) return true;
  }
  return false;
}

exports.handler = async (event) => {
  if(event.httpMethod !== 'POST'){
    return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
  }
  try{
    // "party" = the CONTENT OWNER whose sealed content the caller wants revealed
    const { roomCode, party } = JSON.parse(event.body || '{}');
    if(!roomCode || (party !== 'A' && party !== 'B')){
      return { statusCode: 400, body: JSON.stringify({ error: 'roomCode and party (A or B) are required' }) };
    }
    const secret = process.env.SEAL_SECRET;
    if(!secret){
      return { statusCode: 500, body: JSON.stringify({ error: 'Server is missing the SEAL_SECRET environment variable' }) };
    }

    const roomRes = await fetch(`${DB_URL}/exchanges/${roomCode}.json`);
    if(!roomRes.ok){
      return { statusCode: 502, body: JSON.stringify({ error: 'Could not reach the room database' }) };
    }
    const room = await roomRes.json();
    if(!room){
      return { statusCode: 404, body: JSON.stringify({ error: 'Room not found' }) };
    }

    const owner = party === 'A' ? room.partyA : room.partyB;
    if(!owner || !owner.sealed){
      return { statusCode: 404, body: JSON.stringify({ error: 'No sealed content for that party yet' }) };
    }

    const priceLamports = Math.round((owner.priceSol || 0) * 1e9);
    if(priceLamports > 0){
      if(!owner.payoutWallet || !owner.paymentReference){
        return { statusCode: 400, body: JSON.stringify({ error: 'Payment terms are incomplete for this party' }) };
      }
      const paid = await paymentConfirmed(owner.paymentReference, owner.payoutWallet, priceLamports);
      if(!paid){
        return { statusCode: 402, body: JSON.stringify({ paid: false }) };
      }
    }

    const key = deriveKey(secret, roomCode, party);
    const plaintext = decrypt(owner.sealed, key);
    return { statusCode: 200, body: JSON.stringify({ paid: true, content: plaintext }) };
  }catch(e){
    return { statusCode: 500, body: JSON.stringify({ error: e.message }) };
  }
};
