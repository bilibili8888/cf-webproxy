const TAGS = new Set([0xefefefef, 0xeeeeeeee, 0xdddddddd]);
export const TELEGRAM_DCS = Object.freeze({1:"149.154.175.50",2:"149.154.167.51",3:"149.154.175.100",4:"149.154.167.91",5:"149.154.171.5"});

export class AesCtrStream {
  constructor(keyBytes, ivBytes) {
    if (keyBytes.length !== 32 || ivBytes.length !== 16) throw new Error("bad AES material");
    this.keyPromise = crypto.subtle.importKey("raw", keyBytes, "AES-CTR", false, ["encrypt"]);
    this.counter = new Uint8Array(ivBytes);
    this.offset = 0; // bytes already consumed inside the current 16-byte keystream block
  }
  // Let the native AES-CTR encrypt the data directly (no JS XOR loop).
  // Stream position is updated synchronously, so call order alone fixes the keystream position.
  async crypt(input) {
    const src = input instanceof Uint8Array ? input : new Uint8Array(input);
    if (!src.length) return new Uint8Array();
    const counter = this.counter.slice();
    const offset = this.offset;
    const total = offset + src.length;
    addBlocks(this.counter, Math.floor(total / 16));
    this.offset = total % 16;
    let data = src;
    if (offset) { data = new Uint8Array(total); data.set(src, offset); }
    const key = await this.keyPromise;
    const out = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CTR", counter, length: 128 }, key, data));
    return offset ? out.subarray(offset) : out;
  }
}

function addBlocks(counter, blocks) {
  let carry = blocks;
  for (let i=15;i>=0 && carry;i--) {
    const sum = counter[i] + (carry & 255);
    counter[i] = sum & 255;
    carry = Math.floor(carry / 256) + (sum >>> 8);
  }
}
function reverse(bytes){ return Uint8Array.from(bytes).reverse(); }
function concat(a,b){ const out=new Uint8Array(a.length+b.length); out.set(a); out.set(b,a.length); return out; }
async function sha256(bytes){ return new Uint8Array(await crypto.subtle.digest("SHA-256",bytes)); }
export function parseProxySecret(value) {
  const s=String(value||"").toLowerCase();
  if (/^[0-9a-f]{32}$/.test(s)) return {bridge:hex(s), inner:hex(s), mode:"plain"};
  if (/^dd[0-9a-f]{32}$/.test(s)) return {bridge:hex(s), inner:hex(s.slice(2)), mode:"dd"};
  if (/^ee/.test(s)) throw new Error("FakeTLS secrets are not supported in WEB mode");
  throw new Error("PROXY_SECRET must be 32 hex characters, optionally prefixed with dd");
}
function hex(s){ const x=new Uint8Array(s.length/2); for(let i=0;i<x.length;i++)x[i]=parseInt(s.slice(i*2,i*2+2),16); return x; }

export async function acceptClientHandshake(packet, secret) {
  if (packet.length !== 64) throw new Error("bad handshake length");
  const material = packet.subarray(8,56), rev=reverse(material);
  const decKey=await sha256(concat(material.subarray(0,32),secret));
  const dec=new AesCtrStream(decKey,material.subarray(32,48));
  const encKey=await sha256(concat(rev.subarray(0,32),secret));
  const enc=new AesCtrStream(encKey,rev.subarray(32,48));
  const plain=await dec.crypt(packet);
  const view=new DataView(plain.buffer,plain.byteOffset,plain.byteLength);
  const tag=view.getUint32(56,true), dcId=view.getInt16(60,true);
  if(!TAGS.has(tag) || !TELEGRAM_DCS[Math.abs(dcId)]) throw new Error("invalid MTProxy handshake");
  return {tag,dcId,clientDecrypt:dec,clientEncrypt:enc};
}

export async function createTelegramHandshake(tag, dcId) {
  let nonce;
  do { nonce=new Uint8Array(64); crypto.getRandomValues(nonce); } while (reserved(nonce));
  const v=new DataView(nonce.buffer); v.setUint32(56,tag,true); v.setInt16(60,dcId,true); nonce[62]=nonce[63]=0;
  const material=nonce.subarray(8,56), rev=reverse(material);
  const encrypt=new AesCtrStream(material.subarray(0,32),material.subarray(32,48));
  const decrypt=new AesCtrStream(rev.subarray(0,32),rev.subarray(32,48));
  const encrypted=await encrypt.crypt(nonce);
  const wire=new Uint8Array(nonce); wire.set(encrypted.subarray(56),56);
  return {wire,encrypt,decrypt};
}
function reserved(n){
  const v=new DataView(n.buffer,n.byteOffset,n.byteLength), x=v.getUint32(0,true);
  return n[0]===0xef || x===0x44414548 || x===0x54534f50 || x===0x20544547 || x===0xeeeeeeee || x===0xdddddddd || v.getUint32(4,true)===0;
}
