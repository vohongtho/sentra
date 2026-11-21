// Private object storage for raw SBOMs, imports and evidence. S3-compatible when S3_BUCKET is set;
// local filesystem otherwise (development). Keys are content-addressed per org/project.
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

export async function createObjectStore(cfg) {
  if (cfg.s3.bucket) {
    const { S3Client, PutObjectCommand, GetObjectCommand } = await import('@aws-sdk/client-s3');
    const client = new S3Client({ region: cfg.s3.region, ...(cfg.s3.endpoint ? { endpoint: cfg.s3.endpoint, forcePathStyle: true } : {}) });
    return {
      kind: 's3',
      async put(key, body, contentType = 'application/octet-stream') { await client.send(new PutObjectCommand({ Bucket: cfg.s3.bucket, Key: key, Body: body, ContentType: contentType, ServerSideEncryption: 'AES256' })); return key; },
      async get(key) { const r = await client.send(new GetObjectCommand({ Bucket: cfg.s3.bucket, Key: key })); return Buffer.from(await r.Body.transformToByteArray()); },
    };
  }
  const root = cfg.objectStoreDir || path.join(os.tmpdir(), 'sentra-objects');
  return {
    kind: 'filesystem',
    root,
    async put(key, body) {
      const safe = path.normalize(key).replace(/^(\.\.(\/|\\|$))+/, '');
      const file = path.join(root, safe);
      await mkdir(path.dirname(file), { recursive: true });
      await writeFile(file, body, { mode: 0o600 });
      return safe;
    },
    async get(key) { return readFile(path.join(root, path.normalize(key).replace(/^(\.\.(\/|\\|$))+/, ''))); },
  };
}
