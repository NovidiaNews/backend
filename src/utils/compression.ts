import zlib from 'zlib';

/**
 * Compresses a string using gzip and returns a base64 encoded string.
 */
export function compress(text: string): string {
  const buffer = zlib.gzipSync(text);
  return buffer.toString('base64');
}

/**
 * Decompresses a base64 encoded gzip string back to a utf-8 string.
 */
export function decompress(base64: string): string {
  const buffer = Buffer.from(base64, 'base64');
  return zlib.gunzipSync(buffer).toString('utf-8');
}
