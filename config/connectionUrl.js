/**
 * Ensures Atlas-style hosts get mongodb+srv:// when the scheme was omitted in .env.
 */
export function normalizeConnectionUrl(raw) {
  if (!raw || typeof raw !== 'string') {
    return raw;
  }

  let uri = raw.trim();
  if (
    (uri.startsWith('"') && uri.endsWith('"')) ||
    (uri.startsWith("'") && uri.endsWith("'"))
  ) {
    uri = uri.slice(1, -1).trim();
  }

  if (/^mongodb(\+srv)?:\/\//i.test(uri)) {
    return uri;
  }

  const withoutSlashes = uri.replace(/^\/+/, '');

  if (
    withoutSlashes.includes('.mongodb.net') ||
    withoutSlashes.includes('.mongodb-dev.net')
  ) {
    return `mongodb+srv://${withoutSlashes}`;
  }

  return `mongodb://${withoutSlashes}`;
}
