const fs = require('node:fs');
const path = require('node:path');
function createSettingsStore(file, safeStorage) {
  function read() {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch (error) { if (error.code === 'ENOENT') return { maxPages: 10 }; throw new Error('Οι ρυθμίσεις δεν διαβάζονται. Έλεγξε το αρχείο settings.json.'); }
  }
  function publicSettings() {
    const raw = read();
    return { maxPages: Number.isInteger(raw.maxPages) ? raw.maxPages : 10, hasApiKey: Boolean(raw.apiKeyEncrypted) };
  }
  function key() {
    const raw = read(); if (!raw.apiKeyEncrypted) return '';
    if (!safeStorage.isEncryptionAvailable()) throw new Error('Η ασφαλής αποθήκευση κλειδιού δεν είναι διαθέσιμη.');
    try { return safeStorage.decryptString(Buffer.from(raw.apiKeyEncrypted, 'base64')); }
    catch { throw new Error('Το αποθηκευμένο κλειδί δεν αποκρυπτογραφείται. Αποθήκευσε νέο κλειδί.'); }
  }
  function save(value) {
    if (!value || typeof value !== 'object' || !Number.isInteger(value.maxPages) || value.maxPages < 1 || value.maxPages > 20) throw new Error('Οι σελίδες πρέπει να είναι ακέραιος από 1 έως 20.');
    if (value.apiKey !== undefined && (typeof value.apiKey !== 'string' || value.apiKey.length > 512)) throw new Error('Μη έγκυρο API key.');
    const raw = read(), clean = { maxPages: value.maxPages };
    if (raw.apiKeyEncrypted && value.clearApiKey !== true) clean.apiKeyEncrypted = raw.apiKeyEncrypted;
    if (value.apiKey?.trim()) {
      if (!safeStorage.isEncryptionAvailable()) throw new Error('Η ασφαλής κρυπτογράφηση δεν είναι διαθέσιμη.');
      clean.apiKeyEncrypted = safeStorage.encryptString(value.apiKey.trim()).toString('base64');
    }
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const temp = file + '.tmp';
    fs.writeFileSync(temp, JSON.stringify(clean, null, 2), { mode: 0o600 });
    fs.renameSync(temp, file);
    return publicSettings();
  }
  return { publicSettings, key, save };
}
module.exports = { createSettingsStore };

