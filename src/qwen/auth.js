const path = require('path');
const { promises: fs, unlinkSync } = require('fs');
const { fetch } = require('undici');
const crypto = require('crypto');
const open = require('open');
const os = require('os');

let telegramNotifier;
try {
  telegramNotifier = require('../utils/telegramNotifier.js');
} catch (e) {
  telegramNotifier = null;
}

const QWEN_DIR = '.qwen';
const QWEN_CREDENTIAL_FILENAME = 'oauth_creds.json';
const QWEN_MULTI_ACCOUNT_PREFIX = 'oauth_creds_';
const QWEN_MULTI_ACCOUNT_SUFFIX = '.json';
const QWEN_LOCK_FILENAME = 'oauth_creds.lock';

const QWEN_OAUTH_BASE_URL = 'https://chat.qwen.ai';
const QWEN_OAUTH_DEVICE_CODE_ENDPOINT = `${QWEN_OAUTH_BASE_URL}/api/v1/oauth2/device/code`;
const QWEN_OAUTH_TOKEN_ENDPOINT = `${QWEN_OAUTH_BASE_URL}/api/v1/oauth2/token`;
const QWEN_OAUTH_CLIENT_ID = 'f0304373b74a44d2b584a3fb70ca9e56';
const QWEN_OAUTH_SCOPE = 'openid profile email model.completion';
const QWEN_OAUTH_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';
const TOKEN_REFRESH_BUFFER_MS = 5 * 60 * 1000;
const LOCK_TIMEOUT_MS = 10000;
const CACHE_CHECK_INTERVAL_MS = 5000;

const DEFAULT_LOCK_CONFIG = {
  maxAttempts: 20,
  attemptInterval: 100,
  maxInterval: 2000,
};

function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(codeVerifier) {
  const hash = crypto.createHash('sha256');
  hash.update(codeVerifier);
  return hash.digest('base64url');
}

function generatePKCEPair() {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  return { code_verifier: codeVerifier, code_challenge: codeChallenge };
}

function randomUUID() {
  return crypto.randomUUID();
}

class TokenManagerError extends Error {
  constructor(type, message, originalError) {
    super(message);
    this.name = 'TokenManagerError';
    this.type = type;
    this.originalError = originalError;
  }
}

const TokenError = {
  REFRESH_FAILED: 'REFRESH_FAILED',
  NO_REFRESH_TOKEN: 'NO_REFRESH_TOKEN',
  LOCK_TIMEOUT: 'LOCK_TIMEOUT',
  FILE_ACCESS_ERROR: 'FILE_ACCESS_ERROR',
  NETWORK_ERROR: 'NETWORK_ERROR',
};

class CredentialsClearRequiredError extends Error {
  constructor(message, originalError) {
    super(message);
    this.name = 'CredentialsClearRequiredError';
    this.originalError = originalError;
  }
}

class SharedTokenManager {
  constructor() {
    this.memoryCache = {
      credentials: null,
      fileModTime: 0,
      lastCheck: 0,
    };
    this.refreshPromise = null;
    this.checkPromise = null;
    this.cleanupHandlersRegistered = false;
    this.cleanupFunction = null;
    this.lockConfig = { ...DEFAULT_LOCK_CONFIG };
    this.registerCleanupHandlers();
  }

  static instance = null;

  static getInstance() {
    if (!SharedTokenManager.instance) {
      SharedTokenManager.instance = new SharedTokenManager();
    }
    return SharedTokenManager.instance;
  }

  registerCleanupHandlers() {
    if (this.cleanupHandlersRegistered) return;

    this.cleanupFunction = () => {
      try {
        const lockPath = this.getLockFilePath();
        unlinkSync(lockPath);
      } catch (_error) {}
    };

    process.on('exit', this.cleanupFunction);
    process.on('SIGINT', this.cleanupFunction);
    process.on('SIGTERM', this.cleanupFunction);
    process.on('uncaughtException', this.cleanupFunction);
    process.on('unhandledRejection', this.cleanupFunction);

    this.cleanupHandlersRegistered = true;
  }

  async getValidCredentials(qwenClient, forceRefresh = false) {
    try {
      await this.checkAndReloadIfNeeded(qwenClient);

      if (
        !forceRefresh &&
        this.memoryCache.credentials &&
        this.isTokenValid(this.memoryCache.credentials)
      ) {
        return this.memoryCache.credentials;
      }

      let currentRefreshPromise = this.refreshPromise;

      if (!currentRefreshPromise) {
        currentRefreshPromise = this.performTokenRefresh(qwenClient, forceRefresh);
        this.refreshPromise = currentRefreshPromise;
      }

      try {
        const result = await currentRefreshPromise;
        return result;
      } finally {
        if (this.refreshPromise === currentRefreshPromise) {
          this.refreshPromise = null;
        }
      }
    } catch (error) {
      if (error instanceof TokenManagerError) {
        throw error;
      }
      throw new TokenManagerError(
        TokenError.REFRESH_FAILED,
        `Failed to get valid credentials: ${error instanceof Error ? error.message : String(error)}`,
        error,
      );
    }
  }

  async checkAndReloadIfNeeded(qwenClient) {
    if (this.checkPromise) {
      await this.checkPromise;
      return;
    }

    if (this.refreshPromise) {
      return;
    }

    const now = Date.now();

    if (now - this.memoryCache.lastCheck < CACHE_CHECK_INTERVAL_MS) {
      return;
    }

    this.checkPromise = this.performFileCheck(qwenClient, now);

    try {
      await this.checkPromise;
    } finally {
      this.checkPromise = null;
    }
  }

  withTimeout(promise, timeoutMs, operationType = 'Operation') {
    let timeoutId;
    return Promise.race([
      promise.finally(() => {
        if (timeoutId) {
          clearTimeout(timeoutId);
        }
      }),
      new Promise((_, reject) => {
        timeoutId = setTimeout(
          () => reject(new Error(`${operationType} timed out after ${timeoutMs}ms`)),
          timeoutMs,
        );
      }),
    ]);
  }

  async performFileCheck(qwenClient, checkTime) {
    this.memoryCache.lastCheck = checkTime;

    try {
      const filePath = this.getCredentialFilePath();

      const stats = await this.withTimeout(fs.stat(filePath), 3000, 'File operation');
      const fileModTime = stats.mtimeMs;

      if (fileModTime > this.memoryCache.fileModTime) {
        await this.reloadCredentialsFromFile(qwenClient);
        this.memoryCache.fileModTime = fileModTime;
      }
    } catch (error) {
      if (error instanceof Error && 'code' in error && error.code !== 'ENOENT') {
        this.updateCacheState(null, 0, checkTime);
        throw new TokenManagerError(
          TokenError.FILE_ACCESS_ERROR,
          `Failed to access credentials file: ${error.message}`,
          error,
        );
      }
      this.memoryCache.fileModTime = 0;
    }
  }

  async forceFileCheck(qwenClient) {
    try {
      const filePath = this.getCredentialFilePath();
      const stats = await fs.stat(filePath);
      const fileModTime = stats.mtimeMs;

      if (fileModTime > this.memoryCache.fileModTime) {
        await this.reloadCredentialsFromFile(qwenClient);
        this.memoryCache.fileModTime = fileModTime;
        this.memoryCache.lastCheck = Date.now();
      }
    } catch (error) {
      if (error instanceof Error && 'code' in error && error.code !== 'ENOENT') {
        this.updateCacheState(null, 0);
        throw new TokenManagerError(
          TokenError.FILE_ACCESS_ERROR,
          `Failed to access credentials file during refresh: ${error.message}`,
          error,
        );
      }
      this.memoryCache.fileModTime = 0;
    }
  }

  async reloadCredentialsFromFile(qwenClient) {
    try {
      const filePath = this.getCredentialFilePath();
      const content = await fs.readFile(filePath, 'utf-8');
      const parsedData = JSON.parse(content);
      const credentials = this.validateCredentials(parsedData);

      const previousCredentials = this.memoryCache.credentials;

      this.memoryCache.credentials = credentials;

      try {
        if (qwenClient) {
          qwenClient.setCredentials(credentials);
        }
      } catch (clientError) {
        this.memoryCache.credentials = previousCredentials;
        throw clientError;
      }
    } catch (error) {
      if (error instanceof Error && error.message.includes('Invalid credentials')) {
        console.warn(`Failed to validate credentials file: ${error.message}`);
      }
      this.memoryCache.credentials = null;
    }
  }

  validateCredentials(data) {
    if (!data || typeof data !== 'object') {
      throw new Error('Invalid credentials format');
    }

    const requiredFields = ['access_token', 'refresh_token', 'token_type'];
    for (const field of requiredFields) {
      if (!data[field] || typeof data[field] !== 'string') {
        throw new Error(`Invalid credentials: missing ${field}`);
      }
    }

    if (!data.expiry_date || typeof data.expiry_date !== 'number') {
      throw new Error('Invalid credentials: missing expiry_date');
    }

    return data;
  }

  async performTokenRefresh(qwenClient, forceRefresh = false) {
    const startTime = Date.now();
    const lockPath = this.getLockFilePath();

    try {
      const currentCredentials = qwenClient.getCredentials();
      if (!currentCredentials.refresh_token) {
        throw new TokenManagerError(
          TokenError.NO_REFRESH_TOKEN,
          'No refresh token available for token refresh',
        );
      }

      await this.acquireLock(lockPath);

      const lockAcquisitionTime = Date.now() - startTime;
      if (lockAcquisitionTime > 5000) {
        console.warn(`Token refresh lock acquisition took ${lockAcquisitionTime}ms`);
      }

      await this.forceFileCheck(qwenClient);

      if (
        !forceRefresh &&
        this.memoryCache.credentials &&
        this.isTokenValid(this.memoryCache.credentials)
      ) {
        return this.memoryCache.credentials;
      }

      const response = await qwenClient.refreshAccessToken();

      const totalOperationTime = Date.now() - startTime;
      if (totalOperationTime > 10000) {
        console.warn(`Token refresh operation took ${totalOperationTime}ms`);
      }

      if (!response || response.error) {
        const errorData = response || {};
        throw new TokenManagerError(
          TokenError.REFRESH_FAILED,
          `Token refresh failed: ${errorData.error || 'Unknown error'} - ${errorData.error_description || 'No details provided'}`,
        );
      }

      if (!response.access_token) {
        throw new TokenManagerError(
          TokenError.REFRESH_FAILED,
          'Failed to refresh access token: no token returned',
        );
      }

      const tokenData = response;
      const credentials = {
        access_token: tokenData.access_token,
        token_type: tokenData.token_type,
        refresh_token: tokenData.refresh_token || currentCredentials.refresh_token,
        resource_url: tokenData.resource_url,
        expiry_date: Date.now() + tokenData.expires_in * 1000,
      };

      this.memoryCache.credentials = credentials;
      qwenClient.setCredentials(credentials);

      await this.saveCredentialsToFile(credentials);

      return credentials;
    } catch (error) {
      if (error instanceof CredentialsClearRequiredError) {
        console.debug('SharedTokenManager: Clearing memory cache due to credentials clear requirement');
        this.memoryCache.credentials = null;
        this.memoryCache.fileModTime = 0;
        this.refreshPromise = null;

        throw new TokenManagerError(
          TokenError.REFRESH_FAILED,
          error.message,
          error,
        );
      }

      if (error instanceof TokenManagerError) {
        throw error;
      }

      if (
        error instanceof Error &&
        (error.message.includes('fetch') ||
          error.message.includes('network') ||
          error.message.includes('timeout'))
      ) {
        throw new TokenManagerError(
          TokenError.NETWORK_ERROR,
          `Network error during token refresh: ${error.message}`,
          error,
        );
      }

      throw new TokenManagerError(
        TokenError.REFRESH_FAILED,
        `Unexpected error during token refresh: ${error instanceof Error ? error.message : String(error)}`,
        error,
      );
    } finally {
      await this.releaseLock(lockPath);
    }
  }

  async saveCredentialsToFile(credentials) {
    const filePath = this.getCredentialFilePath();
    const dirPath = path.dirname(filePath);
    const tempPath = `${filePath}.tmp.${randomUUID()}`;

    try {
      await this.withTimeout(
        fs.mkdir(dirPath, { recursive: true, mode: 0o700 }),
        5000,
        'File operation',
      );
    } catch (error) {
      throw new TokenManagerError(
        TokenError.FILE_ACCESS_ERROR,
        `Failed to create credentials directory: ${error instanceof Error ? error.message : String(error)}`,
        error,
      );
    }

    const credString = JSON.stringify(credentials, null, 2);

    try {
      await this.withTimeout(
        fs.writeFile(tempPath, credString, { mode: 0o600 }),
        5000,
        'File operation',
      );

      await this.withTimeout(fs.rename(tempPath, filePath), 5000, 'File operation');

      const stats = await this.withTimeout(fs.stat(filePath), 5000, 'File operation');
      this.memoryCache.fileModTime = stats.mtimeMs;
    } catch (error) {
      try {
        await this.withTimeout(fs.unlink(tempPath), 1000, 'File operation');
      } catch (_cleanupError) {}

      throw new TokenManagerError(
        TokenError.FILE_ACCESS_ERROR,
        `Failed to write credentials file: ${error instanceof Error ? error.message : String(error)}`,
        error,
      );
    }
  }

  isTokenValid(credentials) {
    if (!credentials.expiry_date || !credentials.access_token) {
      return false;
    }
    return Date.now() < credentials.expiry_date - TOKEN_REFRESH_BUFFER_MS;
  }

  getCredentialFilePath() {
    return path.join(os.homedir(), QWEN_DIR, QWEN_CREDENTIAL_FILENAME);
  }

  getLockFilePath() {
    return path.join(os.homedir(), QWEN_DIR, QWEN_LOCK_FILENAME);
  }

  async acquireLock(lockPath) {
    const { maxAttempts, attemptInterval, maxInterval } = this.lockConfig;
    const lockId = randomUUID();

    let currentInterval = attemptInterval;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        await fs.writeFile(lockPath, lockId, { flag: 'wx' });
        return;
      } catch (error) {
        if (error.code === 'EEXIST') {
          try {
            const stats = await fs.stat(lockPath);
            const lockAge = Date.now() - stats.mtimeMs;

            if (lockAge > LOCK_TIMEOUT_MS) {
              const tempPath = `${lockPath}.stale.${randomUUID()}`;
              try {
                await fs.rename(lockPath, tempPath);
                await fs.unlink(tempPath);
                console.warn(`Removed stale lock file: ${lockPath} (age: ${lockAge}ms)`);
                continue;
              } catch (renameError) {
                console.warn(`Failed to remove stale lock file ${lockPath}: ${renameError instanceof Error ? renameError.message : String(renameError)}`);
              }
            }
          } catch (statError) {
            console.warn(`Failed to stat lock file ${lockPath}: ${statError instanceof Error ? statError.message : String(statError)}`);
          }

          await new Promise((resolve) => setTimeout(resolve, currentInterval));
          currentInterval = Math.min(currentInterval * 1.5, maxInterval);
        } else {
          throw new TokenManagerError(
            TokenError.FILE_ACCESS_ERROR,
            `Failed to create lock file: ${error instanceof Error ? error.message : String(error)}`,
            error,
          );
        }
      }
    }

    throw new TokenManagerError(
      TokenError.LOCK_TIMEOUT,
      'Failed to acquire file lock for token refresh: timeout exceeded',
    );
  }

  async releaseLock(lockPath) {
    try {
      await fs.unlink(lockPath);
    } catch (error) {
      if (error.code !== 'ENOENT') {
        console.warn(`Failed to release lock file ${lockPath}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }

  updateCacheState(credentials, fileModTime, lastCheck) {
    this.memoryCache = {
      credentials,
      fileModTime,
      lastCheck: lastCheck ?? Date.now(),
    };
  }

  clearCache() {
    this.updateCacheState(null, 0, 0);
    this.refreshPromise = null;
    this.checkPromise = null;
  }

  getCurrentCredentials() {
    return this.memoryCache.credentials;
  }

  isRefreshInProgress() {
    return this.refreshPromise !== null;
  }

  setLockConfig(config) {
    this.lockConfig = { ...DEFAULT_LOCK_CONFIG, ...config };
  }
}

class QwenOAuth2Client {
  constructor() {
    this.credentials = {};
    this.sharedManager = SharedTokenManager.getInstance();
  }

  setCredentials(credentials) {
    this.credentials = credentials;
  }

  getCredentials() {
    return this.credentials;
  }

  async getAccessToken() {
    try {
      const credentials = await this.sharedManager.getValidCredentials(this);
      return { token: credentials.access_token };
    } catch (error) {
      console.warn('Failed to get access token from shared manager:', error.message);
      return { token: undefined };
    }
  }

  async requestDeviceAuthorization(options) {
    const bodyData = {
      client_id: QWEN_OAUTH_CLIENT_ID,
      scope: options.scope,
      code_challenge: options.code_challenge,
      code_challenge_method: options.code_challenge_method,
    };

    const response = await fetch(QWEN_OAUTH_DEVICE_CODE_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
        'x-request-id': randomUUID(),
      },
      body: Object.keys(bodyData)
        .map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(bodyData[key])}`)
        .join('&'),
    });

    if (!response.ok) {
      const errorData = await response.text();
      throw new Error(`Device authorization failed: ${response.status} ${response.statusText}. Response: ${errorData}`);
    }

    const result = await response.json();

    if (!result.device_code) {
      throw new Error(`Device authorization failed: ${result.error || 'Unknown error'} - ${result.error_description || 'No details provided'}`);
    }

    return result;
  }

  async pollDeviceToken(options) {
    const bodyData = {
      grant_type: QWEN_OAUTH_GRANT_TYPE,
      client_id: QWEN_OAUTH_CLIENT_ID,
      device_code: options.device_code,
      code_verifier: options.code_verifier,
    };

    const response = await fetch(QWEN_OAUTH_TOKEN_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: Object.keys(bodyData)
        .map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(bodyData[key])}`)
        .join('&'),
    });

    if (!response.ok) {
      const responseText = await response.text();

      let errorData = null;
      try {
        errorData = JSON.parse(responseText);
      } catch (_parseError) {
        const error = new Error(`Device token poll failed: ${response.status} ${response.statusText}. Response: ${responseText}`);
        error.status = response.status;
        throw error;
      }

      if (response.status === 400 && errorData.error === 'authorization_pending') {
        return { status: 'pending' };
      }

      if (response.status === 429 && errorData.error === 'slow_down') {
        return { status: 'pending', slowDown: true };
      }

      const error = new Error(`Device token poll failed: ${errorData.error || 'Unknown error'} - ${errorData.error_description}`);
      error.status = response.status;
      throw error;
    }

    return await response.json();
  }

  async refreshAccessToken() {
    if (!this.credentials.refresh_token) {
      throw new Error('No refresh token available');
    }

    const bodyData = {
      grant_type: 'refresh_token',
      refresh_token: this.credentials.refresh_token,
      client_id: QWEN_OAUTH_CLIENT_ID,
    };

    const response = await fetch(QWEN_OAUTH_TOKEN_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: Object.keys(bodyData)
        .map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(bodyData[key])}`)
        .join('&'),
    });

    if (!response.ok) {
      const errorData = await response.text();

      if (response.status === 400) {
        await clearQwenCredentials();
        throw new CredentialsClearRequiredError(
          'Refresh token expired or invalid. Please use /auth to re-authenticate.',
          { status: response.status, response: errorData },
        );
      }
      throw new Error(`Token refresh failed: ${response.status} ${response.statusText}. Response: ${errorData}`);
    }

    const responseData = await response.json();

    if (responseData.error) {
      throw new Error(`Token refresh failed: ${responseData.error || 'Unknown error'} - ${responseData.error_description || 'No details provided'}`);
    }

    const tokenData = responseData;
    const tokens = {
      access_token: tokenData.access_token,
      token_type: tokenData.token_type,
      refresh_token: tokenData.refresh_token || this.credentials.refresh_token,
      resource_url: tokenData.resource_url,
      expiry_date: Date.now() + tokenData.expires_in * 1000,
    };

    this.setCredentials(tokens);

    return responseData;
  }
}

async function clearQwenCredentials(accountId = 'default') {
  const filePath = path.join(os.homedir(), QWEN_DIR, QWEN_CREDENTIAL_FILENAME);
  try {
    await fs.unlink(filePath);
    console.debug('Cached Qwen credentials cleared successfully.');

    if (telegramNotifier?.notifyCredentialsCleared) {
      telegramNotifier.notifyCredentialsCleared(
        accountId,
        'Refresh token expired/invalid (400 error from OAuth server)'
      );
    }
  } catch (error) {
    if (error instanceof Error && error.code === 'ENOENT') {
      return;
    }
    console.warn('Warning: Failed to clear cached Qwen credentials:', error.message);
  } finally {
    try {
      SharedTokenManager.getInstance().clearCache();
    } catch {}
  }
}

async function cacheQwenCredentials(credentials) {
  const filePath = path.join(os.homedir(), QWEN_DIR, QWEN_CREDENTIAL_FILENAME);
  try {
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    const credString = JSON.stringify(credentials, null, 2);
    await fs.writeFile(filePath, credString);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorCode = error instanceof Error && 'code' in error ? error.code : undefined;

    if (errorCode === 'EACCES') {
      throw new Error(`Failed to cache credentials: Permission denied (EACCES). Current user has no permission to access \`${filePath}\`. Please check permissions.`);
    }

    throw new Error(`Failed to cache credentials: error when creating folder \`${path.dirname(filePath)}\` and writing to \`${filePath}\`. ${errorMessage}. Please check permissions.`);
  }
}

class QwenAuthManager {
  constructor() {
    this.qwenDir = path.join(process.env.HOME || process.env.USERPROFILE, QWEN_DIR);
    this.credentialsPath = path.join(this.qwenDir, QWEN_CREDENTIAL_FILENAME);
    this.credentials = null;
    this.refreshPromise = null;
    this.accounts = new Map();
    this.currentAccountIndex = 0;
    this.qwenClient = new QwenOAuth2Client();
    this.sharedManager = SharedTokenManager.getInstance();
  }

  init(qwenAPI) {
    this.qwenAPI = qwenAPI;
  }

  async loadCredentials() {
    const config = require('../config.js');
    if (config.qwenCodeAuthUse === false) {
      return null;
    }

    if (this.credentials) {
      return this.credentials;
    }
    try {
      const credentialsData = await fs.readFile(this.credentialsPath, 'utf8');
      this.credentials = JSON.parse(credentialsData);
      this.qwenClient.setCredentials(this.credentials);
      return this.credentials;
    } catch (error) {
      return null;
    }
  }

  async loadAllAccounts() {
    try {
      this.accounts.clear();

      const files = await fs.readdir(this.qwenDir);

      const accountFiles = files.filter(
        (file) =>
          file.startsWith(QWEN_MULTI_ACCOUNT_PREFIX) &&
          file.endsWith(QWEN_MULTI_ACCOUNT_SUFFIX) &&
          file !== QWEN_CREDENTIAL_FILENAME,
      );

      const config = require('../config.js');
      try {
        const defaultAuthExists = await fs.access(this.credentialsPath).then(() => true).catch(() => false);

        if (defaultAuthExists && accountFiles.length > 0 && config.qwenCodeAuthUse !== false) {
          console.log('\n\x1b[31m%s\x1b[0m', '[PROXY WARNING] Conflicting authentication files detected!');
          console.log('\x1b[31m%s\x1b[0m', 'Found both default ~/.qwen/oauth_creds.json (created by qwen-code) and named account file(s) ~/.qwen/oauth_creds_<name>.json');
          console.log('\x1b[31m%s\x1b[0m', 'If these were created with the same account, token refresh conflicts will occur, invalidating the other file.');
          console.log('\x1b[31m%s\x1b[0m', 'Solution: Set QWEN_CODE_AUTH_USE=false in your .env file, or remove the default auth file.');
        }
      } catch (checkError) {}

      for (const file of accountFiles) {
        try {
          const accountPath = path.join(this.qwenDir, file);
          const credentialsData = await fs.readFile(accountPath, 'utf8');
          const credentials = JSON.parse(credentialsData);

          const accountId = file.substring(
            QWEN_MULTI_ACCOUNT_PREFIX.length,
            file.length - QWEN_MULTI_ACCOUNT_SUFFIX.length,
          );

          this.accounts.set(accountId, credentials);
        } catch (error) {
          console.warn(`Failed to load account from ${file}:`, error.message);
        }
      }

      return this.accounts;
    } catch (error) {
      console.warn('Failed to load multi-account credentials:', error.message);
      return this.accounts;
    }
  }

  async saveCredentials(credentials, accountId = null) {
    try {
      const credString = JSON.stringify(credentials, null, 2);

      if (accountId) {
        const accountFilename = `${QWEN_MULTI_ACCOUNT_PREFIX}${accountId}${QWEN_MULTI_ACCOUNT_SUFFIX}`;
        const accountPath = path.join(this.qwenDir, accountFilename);
        await fs.writeFile(accountPath, credString, { mode: 0o600 });
        this.accounts.set(accountId, credentials);
      } else {
        await fs.writeFile(this.credentialsPath, credString, { mode: 0o600 });
        this.credentials = credentials;
        this.qwenClient.setCredentials(credentials);
      }
    } catch (error) {
      console.error('Error saving credentials:', error.message);
    }
  }

  isTokenValid(credentials) {
    if (!credentials || !credentials.access_token || !credentials.expiry_date) {
      return false;
    }

    if (typeof credentials.access_token !== 'string' || credentials.access_token.length === 0) {
      console.warn('Invalid access token format');
      return false;
    }

    if (isNaN(credentials.expiry_date) || credentials.expiry_date <= 0) {
      console.warn('Invalid expiry date');
      return false;
    }

    return Date.now() < credentials.expiry_date - TOKEN_REFRESH_BUFFER_MS;
  }

  getAccountIds() {
    return Array.from(this.accounts.keys());
  }

  getAccountCredentials(accountId) {
    return this.accounts.get(accountId) || null;
  }

  async addAccount(credentials, accountId) {
    await this.saveCredentials(credentials, accountId);
  }

  async removeAccount(accountId) {
    try {
      const accountFilename = `${QWEN_MULTI_ACCOUNT_PREFIX}${accountId}${QWEN_MULTI_ACCOUNT_SUFFIX}`;
      const accountPath = path.join(this.qwenDir, accountFilename);

      await fs.unlink(accountPath);
      this.accounts.delete(accountId);

      console.log(`Account ${accountId} removed successfully`);
    } catch (error) {
      console.error(`Error removing account ${accountId}:`, error.message);
      throw error;
    }
  }

  async refreshAccessToken(credentials) {
    console.log('\x1b[33m%s\x1b[0m', 'Refreshing Qwen access token...');

    if (!credentials || !credentials.refresh_token) {
      throw new Error('No refresh token available. Please re-authenticate with the Qwen CLI.');
    }

    this.qwenClient.setCredentials(credentials);

    try {
      const response = await this.qwenClient.refreshAccessToken();

      if (response.error) {
        throw new Error(`Token refresh failed: ${response.error} - ${response.error_description}`);
      }

      const newCredentials = {
        ...credentials,
        access_token: response.access_token,
        token_type: response.token_type,
        refresh_token: response.refresh_token || credentials.refresh_token,
        resource_url: response.resource_url || credentials.resource_url,
        expiry_date: Date.now() + response.expires_in * 1000,
      };

      console.log('\x1b[32m%s\x1b[0m', 'Qwen access token refreshed successfully');
      return newCredentials;
    } catch (error) {
      console.error('\x1b[31m%s\x1b[0m', 'Failed to refresh Qwen access token with error:', error.message);
      throw error;
    }
  }

  async getValidAccessToken(accountId = null) {
    if (this.refreshPromise) {
      console.log('\x1b[36m%s\x1b[0m', 'Waiting for ongoing token refresh...');
      return this.refreshPromise;
    }

    try {
      let credentials;

      if (accountId) {
        credentials = this.getAccountCredentials(accountId);
        if (!credentials) {
          await this.loadAllAccounts();
          credentials = this.getAccountCredentials(accountId);
        }
      } else {
        credentials = await this.loadCredentials();
      }

      if (!credentials) {
        if (accountId) {
          throw new Error(`No credentials found for account ${accountId}. Please authenticate this account first.`);
        } else {
          throw new Error('No credentials found. Please authenticate with Qwen CLI first.');
        }
      }

      if (this.isTokenValid(credentials)) {
        return credentials.access_token;
      }

      this.refreshPromise = this.performTokenRefresh(credentials, accountId);

      try {
        const newCredentials = await this.refreshPromise;
        return newCredentials.access_token;
      } finally {
        this.refreshPromise = null;
      }
    } catch (error) {
      this.refreshPromise = null;
      throw error;
    }
  }

  async performTokenRefresh(credentials, accountId = null) {
    const lockAcquired = await this.qwenAPI.acquireAccountLock(accountId);
    if (!lockAcquired) {
      throw new Error(
        accountId
          ? `Account ${accountId} is currently in use, cannot refresh token now`
          : 'Default account is currently in use, cannot refresh token now',
      );
    }

    try {
      const newCredentials = await this.refreshAccessToken(credentials);

      if (accountId) {
        await this.saveCredentials(newCredentials, accountId);
      } else {
        await this.saveCredentials(newCredentials);
      }

      return newCredentials;
    } catch (error) {
      throw new Error(`${error instanceof Error ? error.message : String(error)}`);
    } finally {
      this.qwenAPI.releaseAccountLock(accountId);
    }
  }

  async getNextAccount() {
    if (this.accounts.size === 0) {
      await this.loadAllAccounts();
    }

    const accountIds = this.getAccountIds();

    if (accountIds.length === 0) {
      return null;
    }

    const accountId = accountIds[this.currentAccountIndex];
    const credentials = this.getAccountCredentials(accountId);

    this.currentAccountIndex = (this.currentAccountIndex + 1) % accountIds.length;

    return { accountId, credentials };
  }

  peekNextAccount() {
    if (this.accounts.size === 0) {
      return null;
    }

    const accountIds = this.getAccountIds();

    if (accountIds.length === 0) {
      return null;
    }

    const accountId = accountIds[this.currentAccountIndex];
    const credentials = this.getAccountCredentials(accountId);

    return { accountId, credentials };
  }

  isAccountValid(accountId) {
    const credentials = this.getAccountCredentials(accountId);
    return credentials && this.isTokenValid(credentials);
  }

  async initiateDeviceFlow() {
    const { code_verifier, code_challenge } = generatePKCEPair();

    const bodyData = {
      client_id: QWEN_OAUTH_CLIENT_ID,
      scope: QWEN_OAUTH_SCOPE,
      code_challenge,
      code_challenge_method: 'S256',
    };

    try {
      const response = await fetch(QWEN_OAUTH_DEVICE_CODE_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
          'x-request-id': randomUUID(),
        },
        body: Object.keys(bodyData)
          .map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(bodyData[key])}`)
          .join('&'),
      });

      if (!response.ok) {
        const errorData = await response.text();
        throw new Error(`Device authorization failed: ${response.status} ${response.statusText}. Response: ${errorData}`);
      }

      const result = await response.json();

      if (!result.device_code) {
        throw new Error(`Device authorization failed: ${result.error || 'Unknown error'} - ${result.error_description || 'No details provided'}`);
      }

      return {
        ...result,
        code_verifier,
      };
    } catch (error) {
      console.error('Device authorization flow failed:', error.message);
      throw error;
    }
  }

  async pollForToken(device_code, code_verifier, accountId = null) {
    let pollInterval = 2000;
    const maxAttempts = 60;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const bodyData = {
        grant_type: QWEN_OAUTH_GRANT_TYPE,
        client_id: QWEN_OAUTH_CLIENT_ID,
        device_code,
        code_verifier,
      };

      try {
        const response = await fetch(QWEN_OAUTH_TOKEN_ENDPOINT, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Accept: 'application/json',
          },
          body: Object.keys(bodyData)
            .map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(bodyData[key])}`)
            .join('&'),
        });

        if (!response.ok) {
          let errorData;
          try {
            errorData = await response.json();

            if (response.status === 400 && errorData.error === 'authorization_pending') {
              console.log(`Polling attempt ${attempt + 1}/${maxAttempts}...`);
              await new Promise((resolve) => setTimeout(resolve, pollInterval));
              continue;
            }

            if (response.status === 429 && errorData.error === 'slow_down') {
              pollInterval = Math.min(pollInterval * 1.5, 10000);
              console.log(`Server requested to slow down, increasing poll interval to ${pollInterval}ms`);
              await new Promise((resolve) => setTimeout(resolve, pollInterval));
              continue;
            }

            if (response.status === 400 && errorData.error === 'expired_token') {
              throw new Error('Device code expired. Please restart the authentication process.');
            }

            if (response.status === 400 && errorData.error === 'access_denied') {
              throw new Error('Authorization denied by user. Please restart the authentication process.');
            }

            throw new Error(`Device token poll failed: ${errorData.error || 'Unknown error'} - ${errorData.error_description || 'No details provided'}`);
          } catch (_parseError) {
            const errorData = await response.text();
            throw new Error(`Device token poll failed: ${response.status} ${response.statusText}. Response: ${errorData}`);
          }
        }

        const tokenData = await response.json();

        if (tokenData.error) {
          throw new Error(`Device token poll failed: ${tokenData.error} - ${tokenData.error_description || 'No details provided'}`);
        }

        const credentials = {
          access_token: tokenData.access_token,
          refresh_token: tokenData.refresh_token || undefined,
          token_type: tokenData.token_type,
          resource_url: tokenData.resource_url || tokenData.endpoint,
          expiry_date: tokenData.expires_in ? Date.now() + tokenData.expires_in * 1000 : undefined,
        };

        await this.saveCredentials(credentials, accountId);

        return credentials;
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);

        if (
          errorMessage.includes('expired_token') ||
          errorMessage.includes('access_denied') ||
          errorMessage.includes('Device authorization failed')
        ) {
          throw error;
        }

        console.log(`Polling attempt ${attempt + 1}/${maxAttempts} failed:`, errorMessage);
        await new Promise((resolve) => setTimeout(resolve, pollInterval));
      }
    }

    throw new Error('Authentication timeout. Please restart the authentication process.');
  }
}

module.exports = {
  QwenAuthManager,
  QwenOAuth2Client,
  SharedTokenManager,
  clearQwenCredentials,
  cacheQwenCredentials,
  CredentialsClearRequiredError,
  TokenManagerError,
};