const axios = require('axios');

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const ENV_NAME = process.env.ENV || 'Unknown';

const ALERT_TYPES = {
  TOKEN_REFRESH_FAILED: {
    emoji: '🔄',
    title: 'Token Refresh Failed',
    severity: 'high',
  },
  ACCOUNT_BLOCKED: {
    emoji: '🚫',
    title: 'Account Blocked',
    severity: 'high',
  },
  ALL_ACCOUNTS_UNAVAILABLE: {
    emoji: '🚨',
    title: 'All Accounts Unavailable',
    severity: 'critical',
  },
  QUOTA_EXCEEDED: {
    emoji: '📊',
    title: 'Quota Exceeded',
    severity: 'medium',
  },
  AUTH_ERROR: {
    emoji: '🔐',
    title: 'Authentication Error',
    severity: 'high',
  },
  NETWORK_ERROR: {
    emoji: '🌐',
    title: 'Network Error',
    severity: 'medium',
  },
  CREDENTIALS_CLEARED: {
    emoji: '🗑️',
    title: 'Credentials Cleared',
    severity: 'high',
  },
  REQUEST_FAILED: {
    emoji: '❌',
    title: 'Request Failed',
    severity: 'low',
  },
  SERVER_ERROR: {
    emoji: '💥',
    title: 'Server Error',
    severity: 'medium',
  },
};

function isTelegramConfigured() {
  return !!(TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID);
}

function formatAlertMessage(alertType, data) {
  const { emoji, title, severity } = ALERT_TYPES[alertType] || ALERT_TYPES.SERVER_ERROR;

  let message = `${emoji} *Qwen Proxy Alert*\n\n`;
  message += `*Server/Env:* \`${ENV_NAME}\`\n`;
  message += `*Alert:* ${title}\n`;
  message += `*Severity:* ${severity.toUpperCase()}\n`;

  if (data.accountId) {
    message += `*Account:* \`${data.accountId}\`\n`;
  }

  if (data.error) {
    message += `*Error:* \`${data.error}\`\n`;
  }

  if (data.details) {
    message += `*Details:* ${data.details}\n`;
  }

  if (data.action) {
    message += `*Action:* ${data.action}\n`;
  }

  message += `*Time:* \`${new Date().toISOString()}\``;

  return message;
}

async function sendTelegramMessage(message) {
  if (!isTelegramConfigured()) {
    console.debug('Telegram notification skipped: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not configured');
    return false;
  }

  const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;

  try {
    await axios.post(url, {
      chat_id: TELEGRAM_CHAT_ID,
      text: message,
      parse_mode: 'Markdown',
    });
    return true;
  } catch (e) {
    console.warn(`Telegram notification failed: ${e.message}`);
    return false;
  }
}

async function notify(alertType, data = {}) {
  if (!isTelegramConfigured()) {
    return false;
  }

  const message = formatAlertMessage(alertType, data);
  return sendTelegramMessage(message);
}

async function notifyTokenRefreshFailed(accountId, error, isBlocked = false) {
  let action;
  if (isBlocked) {
    action = `Account is blocked. Check account_health.json. Strike system may be active.`;
  } else if (error.includes('refresh_token') || error.includes('invalid')) {
    action = `Refresh token expired/invalid. Run 'npm run auth:add' to re-authenticate.`;
  } else if (error.includes('network') || error.includes('timeout')) {
    action = `Network error. Check internet connectivity to chat.qwen.ai.`;
  } else {
    action = `Unknown error. Check logs for details.`;
  }

  return notify(ALERT_TYPES.TOKEN_REFRESH_FAILED, {
    accountId,
    error,
    action,
  });
}

async function notifyAccountBlocked(accountId, blockedUntil, reason) {
  const blockedUntilDate = blockedUntil ? new Date(blockedUntil).toISOString() : 'unknown';
  return notify(ALERT_TYPES.ACCOUNT_BLOCKED, {
    accountId,
    details: `Blocked until: ${blockedUntilDate}. Reason: ${reason || 'Multiple failures'}`,
    action: 'Account will be unblocked automatically. Or remove from rotation.',
  });
}

async function notifyAllAccountsUnavailable(accountIds, error) {
  return notify(ALERT_TYPES.ALL_ACCOUNTS_UNAVAILABLE, {
    details: `Accounts affected: ${accountIds.length}. Last error: ${error}`,
    action: 'All accounts are blocked, expired, or invalid. Re-authenticate accounts immediately.',
  });
}

async function notifyQuotaExceeded(accountId, error) {
  return notify(ALERT_TYPES.QUOTA_EXCEEDED, {
    accountId,
    error,
    action: 'Account quota exceeded. Consider adding more accounts.',
  });
}

async function notifyCredentialsCleared(accountId, reason) {
  return notify(ALERT_TYPES.CREDENTIALS_CLEARED, {
    accountId,
    details: `Reason: ${reason}`,
    action: 'Credentials file deleted. Run \'npm run auth:add\' to re-authenticate.',
  });
}

async function notifyServerError(error, context = '') {
  return notify(ALERT_TYPES.SERVER_ERROR, {
    error,
    details: context,
    action: 'Check server logs for details.',
  });
}

module.exports = {
  notify,
  notifyTokenRefreshFailed,
  notifyAccountBlocked,
  notifyAllAccountsUnavailable,
  notifyQuotaExceeded,
  notifyCredentialsCleared,
  notifyServerError,
  ALERT_TYPES,
  isTelegramConfigured,
};