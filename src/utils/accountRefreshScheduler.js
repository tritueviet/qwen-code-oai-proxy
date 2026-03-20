const { QwenAuthManager } = require('../qwen/auth.js');
const { DebugLogger } = require('./logger.js');
const axios = require('axios');

class AccountRefreshScheduler {
  constructor(qwenAPI) {
    this.qwenAPI = qwenAPI;
    this.refreshInterval = null;
    this.isRefreshing = false;
    this.refreshThresholds = new Map(); // Flag to prevent concurrent refresh processes
  }

  /**
   * Initialize the account refresh scheduler
   */
  async initialize() {
    console.log('\x1b[36m%s\x1b[0m', 'Initializing account refresh scheduler...');

    // Start the refresh scheduler
    await this.startScheduler();
  }

  async startScheduler() {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
    }

    await this.checkAndRefreshExpiredAccounts();

    this.refreshInterval = setInterval(() => {
      this.checkAndRefreshExpiredAccounts();
    }, 5 * 60 * 1000);
  }

  stopScheduler() {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = null;
    }
  }

  /**
   * Check for expired accounts and refresh their tokens using account locks to prevent conflicts
   * Processes accounts in parallel batches with concurrency control
   */
  async checkAndRefreshExpiredAccounts() {
    // Check if a refresh process is already running
    if (this.isRefreshing) {
      //   console.log('\x1b[33m%s\x1b[0m', 'Account refresh is already in progress, skipping this check');
      return;
    }

    // Set the flag to indicate a refresh process is starting
    this.isRefreshing = true;

    try {

      // Load all accounts (in case new ones were added)
      await this.qwenAPI.authManager.loadAllAccounts();

      const accountIds = this.qwenAPI.authManager.getAccountIds();
      const defaultCredentials = await this.qwenAPI.authManager.loadCredentials();
      const refreshTargets = [];

      if (defaultCredentials) {
        refreshTargets.push({
          accountId: 'default',
          credentials: defaultCredentials,
          isDefault: true,
        });
      }

      for (const accountId of accountIds) {
        refreshTargets.push({
          accountId,
          credentials: this.qwenAPI.authManager.getAccountCredentials(accountId),
          isDefault: false,
        });
      }

      const accountsToRefresh = [];
      let expiredAccountsFound = false;

      for (const target of refreshTargets) {
        const { accountId, credentials } = target;

        if (!credentials) {
          continue;
        }

        const isExpired = credentials.expiry_date <= Date.now();
        const minutesLeft = (credentials.expiry_date - Date.now()) / 60000;

        if (isExpired) {
          expiredAccountsFound = true;
          accountsToRefresh.push(target);
          console.log(`\x1b[31m●\x1b[0m Refresh | \x1b[36m${accountId}\x1b[0m | \x1b[31mexpired\x1b[0m`);
        } else if (minutesLeft <= 10) {
          expiredAccountsFound = true;
          accountsToRefresh.push(target);
          console.log(`\x1b[33m●\x1b[0m Refresh | \x1b[36m${accountId}\x1b[0m | \x1b[33mexpiring\x1b[0m | ${minutesLeft.toFixed(0)}m`);
        } else {
          let threshold = this.refreshThresholds.get(accountId);
          if (!threshold) {
            threshold = Math.floor(Math.random() * 21) + 10;
            this.refreshThresholds.set(accountId, threshold);
          }

          if (minutesLeft <= threshold) {
            expiredAccountsFound = true;
            accountsToRefresh.push(target);
            console.log(`\x1b[35m●\x1b[0m Refresh | \x1b[36m${accountId}\x1b[0m | \x1b[35mexpiring\x1b[0m | ${minutesLeft.toFixed(0)}m`);
          }
        }
      }

      if (!expiredAccountsFound) {
        console.log(`\x1b[32m●\x1b[0m Refresh | \x1b[32midle\x1b[0m | ${refreshTargets.length} accounts`);
        return;
      }

      // Process accounts that need refresh in parallel batches of 20
      const batchSize = 20;
      for (let i = 0; i < accountsToRefresh.length; i += batchSize) {
        const batch = accountsToRefresh.slice(i, i + batchSize);

        // Process the current batch in parallel
        const batchPromises = batch.map(async (target) => {
          const { accountId, isDefault } = target;
          const credentials = isDefault
            ? await this.qwenAPI.authManager.loadCredentials()
            : this.qwenAPI.authManager.getAccountCredentials(accountId);

          if (!credentials) {
            console.log(`\x1b[31m%s\x1b[0m`, `No credentials found for account ${accountId}`);
            return;
          }

          try {
            // Attempt to refresh the token
            await this.qwenAPI.authManager.performTokenRefresh(
              credentials,
              isDefault ? null : accountId
            );
            this.refreshThresholds.delete(accountId);
            console.log(`\x1b[32m●\x1b[0m Refresh | \x1b[36m${accountId}\x1b[0m | \x1b[32mrefreshed\x1b[0m`);
          } catch (refreshError) {
            console.warn(`\x1b[31m✗\x1b[0m Refresh | \x1b[36m${accountId}\x1b[0m | \x1b[31mfailed\x1b[0m: ${refreshError.message.substring(0, 30)}`);
            await this.sendTelegramAlert(accountId, refreshError.message);
          }

        });

        await Promise.allSettled(batchPromises);
      }
    } catch (error) {
      console.warn(`\x1b[31m!\x1b[0m Refresh | \x1b[31merror\x1b[0m: ${error.message.substring(0, 30)}`);
    } finally {
      // Reset the flag to indicate the refresh process is complete
      this.isRefreshing = false;
    }
  }

  async forceRefreshAllAccounts() {
    await this.qwenAPI.authManager.loadAllAccounts();
    const accountIds = this.qwenAPI.authManager.getAccountIds();
    const defaultCredentials = await this.qwenAPI.authManager.loadCredentials();
    const refreshTargets = [];

    if (defaultCredentials) {
      refreshTargets.push({
        accountId: 'default',
        credentials: defaultCredentials,
        isDefault: true,
      });
    }

    for (const accountId of accountIds) {
      refreshTargets.push({
        accountId,
        credentials: this.qwenAPI.authManager.getAccountCredentials(accountId),
        isDefault: false,
      });
    }

    if (refreshTargets.length === 0) {
      console.log(`\x1b[33m○\x1b[0m Refresh | \x1b[33mnone\x1b[0m | no accounts`);
      return;
    }

    let successCount = 0;
    let failCount = 0;

    for (const target of refreshTargets) {
      const { accountId, isDefault } = target;
      const credentials = isDefault
        ? await this.qwenAPI.authManager.loadCredentials()
        : this.qwenAPI.authManager.getAccountCredentials(accountId);

      if (!credentials) {
        failCount++;
        continue;
      }

      try {
        await this.qwenAPI.authManager.performTokenRefresh(
          credentials,
          isDefault ? null : accountId
        );
        this.refreshThresholds.delete(accountId);
        console.log(`\x1b[32m●\x1b[0m Refresh | \x1b[36m${accountId}\x1b[0m | \x1b[32mforced\x1b[0m`);
        successCount++;
      } catch (refreshError) {
        console.warn(`\x1b[31m✗\x1b[0m Refresh | \x1b[36m${accountId}\x1b[0m | \x1b[31mfailed\x1b[0m: ${refreshError.message.substring(0, 30)}`);
        await this.sendTelegramAlert(accountId, refreshError.message);
        failCount++;
      }
    }

    console.log(`\x1b[36m●\x1b[0m Refresh | \x1b[36mforced\x1b[0m | ${successCount} ok, ${failCount} fail`);
  }

  /**
   * Send Telegram alert when account token refresh fails
   */
  async sendTelegramAlert(accountId, errorMsg) {
    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;
    const envName = process.env.ENV || 'Unknown';

    if (!botToken || !chatId) {
      console.warn(`\x1b[33m~\x1b[0m Telegram alert skipped: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is not set in .env file`);
      return;
    }

    const url = `https://api.telegram.org/bot${botToken}/sendMessage`;
    const message = `🚨 *Qwen Proxy Alert*\n\n*Server/Env:* \`${envName}\`\n*Account ID:* \`${accountId}\`\n*Error:* \n\`${errorMsg}\`\n*Action:* Token refresh failed!`;

    try {
      await axios.post(url, {
        chat_id: chatId,
        text: message,
        parse_mode: 'Markdown'
      });
    } catch (e) {
      console.warn(`\x1b[33m~\x1b[0m Telegram alert failed: ${e.message}`);
    }
  }
}

module.exports = { AccountRefreshScheduler };
