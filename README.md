# Copy fork of **[Cashiuss](https://github.com/Cashiuus/BotPEASS)** based on **[BotPEASS](https://github.com/Cashiuus/BotPEASS)**

![](https://github.com/carlospolop/BotPEASS/raw/main/images/botpeas.png)

Use this bot to monitor new CVEs containing defined keywords and send alerts to Slack and/or Telegram.

## Configure one for yourself

**Configuring your own BotPEASS** that notifies you about the new CVEs containing specific keywords is very easy!

- Fork this repo
- Modify the file `config/botpeas.yaml` and set your own keywords
- In the **github secrets** of your forked repo enter the following API keys:
    - **VULNERS_API_KEY**: (Optional) This is used to find publicly available exploits. You can use a Free API Key.
    - **SLACK_WEBHOOK**: (Optional) Set the slack webhook to send messages to your slack group
    - **DISCORD_WEBHOOK_URL**: (Optional) Set the discord webhook to send messages to your discord channel
    - **TELEGRAM_BOT_TOKEN** and **TELEGRAM_CHAT_ID**: (Optional) Your Telegram bot token and the chat_id to send the messages to

- Check `.github/wordflows/botpeas.yaml` and configure the cron (*once every 8 hours by default*)

*Note that the slack, telegram, discord and ntfy.sh configurations are optional, but if you don't set any of them you won't receive any notifications anywhere*
