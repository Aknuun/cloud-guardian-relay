# AGENTS.md — ربات تلگرام کلادفلر/آروان (DNS bot)

> این فایل دستورالعمل عامل‌های opencode برای این پروژه است.

## قانون نسخه‌بندی (مهم)
- بعد از **هر تغییر** در `worker.js`، قبل از deploy مقدار `BOT_VERSION` را **یک واحد زیاد کن** (مثلاً `8.1` → `8.2`). کاربر نباید یادآوری کند.
- `BOT_VERSION` تنها منبع نسخه است و در منوی اصلی و دستور `/version` نمایش داده می‌شود.
- در پایان هر تغییر، شمارهٔ نسخهٔ جدید را در پاسخ گزارش کن.

## deploy
```bash
cd /root/cloud-guardian-bot && CLOUDFLARE_API_TOKEN=$CLOUDFLARE_API_TOKEN npx --yes wrangler@4.129.1 deploy
```

## نسخهٔ دوست (deployment دوم)
- فایل: `wrangler.friend.toml` (همان `worker.js`، ولی `name` و `KV` و `BOT_TOKEN`/`ADMIN_ID` جدا).
- deploy:
```bash
cd /root/cloud-guardian-bot && CLOUDFLARE_API_TOKEN=<friend-cf-token> npx --yes wrangler@4.129.1 deploy -c wrangler.friend.toml
```
- ربات تلگرامِ دوست باید توکن مستقل از BotFather داشته باشد (یک توکن = یک ربات).

## نکته‌های فنی
- رلهٔ check-host روی سرور: `hf-relay.js` + سرویس `hf-relay` + `relay.videobazi.com:8787`.
- Globalping بدون رله از خود Worker کار می‌کند.
- آروان: ساخت دامنه از API ممکن نیست؛ دامنه باید در پنل آروان اضافه شود و کلید Machine User باید به آن دامنه دسترسی داشته باشد.
