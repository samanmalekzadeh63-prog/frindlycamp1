# Friendly Camp

وب‌اپلیکیشن فارسی رزرو و مدیریت تورهای طبیعت‌گردی با React، Vite، TypeScript و Express.

## اجرای توسعه

1. Node.js 22 یا جدیدتر را نصب کنید.
2. `npm install` را اجرا کنید.
3. `.env.example` را به `.env.local` تبدیل و secretها را تنظیم کنید.
4. با `npm run dev` برنامه را روی `http://localhost:3000` اجرا کنید.

بدون `GEMINI_API_KEY`، تولید محتوا خروجی قالبی با نشان `isFallback` برمی‌گرداند. OTP تا زمان اتصال ارائه‌دهنده پیامک عمداً پاسخ `503` می‌دهد و موفقیت جعلی نمایش نمی‌دهد.

## کنترل کیفیت

- `npm run typecheck`: بررسی TypeScript
- `npm test`: تست‌های واحد
- `npm run build`: ساخت production
- `npm run check`: اجرای تمام کنترل‌ها
- `npm audit --omit=dev`: ممیزی وابستگی‌های production

## امنیت و استقرار

در production مقدار `SESSION_SECRET` با حداقل ۳۲ کاراکتر الزامی است. TLS باید در reverse proxy فعال باشد. فایل `data/users.json` فقط persistence محلی توسعه است؛ برای استقرار چند replica باید با PostgreSQL و migration جایگزین شود. دسترسی ادمین فقط بر پایه نقش ذخیره‌شده سمت سرور انجام می‌شود و client نمی‌تواند هنگام ثبت‌نام نقش تعیین کند.

درگاه پرداخت و پیامک به credential و قرارداد سرویس‌دهنده نیاز دارند و تا اتصال آن‌ها نباید به‌عنوان عملیات موفق نمایش داده شوند.
