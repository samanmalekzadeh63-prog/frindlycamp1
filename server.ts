import "dotenv/config";
import express from "express";
import path from "path";
import fs from "node:fs";
import crypto from "node:crypto";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI } from "@google/genai";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import multer from "multer";
import { ZodError } from "zod";
import { authenticate, bootstrapAdminFromEnvironment, clearSession, createUser, issueSession, optionalSession, requireAdmin, requireUser } from "./server/auth";
import { aiSchema, loginSchema, profileSchema, registerSchema, walletOperationSchema } from "./server/schemas";
import { applyWalletOperation, getProfile, saveProfile } from "./server/profile";
import { adminSnapshot, createAdminRecord, publicDesignSettings, updateAdminRecord, updateAdminSettings, type AdminResource } from "./server/adminStore";

async function startServer() {
  await bootstrapAdminFromEnvironment();
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;
  const isProduction = process.env.NODE_ENV === "production";

  app.disable("x-powered-by");
  // Allows the management application to live on a separate, explicitly trusted domain.
  // Example: ADMIN_ORIGINS=https://admin.friendlycamp.ir
  const adminOrigins = new Set((process.env.ADMIN_ORIGINS || "").split(",").map(value => value.trim()).filter(Boolean));
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin && adminOrigins.has(origin)) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Access-Control-Allow-Credentials", "true");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Requested-With");
      res.setHeader("Access-Control-Allow-Methods", "GET,POST,PATCH,PUT,DELETE,OPTIONS");
      res.setHeader("Vary", "Origin");
    }
    if (req.method === "OPTIONS") return res.status(adminOrigins.has(origin || "") ? 204 : 403).end();
    next();
  });
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        "default-src": ["'self'"], "script-src": isProduction ? ["'self'"] : ["'self'", "'unsafe-inline'"], "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        "font-src": ["'self'", "https://fonts.gstatic.com", "data:"], "img-src": ["'self'", "data:", "https://images.unsplash.com", "https://media.giphy.com"],
        "media-src": ["'self'", "https://assets.mixkit.co", "https://commondatastorage.googleapis.com"], "connect-src": isProduction ? ["'self'"] : ["'self'", "ws:", "wss:"],
        "frame-ancestors": ["'none'"], "base-uri": ["'self'"], "form-action": ["'self'"],
        "upgrade-insecure-requests": isProduction ? [] : null
      }
    }, crossOriginResourcePolicy: { policy: "cross-origin" }, referrerPolicy: { policy: "strict-origin-when-cross-origin" }
  }));
  app.use(express.json({ limit: "32kb" }));
  app.use(cookieParser());
  app.use(optionalSession);
  app.use("/api", rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: "draft-8", legacyHeaders: false }));
  const authLimiter = rateLimit({ windowMs: 15 * 60_000, limit: 10, standardHeaders: "draft-8", legacyHeaders: false });
  const aiLimiter = rateLimit({ windowMs: 60_000, limit: 10, standardHeaders: "draft-8", legacyHeaders: false });
  const uploadsDirectory = path.join(process.cwd(), "public", "uploads");
  fs.mkdirSync(uploadsDirectory, { recursive: true });
  const allowedUploadTypes = new Set(["image/jpeg", "image/png", "image/webp", "image/gif", "audio/mpeg", "audio/mp4", "audio/ogg", "audio/wav"]);
  const upload = multer({
    storage: multer.diskStorage({ destination: uploadsDirectory, filename: (_req, file, callback) => {
      const extension = ({ "image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp", "image/gif": ".gif", "audio/mpeg": ".mp3", "audio/mp4": ".m4a", "audio/ogg": ".ogg", "audio/wav": ".wav" } as Record<string, string>)[file.mimetype] || "";
      callback(null, `${crypto.randomUUID()}${extension}`);
    }}),
    limits: { fileSize: 12 * 1024 * 1024, files: 1 },
    fileFilter: (_req, file, callback) => callback(null, allowedUploadTypes.has(file.mimetype))
  });
  app.use("/uploads", express.static(uploadsDirectory, { immutable: true, maxAge: "30d", fallthrough: false }));

  // Initialize Gemini AI client server-side lazily
  let aiClient: GoogleGenAI | null = null;
  function getGenAI(): GoogleGenAI | null {
    if (!aiClient && process.env.GEMINI_API_KEY) {
      aiClient = new GoogleGenAI({
        apiKey: process.env.GEMINI_API_KEY,
        httpOptions: {
          headers: {
            "User-Agent": "aistudio-build",
          },
        },
      });
    }
    return aiClient;
  }

  // API Route: Health Check
  app.get("/api/health", (req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString(), version: process.env.npm_package_version || "0.0.0" });
  });
  app.get("/api/site/design-settings", async (_req,res,next)=>{try{res.setHeader("Cache-Control","public, max-age=60, stale-while-revalidate=300");res.json({settings:await publicDesignSettings()})}catch(error){next(error)}});

  app.get("/api/auth/me", requireUser, (req, res) => res.json({ user: req.user }));
  app.post("/api/auth/register", authLimiter, async (req, res, next) => {
    try { const input = registerSchema.parse(req.body); const user = await createUser(input); issueSession(res, user, true); res.status(201).json({ user }); }
    catch (error: any) { if (error?.message === "ACCOUNT_EXISTS") return res.status(409).json({ error: "ACCOUNT_EXISTS", message: "حسابی با این ایمیل یا شماره همراه وجود دارد." }); next(error); }
  });
  app.post("/api/auth/login", authLimiter, async (req, res, next) => {
    try { const input = loginSchema.parse(req.body); const user = await authenticate(input.identifier, input.password); if (!user) return res.status(401).json({ error: "INVALID_CREDENTIALS", message: "اطلاعات ورود صحیح نیست." }); issueSession(res, user, input.remember); res.json({ user }); }
    catch (error) { next(error); }
  });
  app.post("/api/auth/logout", (_req, res) => { clearSession(res); res.status(204).end(); });
  app.post("/api/auth/otp/request", authLimiter, (_req, res) => res.status(503).json({ error: "OTP_PROVIDER_NOT_CONFIGURED", message: "سرویس پیامک هنوز پیکربندی نشده است؛ از ورود با رمز استفاده کنید." }));
  app.get("/api/admin/health", requireAdmin, (_req, res) => res.json({ status: "ok" }));
  app.get("/api/admin/dashboard", requireAdmin, async (_req, res, next) => { try { res.json(await adminSnapshot()); } catch (error) { next(error); } });
  app.patch("/api/admin/settings", requireAdmin, async (req, res, next) => { try { if(!req.body||typeof req.body!=="object"||Array.isArray(req.body)) return res.status(400).json({error:"INVALID_PAYLOAD"}); res.json({settings:await updateAdminSettings(req.body,req.user!.email)}); } catch(error){ next(error); } });
  const adminResources = new Set<AdminResource>(["tours","bookings","products","customers","content","tickets"]);
  app.post("/api/admin/:resource", requireAdmin, async (req, res, next) => {
    try {
      const resource=req.params.resource as AdminResource;
      if(!adminResources.has(resource)) return res.status(404).json({error:"RESOURCE_NOT_FOUND"});
      if(!req.body || typeof req.body!=="object" || Array.isArray(req.body)) return res.status(400).json({error:"INVALID_PAYLOAD"});
      res.status(201).json({record:await createAdminRecord(resource,req.body,req.user!.email)});
    } catch(error){ next(error); }
  });
  app.patch("/api/admin/:resource/:id", requireAdmin, async (req, res, next) => {
    try {
      const resource=req.params.resource as AdminResource;
      if(!adminResources.has(resource)) return res.status(404).json({error:"RESOURCE_NOT_FOUND"});
      if(!req.body || typeof req.body!=="object" || Array.isArray(req.body)) return res.status(400).json({error:"INVALID_PAYLOAD"});
      const record=await updateAdminRecord(resource,req.params.id,req.body,req.user!.email);
      if(!record) return res.status(404).json({error:"RECORD_NOT_FOUND"}); res.json({record});
    } catch(error){ next(error); }
  });
  app.get("/api/profile", requireUser, async (req, res, next) => { try { res.json({ profile: await getProfile(req.user!.id), user: req.user }); } catch (error) { next(error); } });
  app.put("/api/profile", requireUser, async (req, res, next) => { try { const profile = profileSchema.parse(req.body); res.json({ profile: await saveProfile(req.user!.id, profile as any) }); } catch (error) { next(error); } });
  app.post("/api/profile/wallet/operation", requireUser, async (req, res, next) => { try { const input = walletOperationSchema.parse(req.body); res.json(await applyWalletOperation(req.user!.id, input)); } catch (error) { if (error instanceof Error && error.message === 'INSUFFICIENT_BALANCE') return res.status(409).json({ error: 'INSUFFICIENT_BALANCE', message: 'موجودی قابل برداشت کافی نیست.' }); next(error); } });
  app.post("/api/profile/upload", requireUser, upload.single("file"), (req, res) => {
    if (!req.file) return res.status(400).json({ error: "INVALID_FILE", message: "فایل معتبر انتخاب نشده است." });
    res.status(201).json({ url: `/uploads/${req.file.filename}`, mimeType: req.file.mimetype, size: req.file.size });
  });

  // API Route: AI Travel Content Generator (Gemini 3.6 Flash)
  app.post("/api/gemini/generate-content", aiLimiter, async (req, res) => {
    const parsedInput = aiSchema.safeParse(req.body);
    if (!parsedInput.success) return res.status(400).json({ error: "VALIDATION_ERROR", issues: parsedInput.error.issues.map(issue => ({ path: issue.path.join('.'), message: issue.message })) });
    try {
      const { contentType, tourName, tone, keywords, additionalPrompt } = parsedInput.data;

      const promptSystem = `شما یک دستیار هوش مصنوعی و متخصص بازاریابی گردشگری و محتوای تورهای طبیعت‌گردی برای برند «فرندلی کمپ» (Friendly Camp) هستید.
پاسخ‌ها را کاملاً به زبان فارسی روان، جذاب، اصولی و با فرمت زیبا (همراه با ایموجی‌های مناسب) آماده کنید.`;

      let promptTask = "";

      switch (contentType) {
        case "personalizer":
          promptTask = `کاربر سفر رویایی خود را این‌گونه توصیف کرده است:
«${additionalPrompt || tourName}»

به عنوان دستیار و هوش مصنوعی تخصصی سفر «فرندلی کمپ»، یک برنامه سفارشی شخصی‌سازی‌شده و کامل برای این سفر آماده کن شامل:
۱. 🏕️ **عنوان پیشنهادی برنامه سفر و مقصد پیشنهادی**
۲. 📅 **برنامه زمان‌بندی روز به روز (Day 1, Day 2, ...)**
۳. 💰 **تخمین تقریبی بودجه (هزینه ترانسفر، وعده‌های غذایی و تجهیزات)**
۴. 🎒 **چک‌لیست تجهیزات ضروری (چادر، کیسه خواب، لباس و ...)**
۵. 🌲 **پیشنهاد تورهای مشابه موجود در فرندلی کمپ**

پاسخ را با ایموجی‌های زیبا، تیترهای مشخص و لحنی بسیار صمیمی، انگیزشی و حرفه‌ای تنظیم کن.`;
          break;

        case "instagram":
          promptTask = `یک پست کامل اینستاگرام شامل تیتر قلاب‌دار (Hook)، متن اصلی هیجان‌انگیز، دعوت به اقدام (CTA)، جزئیات تور «${tourName}» با لحن «${tone || "پرانرژی و جذاب"}» و حداقل ۱۵ هشتگ پربازدید طبیعت‌گردی ایران بنویس.
کلیدواژه‌های پرداختی: ${keywords || "طبیعت‌گردی، کمپینگ، تور اختصاصی"}.
جزئیات اضافه: ${additionalPrompt || "ندارد"}.`;
          break;

        case "itinerary":
          promptTask = `یک برنامه تفصیلی زمان‌بندی روزبه‌روز و ساعت‌به‌ساعت (Itinerary) حرفه‌ای برای تور «${tourName}» بنویس. شامل:
- ساعت حرکت و نقطه قرار
- وعده‌های غذایی (صبحانه، ناهار، شام، پذیرایی دور آتش)
- فعالیت‌های روزانه (پیمایش، عکاسی، کمپینگ، کارگاه بقا)
- تجهیزات اجباری و پیشنهادی
لحن: ${tone || "رسمی و انگیزشی"}.`;
          break;

        case "sms":
          promptTask = `دو نمونه پیامک جذاب اطلاع‌رسانی و یادآوری (یکی جهت یادآوری حرکت و مدارک و دیگری جهت پیشنهاد ثبت‌نام) برای تور «${tourName}» بنویس. کوتاه، کاربردی و دارای لینک فرضی ثبت‌نام.
لحن: ${tone || "صمیمانه و فوری"}.`;
          break;

        case "blog":
        default:
          promptTask = `یک مقاله وبلاگ سئو شده و جامع (حداقل ۵۰۰ کلمه) درباره راهنمای سفر و طبیعت‌گردی در «${tourName}» بنویس.
شامل تیترهای اصلی (H2, H3)، نکات ایمنی، بهترین فصل سفر، جاذبه‌های مسیر و توصیه برای کمپینگ دنج با فرندلی کمپ.
لحن: ${tone || "آموزنده و جذاب"}.`;
          break;
      }

      const ai = getGenAI();

      if (!ai) {
        // Fallback intelligent templates if GEMINI_API_KEY is not set
        const fallbackText = getSmartFallbackContent(contentType, tourName, tone, keywords);
        return res.json({ text: fallbackText, isFallback: true });
      }

      const response = await ai.models.generateContent({
        model: "gemini-3.6-flash",
        contents: `${promptSystem}\n\n${promptTask}`,
      });

      return res.json({ text: response.text || "محتوایی تولید نشد.", isFallback: false });
    } catch (err: any) {
      console.error("Gemini API Error:", err);
      // Fail gracefully with smart templates
      const fallbackText = getSmartFallbackContent(
        req.body?.contentType || "instagram",
        req.body?.tourName || "طبیعت‌گردی",
        req.body?.tone,
        req.body?.keywords
      );
      return res.json({ text: fallbackText, isFallback: true });
    }
  });

  app.use("/api", (_req, res) => res.status(404).json({ error: "NOT_FOUND" }));
  app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    if (error instanceof ZodError) return res.status(400).json({ error: "VALIDATION_ERROR", issues: error.issues.map(issue => ({ path: issue.path.join('.'), message: issue.message })) });
    if (error instanceof SyntaxError) return res.status(400).json({ error: "INVALID_JSON" });
    console.error("Unhandled request error", error);
    return res.status(500).json({ error: "INTERNAL_ERROR" });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

function getSmartFallbackContent(type: string, tour: string, tone?: string, keywords?: string): string {
  if (type === "personalizer") {
    return `✨ **برنامه پیشنهادی اختصاصی هوش مصنوعی فرندلی کمپ**

🏕️ **عنوان سفر:** ماجراجویی بکر ۳ روزه در جنگل، آبشار و کمپینگ کوهستانی

📅 **برنامه زمان‌بندی روز به روز:**

**روز ۱: پیمایش در دل دالان‌های مه و استقرار کمپ**
- ۰۵:۰۰ | حرکت با اتوبوس VIP از تهران به سمت مبدأ
- ۰۹:۳۰ | صرف صبحانه املت ارگانیک و چای زغالی در محلی محلی
- ۱۲:۰۰ | تحویل کوله‌پشتی‌ها به نیسان محلی و آغاز پیمایش سبک جنگلی (۲ ساعت)
- ۱۵:۰۰ | برپایی کمپ اختصاصی چادری در مرتع و صرف ناهار گرم
- ۲۰:۰۰ | شب‌نشینی دور آتش، موسیقی زنده محلی و رصد ستارگان

**روز ۲: کشف آبشار پنهان و کارگاه آموزش بقا**
- ۰۸:۰۰ | بیداری با ندای پرندگان و صرف صبحانه محلی
- ۱۰:۰۰ | راهپیمایی تا آبشار پنهان و شنای اختیاری در حوضچه زلال
- ۱۴:۰۰ | ناهار کباب چنجه محلی
- ۱۶:۳۰ | کارگاه آموزشی جهت‌یابی با قطب‌نما و برپایی سایبان اضطراری
- ۲۱:۰۰ | پذیرایی شام و سیب‌زمینی آتشی

**روز ۳: جمع‌آوری کمپ بدون اثر و بازگشت با خاطرات ماندگار**
- ۰۹:۰۰ | جمع‌آوری کمپ با رعایت اصل Leave No Trace
- ۱۲:۰۰ | خرید سوغات محلی (عسل، پنیر کوهستانی) و حرکت به سمت تهران
- ۲۱:۰۰ | رسیدن به تهران

💰 **تخمین هزینه تقریبی:** حدود ۳,۸۰۰,۰۰۰ تومان (شامل تمام ترانسفرها، وعده‌های غذایی و سرپرست)
🎒 **تجهیزات ضروری:** کیسه خواب صفر درجه، کفش ترکینگ ساق‌دار، هدلامپ، صندلی کمپing
🌲 **تور پیشنهادی مشابه در سایت:** «تور کمپینگ جنگل‌های اسالم و تالش»`;
  }

  if (type === "instagram") {
    return `🌲 آماده یک ماجراجویی بی‌نظیر در ${tour} هستید؟ ✨

اگر دلتون برای بوی هیزم، صدای آبشار و آسمون پر از ستاره کویر/جنگل تنگ شده، این سفر دقیقا برای شماست! ⛺🔥

⭐️ **چرا فرندلی کمپ؟**
• ترانسفر اتوبوس VIP و مجهز
• وعده‌های غذایی محلی و ارگانیک
• چادر و تجهیزات کمپینگ مدرن
• بیمه کامل حوادث + لیدر تخصصی کارت‌دار

📌 **تاریخ حرکت:** آخر همین هفته
👥 **ظرفیت باقی‌مانده:** فقط ۴ نفر!

📥 برای ثبت‌نام و رزرو آنی عدد ۱ رو کامنت کنید یا از لینک بیو وارد بشید.

#فرندلی_کمپ #${tour.replace(/\s+/g, "_")} #طبیعت_گردی #کمپینگ_ایران #ایرانگردی #کمپینگ_شبانه #سفر_ارزان #تور_طبیعتگردی`;
  }

  if (type === "itinerary") {
    return `🗺️ **برنامه زمان‌بندی تفصیلی تور ${tour}**

📅 **روز اول:**
- ۰۴:۳۰ | حرکت از میدان ونک با اتوبوس VIP
- ۰۸:۰۰ | صرف صبحانه ارگانیک در مجتمع بین‌راهی
- ۱۱:۳۰ | رسیدن به مبدأ پیمایش و تحویل کوله‌ها به نیسان
- ۱۳:۰۰ | استقرار در سایت کمپ اختصاصی فرندلی کمپ و برپایی چادرها
- ۱۴:۳۰ | صرف ناهار گرم محلی
- ۱۷:۰۰ | گشت دور دریاچه / جنگل‌نوردی و عکاسی
- ۲۱:۰۰ | دورهمی دور آتش، شب‌نشینی، چای زغالی و عکاسی نجومی

📅 **روز دوم:**
- ۰۷:۳۰ | بیداری با ندای طبیعت و صرف صبحانه
- ۰۹:۰۰ | پیمایش سبک تا آبشار و کارگاه آموزش بقا در طبیعت
- ۱۳:۰۰ | جمع‌آوری کمپ و حرکت به سمت تهران
- ۲۱:۰۰ | رسیدن به تهران با کوله‌باری از خاطرات زیبا`;
  }

  if (type === "sms") {
    return `✉️ **نمونه پیامک ۱ (یادآوری حرکت):**
سلام همنورد عزیز! 🎒
حرکت تور ${tour} فردا ساعت ۰۴:۱۵ از میدان ونک است. مدارک شناسایی و کفش مناسب همراه داشته باشید.
پشتیبانی: ۰۹۱۲۳۴۵۶۷۸۹ (فرندلی کمپ)

✉️ **نمونه پیامک ۲ (پیشنهاد رزرو با تخفیف):**
فرصت ویژه! ۲۰٪ تخفیف رزرو تور ${tour} فقط برای اعضای طلایی باشگاه همنوردان.
کد تخفیف: GOLD-CAMP
ثبت‌نام: friendlycamp.ir/tour`;
  }

  return `✍️ **راهنمای جامع طبیعت‌گردی و کمپینگ در ${tour}**

طبیعت بکر و چشم‌اندازهای رویایی ${tour} یکی از شگفت‌انگیزترین مقاصد برای علاقه‌مندان به سفر و کمپینگ در ایران است. در این مقاله به بررسی ویژگی‌ها و راهنمای سفر امن به این منطقه می‌پردازیم.

### ۱. بهترین زمان سفر
بهترین فصل برای بازدید از ${tour}، فصل بهار و اوایل پاییز است که آب‌وهوا در معتدل‌ترین حالت قرار دارد.

### ۲. تجهیزات ضروری کمپینگ
برای تجربه یک شب‌مانی امن، تجهیزات زیر الزامی است:
- چادر دوپوش ضدآب
- کیسه خواب مناسب با دمای منطقه
- هدلامپ و چراغ کمپing
- وعده‌های غذایی سبُک و متراکم

### ۳. رعایت اصول «ردپایی باقی نگذاریم» (Leave No Trace)
ما در فرندلی کمپ متعهد به حفظ پاکیزگی طبیعت هستیم. تمامی زباله‌ها را همراه خود بازمی‌گردانیم و از آسیب به پوشش گیاهی منطقه جدا خودداری می‌کنیم.`;
}

startServer();
