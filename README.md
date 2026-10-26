# foxyvpn-py

کلاینت **غیررسمی** Firefox VPN به زبان پایتون، الهام‌گرفته از [Vauth/FoxyVPN](https://github.com/Vauth/FoxyVPN) (نسخه‌ی اندروید) و کلاینت Go مرجعش.

با حساب Firefox لاگین می‌کند، از سرویس Guardian موزیلا یک *proxy pass* می‌گیرد و یک **پروکسی SOCKS5 محلی** بالا می‌آورد که اتصال‌ها را از طریق تونل HTTP/2 CONNECT به سرورهای Firefox VPN می‌فرستد.

> **تفاوت مهم با نسخه‌ی اندروید:** اپ اندروید با `VpnService` کل ترافیک گوشی را می‌گیرد. پایتون روی دسکتاپ به‌تنهایی TUN/VPN سیستمی نمی‌سازد؛ این برنامه پروکسی SOCKS5 می‌دهد و باید مرورگر/برنامه‌ات را روی `127.0.0.1:1088` تنظیم کنی (یا با ابزارهایی مثل `proxychains`، `tun2socks`، Proxifier استفاده کنی).

## نصب

```bash
pip install -r requirements.txt     # h2 و requests
```

نیازمند Python 3.9 یا بالاتر.

## استفاده

```bash
python -m foxyvpn_py login                    # ایمیل/رمز حساب Firefox (در صورت نیاز کد ایمیلی)
python -m foxyvpn_py servers --country DE     # لیست سرورها
python -m foxyvpn_py run --country DE         # SOCKS5 روی 127.0.0.1:1088
python -m foxyvpn_py status                   # سهمیه‌ی باقی‌مانده
python -m foxyvpn_py logout
```

تست اتصال:

```bash
curl --socks5-hostname 127.0.0.1:1088 https://www.cloudflare.com/cdn-cgi/trace
```

گزینه‌های `run`: `--country`، `--proxy HOST:PORT`، `--listen 127.0.0.1:1088`، `--max-conns`، و `-v` (لاگ مقصد اتصال‌ها؛ به‌صورت پیش‌فرض مخفی است).

## ساختار

| فایل | کار |
|---|---|
| `fxa.py` | ورود به Firefox Account: PBKDF2/HKDF، هدر Hawk، توکن OAuth (فقط stdlib + requests) |
| `guardian.py` | گرفتن proxy pass (JWT)، فعال‌سازی، سهمیه |
| `serverlist.py` | لیست سرورها از Remote Settings موزیلا و انتخاب سریع‌ترین |
| `h2tunnel.py` | نشست HTTP/2 و تونل‌های CONNECT با کتابخانه‌ی `h2` (کنترل جریان، GOAWAY، اتصال مجدد) |
| `socks.py` | سرور SOCKS5 محلی |
| `app.py` | تمدید خودکار proxy pass، انتخاب سرور، راه‌اندازی |
| `tokens.py` | ذخیره‌ی توکن‌ها با دسترسی `0600` در `~/.foxyvpn-py/tokens.json` |

## تست

```bash
python -m unittest discover -s tests -v
```

تست‌ها بخش‌های رمزنگاری (HKDF با بردارهای RFC 5869، Hawk)، JWT، لیست سرور، ذخیره‌ی توکن و SOCKS5 را پوشش می‌دهند. لایه‌ی شبکه‌ی HTTP/2 (`h2tunnel.py`) نیاز به دسترسی به سرورهای واقعی دارد و با تست واحد پوشش داده نشده است.

## محدودیت‌ها و نکات

- **چالش ضدربات (HTTP 406):** CDN موزیلا ممکن است هنگام لاگین چالش ضدربات برگرداند. این نسخه آن را **خودکار حل نمی‌کند**؛ خودت چالش را در مرورگر واقعی رد می‌کنی و کوکی را ذخیره می‌کنی:

  ```bash
  python -m foxyvpn_py challenge     # راهنمای مرحله‌به‌مرحله + ذخیره‌ی Cookie و User-Agent
  python -m foxyvpn_py login         # این بار با همان نشست
  python -m foxyvpn_py challenge --clear
  ```

  کوکی به IP همان شبکه گره خورده است، پس مرورگر و برنامه باید از یک IP استفاده کنند (مثلاً اگر برنامه را پشت پروکسی می‌چرخانی، IP خروجی عوض می‌شود و کوکی از کار می‌افتد). کوکی و User-Agent در `~/.foxyvpn-py/session.json` با دسترسی `0600` ذخیره می‌شوند و مثل رمز عبور باید محرمانه بمانند.
- فقط ترافیک TCP (SOCKS5 CONNECT). UDP، BIND و HTTP/3 پشتیبانی نمی‌شوند.
- سهمیه‌ی ماهانه‌ی ۵۰ گیگابایت حساب Firefox برای کاربران مرورگر است؛ استفاده از آن در کلاینت غیررسمی ممکن است خلاف شرایط استفاده‌ی موزیلا باشد و هر زمان ممکن است از کار بیفتد. مسئولیت استفاده با خودت است.
- فایل توکن معادل رمز ورود بلندمدت است؛ آن را به اشتراک نگذار و پروکسی را روی شبکه‌ی عمومی باز نکن (پیش‌فرض: `127.0.0.1`).
