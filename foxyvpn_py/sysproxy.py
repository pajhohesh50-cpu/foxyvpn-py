import winreg
import ctypes
import logging

log = logging.getLogger("foxyvpn.sysproxy")

# مسیر رجیستری تنظیمات اینترنت
INTERNET_SETTINGS = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'

def _set_registry_value(name: str, value):
    """تنظیم یک مقدار در رجیستری ویندوز."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_ALL_ACCESS) as key:
            _, reg_type = winreg.QueryValueEx(key, name)
            winreg.SetValueEx(key, name, 0, reg_type, value)
    except FileNotFoundError:
        # اگر مقدار وجود نداشت، با نوع مناسب بساز
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_ALL_ACCESS) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)

def _refresh_wininet():
    """به ویندوز اطلاع می‌دهد که تنظیمات پروکسی تغییر کرده است."""
    INTERNET_OPTION_REFRESH = 37
    INTERNET_OPTION_SETTINGS_CHANGED = 39
    internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
    internet_set_option(0, INTERNET_OPTION_REFRESH, 0, 0)
    internet_set_option(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)

def enable_system_proxy(host: str = "127.0.0.1", port: int = 1088):
    """پروکسی سیستم را فعال می‌کند."""
    try:
        _set_registry_value('ProxyEnable', 1)
        _set_registry_value('ProxyServer', f'{host}:{port}')
        # از پروکسی برای آدرس‌های لوکال استفاده نشود
        _set_registry_value('ProxyOverride', '<local>')
        _refresh_wininet()
        log.info("System proxy enabled: %s:%d", host, port)
    except Exception as e:
        log.warning("Failed to enable system proxy: %s", e)

def disable_system_proxy():
    """پروکسی سیستم را غیرفعال می‌کند."""
    try:
        _set_registry_value('ProxyEnable', 0)
        _refresh_wininet()
        log.info("System proxy disabled.")
    except Exception as e:
        log.warning("Failed to disable system proxy: %s", e)