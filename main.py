# -*- coding: utf-8 -*-
import os
import sys
import time
import uuid
import hmac
import hashlib
import requests
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.clock import Clock
from kivy.utils import platform

# 自动注入的验证参数
API_URL = "https://ww.wlyz.asia/api/verify"
INJECTED_APP_KEY = "APP_1aa1e5d890dc2c0f58d938605e33d6d4"
INJECTED_APP_SECRET = "dd4d2975229d37b3420f96b70093dd9f584849ffd9e1646473ce8c835c91796e"
SECRET_KEY = b"my_super_secret_key_2024"

def get_machine_code():
    if platform == 'android':
        try:
            from jnius import autoclass
            context = autoclass('org.kivy.android.PythonActivity').mActivity
            resolver = context.getContentResolver()
            android_id = autoclass('android.provider.Settings$Secure').getString(resolver, 'android_id')
            return android_id or "unknown"
        except Exception:
            return "unknown"
    else:
        return str(uuid.getnode())

def generate_sign(app_key, app_secret, cdkey_norm, machine, ts, nonce):
    raw = "|".join([app_key, cdkey_norm, machine, app_secret, str(ts), nonce])
    return hmac.new(app_secret.encode('utf-8'), raw.encode('utf-8'), hashlib.sha256).hexdigest()

def request_api(cdkey, machine):
    ts = int(time.time())
    nonce = uuid.uuid4().hex[:16]
    cdkey_norm = cdkey.strip().upper()
    data = {
        "app_key": INJECTED_APP_KEY, "app_secret": INJECTED_APP_SECRET,
        "cdkey": cdkey, "machine": machine, "timestamp": ts, "nonce": nonce
    }
    data["sign"] = generate_sign(INJECTED_APP_KEY, INJECTED_APP_SECRET, cdkey_norm, machine, ts, nonce)
    try:
        resp = requests.post(API_URL, data=data, timeout=10)
        return resp.json()
    except Exception as e:
        return {"code": -99, "message": f"请求失败: {str(e)}"}

class LoginScreen(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.padding = 30
        self.spacing = 15

        self.add_widget(Label(text="网络验证", font_size=28, bold=True, size_hint_y=0.2))
        self.et_card = TextInput(hint_text="请输入您的卡密", multiline=False, font_size=18, size_hint_y=0.15)
        self.add_widget(self.et_card)

        self.btn_verify = Button(text="验证并安装", font_size=20, background_color=(0.29, 0.56, 0.89, 1), size_hint_y=0.15)
        self.btn_verify.bind(on_release=self.on_verify)
        self.add_widget(self.btn_verify)

        self.lbl_status = Label(text="", color=(0.85, 0.33, 0.31, 1), size_hint_y=0.1)
        self.add_widget(self.lbl_status)
        self.is_verifying = False

    def on_verify(self, instance):
        if self.is_verifying: return
        card = self.et_card.text.strip()
        if not card:
            self.lbl_status.text = "请输入卡密"
            return
        self.is_verifying = True
        self.btn_verify.disabled = True
        self.lbl_status.text = "正在联网验证..."

        machine = get_machine_code()
        import threading
        threading.Thread(target=self._do_request, args=(card, machine), daemon=True).start()

    def _do_request(self, card, machine):
        res = request_api(card, machine)
        Clock.schedule_once(lambda dt: self._on_result(res), 0)

    def _on_result(self, res):
        self.is_verifying = False
        self.btn_verify.disabled = False
        if not res or res.get("code") != 0:
            msg = res.get("message", "未知错误") if isinstance(res, dict) else str(res)
            self.lbl_status.text = f"失败：{msg}"
            return

        self.lbl_status.text = "验证通过，正在解密..."
        self.lbl_status.color = (0.2, 0.8, 0.2, 1)
        if platform == 'android':
            self.extract_and_install()
        else:
            self.lbl_status.text = "验证成功（电脑端无法安装）"

    def extract_and_install(self):
        from jnius import autoclass
        from android import mActivity

        src_enc = os.path.join(os.getcwd(), "payload.enc")
        dest_apk = os.path.join(mActivity.getExternalFilesDir(None).getAbsolutePath(), "business.apk")

        try:
            if not os.path.exists(src_enc):
                self.lbl_status.text = "找不到加密文件(payload.enc)"
                return

            with open(src_enc, "rb") as f:
                enc_data = f.read()

            decrypted_data = bytearray(len(enc_data))
            key_len = len(SECRET_KEY)
            for i in range(len(enc_data)):
                decrypted_data[i] = enc_data[i] ^ SECRET_KEY[i % key_len]

            with open(dest_apk, "wb") as f:
                f.write(decrypted_data)

            Intent = autoclass('android.content.Intent')
            Uri = autoclass('android.net.Uri')
            File = autoclass('java.io.File')
            FileProvider = autoclass('androidx.core.content.FileProvider')

            intent = Intent(Intent.ACTION_VIEW)
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            authority = mActivity.getPackageName() + ".fileprovider"
            uri = FileProvider.getUriForFile(mActivity, authority, File(dest_apk))
            intent.setDataAndType(uri, "application/vnd.android.package-archive")
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            mActivity.startActivity(intent)

            from kivy.clock import Clock
            Clock.schedule_once(lambda dt: os.remove(dest_apk) if os.path.exists(dest_apk) else None, 30)
        except Exception as e:
            self.lbl_status.text = f"安装失败: {str(e)}"

class ApkShellApp(App):
    def build(self):
        self.title = "验证系统"
        return LoginScreen()

if __name__ == '__main__':
    ApkShellApp().run()
