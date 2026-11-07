#!/usr/bin/env python3
"""
Programador de copias de Montacode (GitHub Actions, programador.yml).

Abre el CMS con un Chrome sin pantalla, se identifica con la clave del programador y le pide «latidos» hasta que
no queda nada por hacer: el CMS exporta las bases de datos por tandas y lanza el trabajador de archivos (backup.yml).
Es exactamente lo que hace el navegador del administrador cuando tiene el CMS abierto.

El registro de GitHub es público: aquí solo se escriben números, nunca nombres de clientes, servidores ni errores.
Sale con error (y GitHub avisa por email) si alguna web va con retraso o alguna copia de hoy ha fallado.
"""
import json
import os
import smtplib
import ssl
import sys
import time
from email.message import EmailMessage

from playwright.sync_api import sync_playwright, Error as PwError

URL = os.environ.get('ROBOT_URL', '').strip()
KEY = os.environ.get('ROBOT_KEY', '').strip()
MAX_MINUTES = int(os.environ.get('MAX_MINUTES', '200'))
# Avisos de MontaCare por email (opcional): secretos SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS y MAIL_TO.
SMTP = {k: os.environ.get(k, '').strip() for k in ('SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS', 'MAIL_TO')}

POST_JS = """async (d) => {
  const r = await fetch(location.pathname, {method: 'POST', body: new URLSearchParams(d), credentials: 'same-origin'});
  return {status: r.status, text: await r.text()};
}"""


def log(msg):
    print(time.strftime('%H:%M:%S'), msg, flush=True)


def fail(msg):
    log('ERROR: ' + msg)
    sys.exit(1)


class Cms:
    def __init__(self, page):
        self.page = page
        self.csrf = ''

    def open(self):
        """Carga robot.php. La primera vez InfinityFree enseña su comprobación anti-robots (JavaScript): Chrome la pasa solo."""
        last = ''
        for attempt in range(3):
            try:
                self.page.goto(URL, wait_until='domcontentloaded', timeout=60000)
                self.page.wait_for_selector('[data-robot]', timeout=60000, state='attached')
                return
            except PwError as e:
                last = str(e).splitlines()[0][:200]
                try:
                    body = self.page.inner_text('body', timeout=5000)[:300].replace('\n', ' ')
                except PwError:
                    body = ''
                log(f'Intento {attempt + 1}: no se ve la página del programador ({last}). Título: «{self.page.title()[:80]}». Texto: «{body}»')
                time.sleep(10)
        fail('No se ha podido abrir el CMS. Si el texto de arriba es una página de InfinityFree, su comprobación anti-robots está bloqueando al programador.')

    def post(self, data, retries=4):
        for attempt in range(retries + 1):
            try:
                r = self.page.evaluate(POST_JS, data)
            except PwError as e:
                r = {'status': 0, 'text': str(e)[:200]}
            try:
                j = json.loads(r['text'])
            except ValueError:
                j = None
            if j is not None and r['status'] in (200, 400, 401, 403, 419, 500):
                return r['status'], j
            # Respuesta que no es JSON: normalmente la comprobación de InfinityFree otra vez. Se recarga la página y se reintenta.
            log(f'Respuesta inesperada (HTTP {r["status"]}); reintentando…')
            time.sleep(15 * (attempt + 1))
            self.open()
        fail('El CMS no responde correctamente.')

    def login(self):
        code, j = self.post({'action': 'login', 'key': KEY})
        if code != 200 or not j.get('ok'):
            if j.get('off'):
                fail('El programador está desactivado en el CMS (no hay clave). Genera una en «Almacenamiento externo» y guárdala en el secreto ROBOT_KEY.')
            fail('El CMS ha rechazado la clave del programador. Genera una nueva en «Almacenamiento externo» y actualiza el secreto ROBOT_KEY.')
        self.csrf = j['csrf']

    def call(self, action):
        return self.call_data(action, {})

    def call_data(self, action, extra):
        for _ in range(3):
            code, j = self.post({'action': action, 'csrf': self.csrf, **extra})
            if code in (401, 419):  # sesión caducada: se vuelve a entrar
                self.login()
                continue
            return code, j
        fail('No se ha podido mantener la sesión con el CMS.')


def send_care_mail(cms):
    """Envía por email los avisos de MontaCare aún no enviados. El contenido nunca se escribe en el registro (es público)."""
    if not (SMTP['SMTP_HOST'] and SMTP['SMTP_USER'] and SMTP['SMTP_PASS'] and SMTP['MAIL_TO']):
        return
    code, d = cms.call('care_digest')
    if code != 200 or not d.get('ok') or not d.get('lines'):
        return
    msg = EmailMessage()
    msg['Subject'] = d['subject']
    msg['From'] = SMTP['SMTP_USER']
    msg['To'] = SMTP['MAIL_TO']
    msg.set_content('Avisos de MontaCare:\n\n' + '\n'.join(d['lines']) + '\n\nGestiónalos en ' + d['url'] + '\n')
    port = int(SMTP['SMTP_PORT'] or 465)
    try:
        if port == 465:
            with smtplib.SMTP_SSL(SMTP['SMTP_HOST'], port, context=ssl.create_default_context(), timeout=30) as s:
                s.login(SMTP['SMTP_USER'], SMTP['SMTP_PASS']); s.send_message(msg)
        else:
            with smtplib.SMTP(SMTP['SMTP_HOST'], port, timeout=30) as s:
                s.starttls(context=ssl.create_default_context()); s.login(SMTP['SMTP_USER'], SMTP['SMTP_PASS']); s.send_message(msg)
    except Exception as e:  # sin detalles: podrían incluir datos del servidor de correo
        log(f'No se ha podido enviar el email de avisos de MontaCare ({type(e).__name__}). Se reintentará en la próxima pasada.')
        return
    cms.call_data('care_mailed', {'ids': ','.join(str(i) for i in d.get('alert_ids', [])), 'request_max': str(d.get('request_max', 0))})
    log(f'Email de MontaCare enviado ({len(d["lines"])} aviso(s)).')


def main():
    if not URL.startswith('https://') or len(KEY) < 32:
        fail('Faltan los secretos ROBOT_URL (https://…/admin/robot.php) o ROBOT_KEY en el repositorio.')
    print(f'::add-mask::{URL}', flush=True)
    deadline = time.time() + MAX_MINUTES * 60

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        # Agente de usuario de un Chrome normal (el de serie dice «HeadlessChrome»).
        ua = f'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{browser.version} Safari/537.36'
        page = browser.new_context(user_agent=ua, locale='es-ES', timezone_id='Europe/Madrid').new_page()
        cms = Cms(page)
        cms.open()
        log('CMS abierto: la comprobación de InfinityFree se ha superado.')
        cms.login()
        log('Programador identificado. Avanzando copias…')

        ticks, errors, last_report = 0, 0, 0
        while time.time() < deadline:
            code, j = cms.call('tick')
            ticks += 1
            if code != 200 or not j.get('ok'):
                errors += 1
                log(f'El CMS ha devuelto un error (HTTP {code}). Detalles en la actividad de copias del CMS.')
                if errors >= 5:
                    break
                time.sleep(30)
                continue
            errors = 0
            if time.time() - last_report > 300:
                log(f'Copias en curso: {j["active"]} (exportando base de datos en el CMS: {j["cms"]}).')
                last_report = time.time()
            if j['busy']:
                time.sleep(4)
            elif j['more']:
                time.sleep(0.5)
            elif j['wait']:
                time.sleep(20)  # el trabajador de GitHub está copiando archivos: se pregunta cada 20 s
            else:
                break
        else:
            log(f'Se ha llegado al tiempo máximo ({MAX_MINUTES} min). Lo pendiente lo recogerá la siguiente pasada.')

        code, s = cms.call('status')
        if code == 200 and s.get('ok'):
            log(f'MontaCare: {s.get("care_new", 0)} aviso(s) de vencimiento nuevo(s), {s.get("care_pending", 0)} pendiente(s) en el CMS.')
            if s.get('care_mail'):
                send_care_mail(cms)
        browser.close()

    if code != 200 or not s.get('ok'):
        fail('No se ha podido consultar el estado final.')
    log(f'{ticks} latidos. Hoy: {s["ok_today"]} copia(s) correcta(s), {s["failed_today"]} con fallos. En curso: {s["active"]}.')
    problems = []
    if s['stale']:
        problems.append(f'{s["stale"]} web(s) llevan más de 36 h sin una copia correcta')
    if s['failed_today']:
        problems.append(f'{s["failed_today"]} copia(s) de hoy han fallado')
    if problems:
        fail('; '.join(problems) + '. Revisa «Copias de seguridad» en el CMS.')
    log('Todo al día.')


if __name__ == '__main__':
    main()
