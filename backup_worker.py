#!/usr/bin/env python3
"""
Trabajador de copias de Montacode (GitHub Actions).

Lo lanza el CMS con dos entradas: el número de copia y un «payload» cifrado con la clave pública del trabajador
(sobre sellado de libsodium). Aquí se descifra con el secreto WORKER_PRIVATE_KEY y:
  - Archivos: descarga por FTP/FTPS la carpeta de la web (solo lectura) y la sube a Drive como archivos.zip.
  - Base de datos (solo hostings que no son InfinityFree): mysqldump → base_datos.sql.gz.
Al terminar deja «estado_trabajador.json» en la carpeta de la copia; el CMS lo lee y cierra la copia.

El registro de GitHub no muestra servidores, usuarios, contraseñas ni nombres de archivos.
Nunca se modifica ni se borra nada en el servidor de origen.
"""
import base64
import fnmatch
import ftplib
import gzip
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from nacl.public import PrivateKey, SealedBox

CHUNK = 8 * 1024 * 1024  # múltiplo de 256 KB (requisito de las subidas reanudables de Drive)
STATUS_NAME = 'estado_trabajador.json'
SECRETS = []


def log(msg):
    print(time.strftime('%H:%M:%S'), msg, flush=True)


def mask(value):
    """Oculta un valor en el registro de GitHub y en los mensajes de error."""
    if value:
        value = str(value)
        SECRETS.append(value)
        print(f'::add-mask::{value}', flush=True)


def clean(msg):
    msg = str(msg)
    for s in SECRETS:
        if s and len(s) > 2:
            msg = msg.replace(s, '***')
    return msg[:500]


# ---------------------------------------------------------------- Google Drive

class Drive:
    def __init__(self, cfg):
        self.cfg = cfg
        self.token = None
        self.exp = 0

    def access(self):
        if self.token and time.time() < self.exp - 120:
            return self.token
        data = urllib.parse.urlencode({
            'client_id': self.cfg['client_id'], 'client_secret': self.cfg['client_secret'],
            'refresh_token': self.cfg['refresh_token'], 'grant_type': 'refresh_token'}).encode()
        req = urllib.request.Request('https://oauth2.googleapis.com/token', data=data, method='POST')
        j = json.loads(self._send(req).read())
        self.token = j['access_token']
        self.exp = time.time() + int(j.get('expires_in', 3600))
        mask(self.token)
        return self.token

    @staticmethod
    def _send(req, timeout=300):
        for attempt in range(5):
            try:
                return urllib.request.urlopen(req, timeout=timeout)
            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 502, 503, 504) and attempt < 4:
                    time.sleep(3 * (attempt + 1))
                    continue
                raise RuntimeError(f'Google respondió {e.code}: {e.read()[:300].decode("utf-8", "replace")}')
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                if attempt < 4:
                    time.sleep(3 * (attempt + 1))
                    continue
                raise RuntimeError(f'Sin conexión con Google: {e}')

    def upload_bytes(self, content, name, parent, mime):
        boundary = 'mc' + os.urandom(8).hex()
        meta = json.dumps({'name': name, 'parents': [parent]}).encode()
        body = (f'--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n'.encode() + meta
                + f'\r\n--{boundary}\r\nContent-Type: {mime}\r\n\r\n'.encode() + content + f'\r\n--{boundary}--'.encode())
        req = urllib.request.Request(
            'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id', data=body, method='POST',
            headers={'Authorization': 'Bearer ' + self.access(), 'Content-Type': f'multipart/related; boundary={boundary}'})
        return json.loads(self._send(req).read())

    def upload_file(self, path, name, parent, mime):
        """Subida reanudable por trozos de 8 MB; si se corta, pregunta a Drive cuánto tiene y sigue desde ahí."""
        size = os.path.getsize(path)
        req = urllib.request.Request(
            'https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&fields=id,size',
            data=json.dumps({'name': name, 'parents': [parent]}).encode(), method='POST',
            headers={'Authorization': 'Bearer ' + self.access(), 'Content-Type': 'application/json; charset=UTF-8',
                     'X-Upload-Content-Type': mime, 'X-Upload-Content-Length': str(size)})
        session = self._send(req).headers['Location']
        offset, errors = 0, 0
        with open(path, 'rb') as f:
            while True:
                f.seek(offset)
                chunk = f.read(CHUNK)
                rng = f'bytes {offset}-{offset + len(chunk) - 1}/{size}' if chunk else f'bytes */{size}'
                req = urllib.request.Request(session, data=chunk, method='PUT', headers={'Content-Range': rng})
                try:
                    with urllib.request.urlopen(req, timeout=600) as r:
                        return json.loads(r.read())  # 200/201: completo
                except urllib.error.HTTPError as e:
                    if e.code == 308:  # trozo recibido, falta más
                        offset = self._range_end(e.headers)
                        errors = 0
                        continue
                    if e.code in (429, 500, 502, 503, 504) and errors < 6:
                        errors += 1
                        time.sleep(5 * errors)
                        offset = self._status(session, size)
                        continue
                    raise RuntimeError(f'Drive rechazó la subida ({e.code}).')
                except (urllib.error.URLError, TimeoutError, ConnectionError):
                    if errors >= 6:
                        raise RuntimeError('Se ha cortado la subida a Drive demasiadas veces.')
                    errors += 1
                    time.sleep(5 * errors)
                    offset = self._status(session, size)

    @staticmethod
    def _range_end(headers):
        r = headers.get('Range') or ''
        return int(r.rsplit('-', 1)[1]) + 1 if '-' in r else 0

    def _status(self, session, size):
        req = urllib.request.Request(session, data=b'', method='PUT', headers={'Content-Range': f'bytes */{size}'})
        try:
            urllib.request.urlopen(req, timeout=60)
            return size
        except urllib.error.HTTPError as e:
            if e.code == 308:
                return self._range_end(e.headers)
            raise RuntimeError(f'Drive no reconoce la subida ({e.code}).')


# ---------------------------------------------------------------- FTP → ZIP

class Ftp:
    def __init__(self, cfg):
        self.cfg = cfg
        self.conn = None

    def connect(self):
        c = self.cfg
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
        if c.get('secure'):
            ftp = ftplib.FTP_TLS(context=ssl.create_default_context(), timeout=90)
            ftp.connect(c['host'], int(c['port']))
            ftp.login(c['user'], c['password'])
            ftp.prot_p()
        else:
            ftp = ftplib.FTP(timeout=90)
            ftp.connect(c['host'], int(c['port']))
            ftp.login(c['user'], c['password'])
        ftp.set_pasv(True)
        self.conn = ftp

    def retry(self, fn, *args):
        for attempt in range(4):
            try:
                return fn(*args)
            except ftplib.error_perm:
                raise
            except (ftplib.Error, OSError, EOFError):
                if attempt == 3:
                    raise
                time.sleep(4 * (attempt + 1))
                self.connect()

    def _listdir(self, path):
        """[(nombre, es_carpeta)] de una carpeta. MLSD si el servidor lo admite; si no, LIST."""
        try:
            return [(n, f.get('type') == 'dir') for n, f in self.conn.mlsd(path, facts=['type'])
                    if f.get('type') in ('file', 'dir')]
        except ftplib.error_perm:
            pass
        self.conn.cwd(path)
        lines = []
        self.conn.retrlines('LIST -a', lines.append)
        out = []
        for line in lines:
            parts = line.split(None, 8)
            if len(parts) < 9 or line[0] not in '-d':
                continue  # enlaces simbólicos y líneas raras: se ignoran
            name = parts[8]
            if name in ('.', '..'):
                continue
            out.append((name, line[0] == 'd'))
        return out

    def listdir(self, path):
        return self.retry(self._listdir, path)

    def _download(self, remote, local):
        with open(local, 'wb') as f:
            self.conn.retrbinary('RETR ' + remote, f.write, blocksize=262144)

    def download(self, remote, local):
        return self.retry(self._download, remote, local)


def excluded(rel, is_dir, patterns):
    name = rel.rsplit('/', 1)[-1]
    for p in patterns:
        if p.endswith('/'):
            p = p.rstrip('/')
            if is_dir and (fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(name, p)):
                return True
        elif not is_dir and (fnmatch.fnmatch(name, p) or fnmatch.fnmatch(rel, p)):
            return True
    return False


def backup_files(cfg, work, drive, folder):
    root = '/' + cfg['path'].strip('/') if cfg['path'].strip('/') else '/'
    if '..' in root.split('/'):
        raise RuntimeError('Carpeta no permitida.')
    patterns = [p.strip() for p in cfg.get('exclude', []) if p.strip()]
    ftp = Ftp(cfg)
    try:
        ftp.connect()
    except ftplib.error_perm:
        raise RuntimeError('El servidor FTP ha rechazado el usuario o la contraseña.')
    except (OSError, ftplib.Error) as e:
        raise RuntimeError(f'No se pudo conectar por FTP: {e}')
    log('Conectado por FTP. Listando archivos…')
    try:
        ftp.listdir(root)
    except ftplib.error_perm:
        raise RuntimeError(f'La carpeta {root} no existe en el FTP.')

    zip_path = os.path.join(work, 'archivos.zip')
    tmp = os.path.join(work, 'descarga.tmp')
    count, skipped, total = 0, [], 0
    stack = ['']
    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as z:
        while stack:
            rel_dir = stack.pop()
            remote_dir = root.rstrip('/') + ('/' + rel_dir if rel_dir else '') or '/'
            try:
                entries = ftp.listdir(remote_dir)
            except Exception as e:
                skipped.append(rel_dir + '/ (' + clean(e)[:80] + ')')
                continue
            if rel_dir:
                z.writestr(rel_dir + '/', b'')
            for name, is_dir in sorted(entries):
                rel = (rel_dir + '/' if rel_dir else '') + name
                if excluded(rel, is_dir, patterns):
                    continue
                if is_dir:
                    stack.append(rel)
                    continue
                try:
                    ftp.download(remote_dir.rstrip('/') + '/' + name, tmp)
                    z.write(tmp, rel)
                    total += os.path.getsize(tmp)
                    count += 1
                    if count % 250 == 0:
                        log(f'{count} archivos copiados…')
                except Exception as e:
                    skipped.append(rel + ' (' + clean(e)[:80] + ')')
    try:
        ftp.conn.quit()
    except Exception:
        pass
    if os.path.exists(tmp):
        os.remove(tmp)
    if count == 0 and skipped:
        raise RuntimeError('No se ha podido descargar ningún archivo.')
    log(f'{count} archivos ({total // 1048576} MB sin comprimir), {len(skipped)} no copiados. Subiendo a Drive…')
    f = drive.upload_file(zip_path, 'archivos.zip', folder, 'application/zip')
    size = os.path.getsize(zip_path)
    os.remove(zip_path)
    return {'status': 'done', 'id': f.get('id', ''), 'size': size, 'count': count,
            'skipped': len(skipped), 'skipped_list': skipped[:50]}


# ---------------------------------------------------------------- MySQL → SQL.GZ

def backup_db(cfg, work, drive, folder):
    version = subprocess.run(['mysqldump', '--version'], capture_output=True, text=True).stdout
    args = ['mysqldump', '-h', cfg['host'], '-P', str(int(cfg['port'])), '-u', cfg['user'],
            '--single-transaction', '--quick', '--skip-lock-tables', '--no-tablespaces',
            '--default-character-set=utf8mb4', '--hex-blob', '--skip-comments']
    if 'MariaDB' not in version:
        args += ['--set-gtid-purged=OFF', '--column-statistics=0']
    args += ['--', cfg['name']]
    env = dict(os.environ, MYSQL_PWD=cfg['password'])
    out = os.path.join(work, 'base_datos.sql.gz')
    log('Exportando la base de datos…')
    with open(os.path.join(work, 'mysqldump.err'), 'w+b') as err:
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=err, env=env)
        with gzip.open(out, 'wb', compresslevel=6) as g:
            shutil.copyfileobj(p.stdout, g, 1 << 20)
        rc = p.wait()
        err.seek(0)
        msg = err.read().decode('utf-8', 'replace')
    if rc != 0:
        msg = '\n'.join(l for l in msg.splitlines() if 'Using a password' not in l)
        raise RuntimeError('mysqldump: ' + clean(msg.strip() or f'código {rc}'))
    size = os.path.getsize(out)
    log(f'Base de datos exportada ({size // 1024} KB comprimida). Subiendo a Drive…')
    f = drive.upload_file(out, 'base_datos.sql.gz', folder, 'application/gzip')
    os.remove(out)
    return {'status': 'done', 'id': f.get('id', ''), 'size': size}


# ---------------------------------------------------------------- Principal

def main():
    run_id = os.environ.get('RUN_ID', '')
    try:
        key = PrivateKey(base64.b64decode(os.environ['WORKER_PRIVATE_KEY'].strip()))
        data = json.loads(SealedBox(key).decrypt(base64.b64decode(os.environ['PAYLOAD'])))
    except Exception:
        log('No se pudieron descifrar los datos. ¿El secreto WORKER_PRIVATE_KEY corresponde a la clave generada en el CMS?')
        sys.exit(1)

    g, files, db = data['google'], data.get('files'), data.get('db')
    mask(g['client_secret'])
    mask(g['refresh_token'])
    for part in (files, db):
        if part:
            for k in ('host', 'user', 'password', 'name', 'path'):
                if part.get(k) and part.get(k) != '/':
                    mask(part[k])
    mask(data['folder'])

    if str(data['run']) != run_id:
        log('El número de copia no coincide con los datos cifrados.')
        sys.exit(1)
    if time.time() > data['exp']:
        log('Datos caducados: esta copia se lanzó hace demasiado tiempo.')
        sys.exit(1)

    drive = Drive(g)
    status = {'run': data['run'], 'files': None, 'db': None}
    work = tempfile.mkdtemp(prefix='montacode-')
    try:
        if files:
            try:
                status['files'] = backup_files(files, work, drive, data['folder'])
                log('Archivos: correcto.')
            except Exception as e:
                status['files'] = {'status': 'error', 'error': clean(e)}
                log('Archivos: error. ' + clean(e))
        if db:
            try:
                status['db'] = backup_db(db, work, drive, data['folder'])
                log('Base de datos: correcto.')
            except Exception as e:
                status['db'] = {'status': 'error', 'error': clean(e)}
                log('Base de datos: error. ' + clean(e))
    finally:
        shutil.rmtree(work, ignore_errors=True)
        status['finished'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        drive.upload_bytes(json.dumps(status, ensure_ascii=False).encode(), STATUS_NAME, data['folder'], 'application/json')
        log('Resultado enviado al CMS.')

    if any(s and s.get('status') == 'error' for s in (status['files'], status['db'])):
        sys.exit(2)


if __name__ == '__main__':
    main()
