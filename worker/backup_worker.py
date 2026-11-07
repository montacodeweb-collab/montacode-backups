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
import hashlib
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
PROGRESS_NAME = 'progreso_trabajador.json'  # lo que está haciendo ahora; el CMS lo muestra en directo
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

    def update_bytes(self, file_id, content, mime):
        req = urllib.request.Request(
            f'https://www.googleapis.com/upload/drive/v3/files/{file_id}?uploadType=media&fields=id', data=content, method='PATCH',
            headers={'Authorization': 'Bearer ' + self.access(), 'Content-Type': mime})
        return json.loads(self._send(req, timeout=60).read())

    def delete(self, file_id):
        req = urllib.request.Request(f'https://www.googleapis.com/drive/v3/files/{file_id}', method='DELETE',
                                     headers={'Authorization': 'Bearer ' + self.access()})
        self._send(req, timeout=60)

    def upload_file(self, path, name, parent, mime, on_progress=None):
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
                        if on_progress and size:
                            on_progress(offset * 100 // size)
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


class Progress:
    """Deja en Drive un pequeño JSON con lo que se está haciendo (como mucho cada 20 s). Si falla, no pasa nada."""

    def __init__(self, drive, folder, run):
        self.drive, self.folder, self.run = drive, folder, run
        self.file_id, self.last = None, 0

    def __call__(self, msg, force=False):
        if not force and time.time() - self.last < 20:
            return
        self.last = time.time()
        body = json.dumps({'run': self.run, 'msg': msg}, ensure_ascii=False).encode()
        try:
            if self.file_id:
                self.drive.update_bytes(self.file_id, body, 'application/json')
            else:
                self.file_id = self.drive.upload_bytes(body, PROGRESS_NAME, self.folder, 'application/json').get('id')
        except Exception as e:
            log('Aviso: no se pudo actualizar el progreso. ' + clean(e)[:120])

    def remove(self):
        if self.file_id:
            try:
                self.drive.delete(self.file_id)
            except Exception:
                pass


def mb(n):
    return f'{n / 1048576:.1f} MB'.replace('.', ',')


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
        """[(nombre, es_carpeta, huella)] de una carpeta. MLSD si el servidor lo admite; si no, LIST.
        La huella (tamaño y fecha) sirve para saber si algo ha cambiado sin descargarlo."""
        try:
            return [(n, f.get('type') == 'dir', f.get('size', '') + '@' + f.get('modify', ''))
                    for n, f in self.conn.mlsd(path, facts=['type', 'size', 'modify'])
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
            out.append((name, line[0] == 'd', parts[4] + '@' + ' '.join(parts[5:8])))
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


def backup_files(cfg, work, drive, folder, progress):
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
    progress('Archivos: conectado por FTP, revisando si hay cambios…', True)
    try:
        ftp.listdir(root)
    except ftplib.error_perm:
        raise RuntimeError(f'La carpeta {root} no existe en el FTP.')

    # 1) Listado completo (sin descargar nada) y huella: rutas + tamaños + fechas.
    files, dirs, skipped = [], [], []
    stack = ['']
    while stack:
        rel_dir = stack.pop()
        remote_dir = root.rstrip('/') + ('/' + rel_dir if rel_dir else '') or '/'
        try:
            entries = ftp.listdir(remote_dir)
        except Exception as e:
            skipped.append(rel_dir + '/ (' + clean(e)[:80] + ')')
            continue
        if rel_dir:
            dirs.append(rel_dir)
        for name, is_dir, mark in sorted(entries):
            rel = (rel_dir + '/' if rel_dir else '') + name
            if excluded(rel, is_dir, patterns):
                continue
            if is_dir:
                stack.append(rel)
            else:
                files.append((rel, remote_dir.rstrip('/') + '/' + name, mark))
        progress(f'Archivos: revisando si hay cambios… {len(files)} encontrados')
    h = hashlib.sha256()
    for rel, _, mark in sorted(files):
        h.update(f'{rel}\t{mark}\n'.encode('utf-8', 'replace'))
    for d in sorted(dirs):
        h.update(f'{d}/\n'.encode('utf-8', 'replace'))
    for x in sorted(skipped):
        h.update(f'!{x}\n'.encode('utf-8', 'replace'))
    manifest = h.hexdigest()
    log(f'{len(files)} archivos en {len(dirs) + 1} carpetas.')

    if cfg.get('manifest') and cfg['manifest'] == manifest:
        try:
            ftp.conn.quit()
        except Exception:
            pass
        log('Sin cambios desde la última copia completa: no se descarga nada.')
        return {'status': 'same', 'manifest': manifest, 'count': len(files), 'skipped': len(skipped), 'skipped_list': skipped[:50]}

    # 2) Hay cambios (o toca la copia completa semanal): se descarga todo y se sube archivos.zip.
    zip_path = os.path.join(work, 'archivos.zip')
    tmp = os.path.join(work, 'descarga.tmp')
    count, total = 0, 0
    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as z:
        for d in dirs:
            z.writestr(d + '/', b'')
        for rel, remote, _ in files:
            try:
                ftp.download(remote, tmp)
                z.write(tmp, rel)
                total += os.path.getsize(tmp)
                count += 1
                if count % 250 == 0:
                    log(f'{count} archivos copiados…')
                progress(f'Archivos: {count} de {len(files)} descargados ({mb(total)})…')
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
    zsize = os.path.getsize(zip_path)
    progress(f'Archivos: {count} descargados. Subiendo archivos.zip ({mb(zsize)}) a Drive…', True)
    f = drive.upload_file(zip_path, 'archivos.zip', folder, 'application/zip',
                          lambda pct: progress(f'Archivos: subiendo archivos.zip ({mb(zsize)}) a Drive · {pct}%'))
    os.remove(zip_path)
    # Si algún archivo no se pudo descargar, la huella no se guarda: la próxima vez se vuelve a intentar entero.
    return {'status': 'done', 'id': f.get('id', ''), 'size': zsize, 'count': count, 'manifest': '' if skipped else manifest,
            'skipped': len(skipped), 'skipped_list': skipped[:50]}


# ---------------------------------------------------------------- MySQL → SQL.GZ

def backup_db(cfg, work, drive, folder, progress):
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
    progress('Base de datos: exportando con mysqldump…', True)
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
    progress(f'Base de datos: subiendo base_datos.sql.gz ({mb(size)}) a Drive…', True)
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
    progress = Progress(drive, data['folder'], data['run'])
    status = {'run': data['run'], 'files': None, 'db': None}
    work = tempfile.mkdtemp(prefix='montacode-')
    try:
        if files:
            try:
                status['files'] = backup_files(files, work, drive, data['folder'], progress)
                log('Archivos: correcto.')
            except Exception as e:
                status['files'] = {'status': 'error', 'error': clean(e)}
                log('Archivos: error. ' + clean(e))
        if db:
            try:
                status['db'] = backup_db(db, work, drive, data['folder'], progress)
                log('Base de datos: correcto.')
            except Exception as e:
                status['db'] = {'status': 'error', 'error': clean(e)}
                log('Base de datos: error. ' + clean(e))
    finally:
        shutil.rmtree(work, ignore_errors=True)
        progress.remove()
        status['finished'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        drive.upload_bytes(json.dumps(status, ensure_ascii=False).encode(), STATUS_NAME, data['folder'], 'application/json')
        log('Resultado enviado al CMS.')

    if any(s and s.get('status') == 'error' for s in (status['files'], status['db'])):
        sys.exit(2)


if __name__ == '__main__':
    main()
