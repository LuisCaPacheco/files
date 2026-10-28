"""
Demo OWASP Top 10:2025 - A10 Mishandling of Exceptional Conditions
(con puentes a A09 Logging & Alerting y A06 Insecure Design)

Una sola app FastAPI expone DOS implementaciones de la misma transferencia:
  /vulnerable/*  -> sin manejo correcto de excepciones (a propósito)
  /secure/*      -> con los controles que recomienda OWASP

Ejecutar:  uvicorn main:app --reload --port 8000   y abrir http://localhost:8000
SOLO para uso educativo en localhost.
"""
import logging
import os
import sqlite3
import time
import traceback
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from threading import Lock

from fastapi import FastAPI, HTTPException, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

BASE = os.path.dirname(os.path.abspath(__file__))
DB = {
    "vulnerable": os.path.join(BASE, "vulnerable.db"),
    "secure": os.path.join(BASE, "secure.db"),
}
CUENTAS = [("ANA", "Ana", 1000), ("BETO", "Beto", 1000), ("CARLA", "Carla", 1000)]
TOTAL_ESPERADO = sum(c[2] for c in CUENTAS)

MAX_MONTO = 10_000        # control: límite por transacción
RATE_LIMIT = 15           # control: solicitudes permitidas...
RATE_WINDOW = 10          # ...por ventana de N segundos y por IP

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("demo")

@asynccontextmanager
async def lifespan(_: FastAPI):
    for mode in DB:
        init_db(mode)
    yield


app = FastAPI(title="Demo OWASP A10:2025", lifespan=lifespan)


# ----------------------------------------------------------------- base de datos
def connect(mode: str) -> sqlite3.Connection:
    conn = sqlite3.connect(DB[mode], timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def init_db(mode: str) -> None:
    if os.path.exists(DB[mode]):
        os.remove(DB[mode])
    conn = connect(mode)
    conn.executescript(
        """
        CREATE TABLE accounts (id TEXT PRIMARY KEY, nombre TEXT, balance INTEGER);
        CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT,
                            evento TEXT, detalle TEXT, error_id TEXT);
        """
    )
    conn.executemany("INSERT INTO accounts VALUES (?,?,?)", CUENTAS)
    if mode == "secure":
        # A09: bitácora con integridad (append-only): nadie puede editar ni borrar filas
        conn.executescript(
            """
            CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit
              BEGIN SELECT RAISE(ABORT, 'audit es append-only'); END;
            CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit
              BEGIN SELECT RAISE(ABORT, 'audit es append-only'); END;
            """
        )
    conn.commit()
    conn.close()


def write_audit(mode: str, evento: str, detalle: str, error_id: str | None = None) -> None:
    conn = connect(mode)
    try:
        conn.execute(
            "INSERT INTO audit(ts, evento, detalle, error_id) VALUES (?,?,?,?)",
            (now(), evento, detalle, error_id),
        )
        conn.commit()
    finally:
        conn.close()


# ----------------------------------------------------------------- modelos
class Transfer(BaseModel):
    """Entrada de la API VULNERABLE: acepta casi cualquier cosa (monto negativo, cuentas raras)."""
    origen: str
    destino: str
    monto: int
    caida_a_mitad: bool = False   # inyección de fallo SOLO para la demo


class SecureTransfer(BaseModel):
    """Entrada de la API SEGURA: validación estricta de entrada."""
    origen: str = Field(min_length=1, max_length=20, pattern=r"^[A-Za-z]+$")
    destino: str = Field(min_length=1, max_length=20, pattern=r"^[A-Za-z]+$")
    monto: int = Field(gt=0, le=MAX_MONTO)
    caida_a_mitad: bool = False   # inyección de fallo SOLO para la demo


class BusinessError(Exception):
    """Error esperado de negocio (se informa al usuario con un mensaje seguro)."""


# ================================================================== VULNERABLE
@app.post("/vulnerable/transfer")
def vulnerable_transfer(t: Transfer):
    conn = connect("vulnerable")
    sql = ""
    try:
        # Paso 1: debitar (y confirmar enseguida: no hay transacción atómica)
        sql = "UPDATE accounts SET balance = balance - ? WHERE id = ?"
        conn.execute(sql, (t.monto, t.origen))
        conn.commit()

        if t.caida_a_mitad:
            raise RuntimeError("Se perdió la conexión con el servicio de acreditación")

        # Paso 2: acreditar (si el destino no existe, esto revienta con TypeError)
        sql = "SELECT balance FROM accounts WHERE id = ?"
        _ = conn.execute(sql, (t.destino,)).fetchone()["balance"]
        sql = "UPDATE accounts SET balance = balance + ? WHERE id = ?"
        conn.execute(sql, (t.monto, t.destino))
        conn.commit()

        # Paso 3: registrar (solo se llega aquí si todo salió bien)
        write_audit("vulnerable", "TRANSFERENCIA_OK", f"{t.origen}->{t.destino} {t.monto}")
        return {"ok": True, "mensaje": "Transferencia realizada"}
    except Exception as e:
        # MAL: se devuelve TODO al cliente (CWE-209), no hay rollback, no se registra nada
        return JSONResponse(
            status_code=500,
            content={
                "error": str(e),
                "tipo": type(e).__name__,
                "sql": sql,
                "base_de_datos": DB["vulnerable"],
                "traceback": traceback.format_exc(),
            },
        )
    finally:
        conn.close()


# ================================================================== SEGURA
_hits: dict[str, deque] = defaultdict(deque)
_last_alert: dict[str, float] = {}
_lock = Lock()


def check_rate_limit(request: Request) -> None:
    ip = request.client.host if request.client else "desconocida"
    t = time.monotonic()
    with _lock:
        q = _hits[ip]
        while q and t - q[0] > RATE_WINDOW:
            q.popleft()
        blocked = len(q) >= RATE_LIMIT
        if not blocked:
            q.append(t)
        first_alert = blocked and t - _last_alert.get(ip, -1e9) > RATE_WINDOW
        if first_alert:
            _last_alert[ip] = t
    if blocked:
        if first_alert:  # A09: se alerta una vez por ventana (evita inundar al SOC)
            log.warning("ALERTA posible abuso/automatización desde %s", ip)
            write_audit("secure", "ALERTA_RATE_LIMIT", f"ip={ip} >{RATE_LIMIT}/{RATE_WINDOW}s")
        raise HTTPException(status_code=429, detail="Demasiadas solicitudes. Intenta de nuevo en unos segundos.")


def _rollback(conn: sqlite3.Connection) -> None:
    try:
        conn.execute("ROLLBACK")
    except sqlite3.Error:
        pass


@app.post("/secure/transfer")
def secure_transfer(t: SecureTransfer, request: Request):
    check_rate_limit(request)
    origen, destino = t.origen.upper(), t.destino.upper()
    detalle = f"{origen}->{destino} {t.monto}"
    conn = connect("secure")
    conn.isolation_level = None  # control manual de la transacción
    try:
        conn.execute("BEGIN IMMEDIATE")  # todo o nada

        if origen == destino:
            raise BusinessError("La cuenta de origen y la de destino deben ser distintas")
        existentes = conn.execute(
            "SELECT COUNT(*) FROM accounts WHERE id IN (?, ?)", (origen, destino)
        ).fetchone()[0]
        if existentes != 2:
            raise BusinessError("Cuenta de origen o destino no válida")

        cur = conn.execute(
            "UPDATE accounts SET balance = balance - ? WHERE id = ? AND balance >= ?",
            (t.monto, origen, t.monto),
        )
        if cur.rowcount != 1:
            raise BusinessError("Fondos insuficientes")

        if t.caida_a_mitad:
            raise RuntimeError("Fallo simulado entre el débito y el crédito")

        conn.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (t.monto, destino))
        conn.execute(
            "INSERT INTO audit(ts, evento, detalle, error_id) VALUES (?,?,?,?)",
            (now(), "TRANSFERENCIA_OK", detalle, None),
        )
        conn.execute("COMMIT")
        return {"ok": True, "mensaje": "Transferencia realizada"}

    except BusinessError as e:
        _rollback(conn)
        write_audit("secure", "TRANSFERENCIA_RECHAZADA", f"{detalle} ({e})")
        return JSONResponse(status_code=422, content={"ok": False, "error": str(e)})

    except Exception:
        _rollback(conn)  # fail closed: se deshace TODO
        error_id = uuid.uuid4().hex[:8]
        log.exception("[%s] error inesperado en transferencia %s", error_id, detalle)  # detalle solo en servidor
        write_audit("secure", "ERROR_INTERNO", detalle, error_id)
        return JSONResponse(
            status_code=500,
            content={
                "ok": False,
                "error": "No se pudo completar la operación. Ningún saldo fue modificado.",
                "error_id": error_id,
            },
        )
    finally:
        conn.close()


# ----------------------------------------------------------------- manejadores globales
@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    if request.url.path.startswith("/secure"):
        error_id = uuid.uuid4().hex[:8]
        log.warning("[%s] entrada inválida en %s", error_id, request.url.path)
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "Datos de la transferencia inválidos", "error_id": error_id},
        )
    return await request_validation_exception_handler(request, exc)  # la vulnerable filtra el detalle


@app.exception_handler(HTTPException)
async def http_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"ok": False, "error": exc.detail})


@app.exception_handler(Exception)
async def global_handler(request: Request, exc: Exception):
    """Manejador global de respaldo: por si algo se nos escapó."""
    error_id = uuid.uuid4().hex[:8]
    log.error("[%s] excepción no controlada en %s: %r", error_id, request.url.path, exc)
    return JSONResponse(
        status_code=500,
        content={"ok": False, "error": "Error interno. Intenta de nuevo más tarde.", "error_id": error_id},
    )


# ----------------------------------------------------------------- utilidades comunes
def _modo(mode: str) -> str:
    if mode not in DB:
        raise HTTPException(status_code=404, detail="No encontrado")
    return mode


@app.get("/{mode}/accounts")
def accounts(mode: str):
    conn = connect(_modo(mode))
    try:
        rows = conn.execute("SELECT id, nombre, balance FROM accounts ORDER BY id").fetchall()
    finally:
        conn.close()
    cuentas = [{"id": r["id"], "nombre": r["nombre"], "saldo": r["balance"]} for r in rows]
    return {"cuentas": cuentas, "total": sum(c["saldo"] for c in cuentas), "total_esperado": TOTAL_ESPERADO}


@app.get("/{mode}/audit")
def audit(mode: str):
    conn = connect(_modo(mode))
    try:
        rows = conn.execute("SELECT ts, evento, detalle, error_id FROM audit ORDER BY id DESC LIMIT 12").fetchall()
    finally:
        conn.close()
    return {"eventos": [dict(r) for r in rows]}


@app.post("/{mode}/reset")
def reset(mode: str):
    init_db(_modo(mode))
    if mode == "secure":
        with _lock:
            _hits.clear()
            _last_alert.clear()
    return {"ok": True}


@app.get("/")
def index():
    return FileResponse(os.path.join(BASE, "static", "index.html"))
