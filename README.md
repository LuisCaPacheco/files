# Demo OWASP A10:2025 – Mishandling of Exceptional Conditions

La **misma transferencia bancaria** implementada dos veces: sin controles (`/vulnerable`) y con los controles que recomienda OWASP (`/secure`). La interfaz las muestra lado a lado y cada escenario se envía a las dos a la vez.
Incluye puentes a **A09** (Security Logging and Alerting Failures) y **A06** (Insecure Design).

> **Solo para uso educativo y local.** La app escucha únicamente en `127.0.0.1:8000` y funciona sin internet.

## Cómo ejecutar

Requiere Python 3.11 o superior.

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate        macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt

python main.py                 # abre http://127.0.0.1:8000
pytest -q                      # pruebas automáticas (10 pruebas)
```

Las bases `vulnerable.db` y `secure.db` se recrean al iniciar y con el botón **Reiniciar demo**.

## Arquitectura

```
 Navegador ─ static/index.html (HTML + CSS + JS vanilla, sin CDN)
     │  cada escenario hace la MISMA petición a las dos APIs
     ▼
 FastAPI (main.py, un solo proceso, 127.0.0.1:8000)
     │
     ├── /vulnerable/transfer ──► vulnerable.db
     │      débito con commit inmediato → crédito (sin rollback)
     │      sin validación · sin rate limit · errores con traceback y SQL
     │      bitácora solo de éxitos
     │
     ├── /secure/transfer ──► rate limit (15 / 10 s por IP) ──► validación estricta
     │      ──► BEGIN IMMEDIATE … COMMIT  |  ROLLBACK ante cualquier excepción
     │      ──► secure.db  (bitácora append-only con triggers)
     │      errores: 400 / 422 / 429 / 500 genéricos con error_id
     │      detalle técnico solo en el log del servidor
     │
     └── comunes: GET /{modo}/accounts · GET /{modo}/audit · POST /{modo}/reset · GET /
```

## Guion de demo (6 minutos)

Antes de empezar, pulsa **Reiniciar demo**. Los dos medidores deben mostrar **$3.000 · Íntegro**.

| Tiempo | Botón | Qué señalar en "Sin controles" | Qué señalar en "Con controles" | OWASP |
|---|---|---|---|---|
| 0:00–0:45 | — | Presenta la idea: la suma de todas las cuentas siempre debe ser $3.000. El medidor es el "detector de mentiras". | Lo mismo. | — |
| 0:45–1:30 | **Transferencia normal** | 200 OK, total $3.000. | 200 OK, total $3.000. Con todo en orden, las dos versiones se ven iguales. | línea base |
| 1:30–2:45 | **Caída a mitad de operación** | 500. El medidor se pone rojo: **Faltan $200**. Ana perdió el dinero y Beto no lo recibió. La respuesta muestra traceback, SQL y la ruta de la base. **La bitácora sigue vacía: nadie se enteró.** | 500 con un mensaje genérico y un `error_id`. Total $3.000: hubo rollback. La bitácora tiene `ERROR_INTERNO` con **el mismo** `error_id`, así que soporte puede correlacionar el reclamo del cliente con el log. | **A10** (fail open vs. fail closed) + **A09** |
| 2:45–3:30 | **Destino inexistente** | Otra vez faltan $200 (ahora $400). Lee en voz alta el `TypeError` y la sentencia SQL: eso le sirve a un atacante (CWE-209). | 422: "Cuenta de origen o destino no válida". Nada cambió y el rechazo quedó registrado. | **A10** (CWE-209) |
| 3:30–4:30 | **Monto negativo** | 200 "OK". Ana **gana** $500 y Beto los pierde. El total no cambia, por eso el medidor no detecta este robo: hace falta validar la entrada. | 400 genérico con `error_id`, sin revelar el esquema de validación. Saldos intactos. | **A06** + A10 |
| 4:30–5:30 | **Ráfaga de 30 solicitudes** | Acepta las 30, sin límite. | 15 aceptadas y 15 con 429. **Una sola** `ALERTA_RATE_LIMIT` en la bitácora, para no inundar al SOC. | **A06** / **A09** |
| 5:30–6:00 | **Reiniciar demo** | Cierre: el problema no es que ocurra una excepción, sino qué hace el sistema cuando ocurre. | Muestra la lista de controles de abajo. | resumen |

Pregunta para el público después del paso de la caída: *"¿Cuánto tardaría este banco en descubrir que faltan $200?"* Sin bitácora de fallos, nunca. Ahí A10 se convierte en A09.

## Controles de la versión segura

1. **Transacción atómica** (`BEGIN IMMEDIATE` … `COMMIT`) con **rollback ante cualquier excepción** (*fail closed*).
2. **Validación estricta de entrada**: monto entero (sin coerción de texto ni decimales) entre 1 y 10.000; cuentas solo con letras, máximo 20 caracteres; origen distinto del destino; ambas cuentas deben existir.
3. **Fondos verificados de forma atómica**: `UPDATE … WHERE balance >= monto` dentro de la transacción.
4. **Errores clasificados y genéricos**: 400 para entrada inválida (con `error_id` y sin detalle del esquema), 422 para reglas de negocio, 429 por exceso de solicitudes y 500 inesperado (con `error_id` y sin detalles técnicos).
5. **Correlación**: el detalle completo va solo al log del servidor y a la bitácora, con el mismo `error_id` que recibe el cliente.
6. **Manejador global de excepciones** de respaldo.
7. **Rate limiting**: 15 solicitudes cada 10 segundos por IP.
8. **Bitácora con integridad**: append-only, con triggers de SQLite que bloquean UPDATE y DELETE. Registra transferencias OK, rechazos, errores internos y alertas.
9. **Alerta de abuso deduplicada**: una por ventana.

## Notas y limitaciones

- `caida_a_mitad` es una **inyección de fallo solo para la demo**: lanza una excepción entre el débito y el crédito para que el escenario sea repetible. En la vida real el fallo vendría de la red, la base de datos, la memoria, etc.
- El rate limit vive en memoria: se reinicia con el servidor y no se comparte entre procesos. En producción iría en un gateway o en Redis.
- `/audit` devuelve solo los 12 eventos más recientes. Con mucha concurrencia, la alerta de la ráfaga podría quedar fuera de esa lista aunque esté registrada.
- La API vulnerable filtra información **a propósito**. No la expongas fuera de `127.0.0.1`.
