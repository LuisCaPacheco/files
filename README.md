# Demo OWASP A10:2025 – Mishandling of Exceptional Conditions

Una transferencia bancaria implementada dos veces: sin controles (`/vulnerable`) y con los controles que recomienda OWASP (`/secure`).
La interfaz las muestra lado a lado. **Solo para uso educativo, en localhost.**

## Arquitectura

```
Navegador (static/index.html)
   │  fetch /vulnerable/*  y  /secure/*   (mismas peticiones a las dos)
   ▼
FastAPI (main.py, un solo proceso)
   ├── /vulnerable/transfer  → sqlite vulnerable.db  (sin rollback, errores filtrados, sin logs)
   └── /secure/transfer      → sqlite secure.db      (transacción atómica, validación, rate limit,
                                                     bitácora append-only, mensajes genéricos)
   Comunes: GET /{modo}/accounts · GET /{modo}/audit · POST /{modo}/reset
```

## Cómo correrla

```bash
pip install -r requirements.txt
uvicorn main:app --port 8000
# abrir http://localhost:8000
# pruebas automáticas (opcional): pip install pytest httpx && pytest -q
```

## Guion (≈6 min)

| # | Botón | Qué pasa en "Sin controles" | Qué pasa en "Con controles" | Categoría |
|---|---|---|---|---|
| 1 | Transferencia normal | OK | OK | línea base |
| 2 | Caída a mitad de operación | Ana pierde $200, nadie los recibe; total $2.800; la bitácora queda vacía | Rollback total; total $3.000; error genérico con `error_id`; la bitácora registra `ERROR_INTERNO` | A10 + A09 |
| 3 | Destino inexistente | Mismo daño, y la respuesta filtra SQL, ruta del archivo y traceback | 422 con mensaje seguro; nada cambia | A10 (CWE-209, 636) |
| 4 | Monto negativo | Ana *gana* $500 y Beto los pierde, con "OK" | 400, validación de entrada | A10 / A06 |
| 5 | Ráfaga de 30 | Acepta las 30 | 15 pasan, 15 reciben 429, una alerta en la bitácora | A10 (límites) / A09 |

Punto clave para la audiencia: en el lado vulnerable el medidor se pone rojo (faltan $200) **y el sistema no se entera**. Ahí A10 se convierte en A09.

## Qué controles de OWASP implementa `/secure`

- Capturar el error donde ocurre y hacer rollback completo (*fail closed*).
- Manejador global de excepciones y mensajes genéricos con `error_id` (el detalle solo va al log del servidor).
- Validación estricta de entrada (monto 1–10.000, cuentas alfabéticas).
- Rate limiting (15 solicitudes cada 10 s por IP).
- Bitácora con integridad (triggers que impiden UPDATE/DELETE) y alerta ante abuso.

## Nota de alcance
La inyección de fallo (`caida_a_mitad`) existe solo para que la demo sea repetible. En la vida real el fallo viene de la red, la base de datos, memoria, etc.
