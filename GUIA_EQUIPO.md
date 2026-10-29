# Guía para probar la demo en equipo

Cada persona ejecuta la demo **en su propio computador**. La app escucha solo en `127.0.0.1` a propósito, porque la versión vulnerable revela información interna y no debe abrirse a la red.

## 1. Acceso al repositorio (el dueño, una sola vez)

El repositorio es privado. El dueño invita al compañero:

1. https://github.com/LuisCaPacheco/files → **Settings** → **Collaborators** → **Add people**.
2. Escribe el usuario de GitHub del compañero y envía la invitación.
3. El compañero la acepta desde su correo o desde GitHub.

## 2. Instalación (cada uno)

Requisitos: **Python 3.11 o superior** y **Git**.

```
git clone https://github.com/LuisCaPacheco/files.git
cd files
python -m venv .venv
.venv\Scripts\activate          (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
```

## 3. Comprobar que todo funciona (cada uno)

```
pytest -q
```

Debe decir **10 passed**. Si sale otro resultado, el problema está en esa instalación, no en la demo.

## 4. Ensayo con la demo (los dos juntos)

```
python main.py
```

Abran **http://127.0.0.1:8000**, pulsen **Reiniciar demo** y luego cada escenario en orden:

| Botón | Sin controles | Con controles |
|---|---|---|
| Transferencia normal | 200, $3.000 | 200, $3.000 |
| Caída a mitad de operación | 500 con traceback, **Faltan $200**, bitácora vacía | 500 genérico con `error_id`, $3.000, `ERROR_INTERNO` en la bitácora |
| Destino inexistente | 500, **Faltan $400** | 422, $3.000 |
| Monto negativo | 200 "OK", Ana gana $500 | 400, saldos intactos |
| Ráfaga de 30 solicitudes | 30 aceptadas | 15 aceptadas, 15 con 429, una alerta |

Para detener el servidor: **Ctrl+C** en la terminal.

## 5. Reparto sugerido para la exposición

- **Persona A (operador):** pulsa los botones y lee en voz alta los códigos HTTP.
- **Persona B (narrador):** sigue el guion del [README](README.md#guion-de-demo-6-minutos), señala cada panel y nombra la categoría OWASP (A10, A09, A06).
- Ensayen al menos una vez con cronómetro: el guion dura 6 minutos.
- El día de la clase, lleven la demo instalada en **los dos** computadores. Si uno falla, el otro sirve de respaldo, y no necesitan internet.

## 6. Si hacen cambios

Antes de empezar a trabajar:

```
git pull
```

Al terminar:

```
git add .
git commit -m "describe el cambio"
git push
```

Si los dos cambian el mismo archivo a la vez, Git pedirá resolver un conflicto. Lo más fácil es acordar quién edita qué.
