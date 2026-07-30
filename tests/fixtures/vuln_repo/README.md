# Repo vulnerable de prueba

Fixture con debilidades **intencionales** para verificar Wasp end-to-end:

- `app/main.py`: inyección de comandos (`shell=True`) y hash MD5 de contraseñas.
- `config/prod.env`: credenciales de ejemplo (no reales) para el detector de secretos.
- `package.json`: `lodash 4.17.19` (versión con CVEs conocidos).

No usar como plantilla de nada.
