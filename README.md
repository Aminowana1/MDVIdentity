# MDVIdentity 1.0.3

Plugin Paper/Purpur para MDVCRAFT que reserva nombres entre Java y Bedrock y hace de puente de autenticación entre Floodgate y nLogin cuando Floodgate usa `username-prefix: ""`.

## Regla de identidad

- Un nombre puede pertenecer a **JAVA** o **BEDROCK**, nunca a ambos.
- Los nombres se comparan sin distinguir mayúsculas/minúsculas.
- Bedrock reserva el nombre únicamente con una identidad Floodgate verificada (UUID/XUID).
- Java offline reserva el nombre al completar `/register` en nLogin.
- Java premium reserva el nombre después de la autenticación premium de nLogin.
- Si el nombre pertenece a la otra plataforma, se rechaza la conexión/registro.
- Una segunda cuenta Xbox no puede reutilizar un nombre Bedrock ya reservado por otro UUID/XUID.

## Cambio principal de 1.0.3: autologin Bedrock inmediato

La 1.0.2 esperaba por defecto 2 ticks después de `PlayerJoinEvent`. Mientras tanto nLogin podía abrir su formulario de contraseña en Bedrock, especialmente si su propio `autologin.bedrock.enable` seguía activado.

1.0.3 cambia el flujo:

1. `AsyncPlayerPreLoginEvent`: Floodgate verifica UUID/XUID y MDVIdentity reserva/comprueba el nombre.
2. `PlayerJoinEvent` en prioridad `LOWEST`: MDVIdentity intenta autenticar inmediatamente, sin esperar ticks.
3. Si `identities.db` confirma que el nombre pertenece a ese mismo UUID/XUID Bedrock:
   - si la cuenta nLogin ya existe, usa `forceLogin(..., false)`;
   - si aún no existe, crea una contraseña interna aleatoria con `performRegister(...)` y acto seguido hace `forceLogin(..., false)`.
4. Si nLogin todavía no está listo para esa conexión, reintenta cada 1 tick hasta 20 intentos.
5. Los fallbacks por nombre/alias antiguo solo se usan si los datos de nLogin demuestran que corresponden al mismo UUID Floodgate. Nunca se auto-loguea una cuenta Mojang real por coincidencia de nombre.

Esto hace que un Bedrock que ya está en `identities.db` no necesite `/login` en reconexiones.

## Configuración OBLIGATORIA

### Floodgate

```yaml
username-prefix: ""
replace-spaces: true
```

### nLogin Premium

El autologin Bedrock **de nLogin** debe estar desactivado. MDVIdentity lo reemplaza:

```yaml
autologin:
  bedrock:
    enable: false
    skip-register: true
    use-database-uuid: false
```

No uses `enable: true` junto con MDVIdentity y prefijo vacío: nLogin puede iniciar su propio flujo Bedrock y abrir el formulario de contraseña antes del bridge.

### MDVIdentity

```yaml
bedrock-auth:
  enabled: true
  delay-ticks: 0
  retry-delay-ticks: 1
  max-attempts: 20
  log-success: true
  internal-password-length: 24
```

Para una prueba con DB limpia y sin importar cuentas antiguas:

```yaml
migration:
  import-existing-nlogin-on-first-start: false
  legacy-bedrock-prefix: "_"
  write-conflicts-yml: true
  repair-verified-legacy-bedrock-aliases: false
```

Para producción en un servidor existente, haz backup y vuelve a habilitar la importación para reservar también los nombres de jugadores antiguos que todavía no hayan vuelto a entrar.

## Resultado esperado

Primera conexión Bedrock `cho1oman123`:

```text
Identidad reservada: cho1oman123 -> BEDROCK (...)
Cuenta nLogin Bedrock creada automaticamente: cho1oman123
Autologin Bedrock completado: cho1oman123 (...)
```

Siguientes conexiones:

```text
Autologin Bedrock completado: cho1oman123 (...)
```

No debe aparecer `/register`, `/login` ni formulario de contraseña.

## Compilar con GitHub Actions

El proyecto incluye `.github/workflows/build.yml`.

1. Sube el contenido de esta carpeta a un repositorio GitHub.
2. Abre **Actions -> Build MDVIdentity -> Run workflow**.
3. GitHub compila con Java 21 y Maven.
4. Descarga el artifact `MDVIdentity-1.0.3`.

El JAR generado queda en:

```text
target/MDVIdentity-1.0.3.jar
```

Instálalo como plugin normal:

```text
plugins/MDVIdentity-1.0.3.jar
```
