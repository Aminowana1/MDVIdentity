# MDVIdentity 1.0.4

MDVIdentity reserva nombres entre Java y Bedrock para MDVCRAFT y hace de puente de autenticacion entre Floodgate y nLogin cuando Floodgate usa `username-prefix: ""`.

## Reglas

- Un nombre solo puede pertenecer a una identidad/plataforma.
- El primero que queda registrado gana el nombre.
- Bedrock se valida SIEMPRE mediante Floodgate UUID/XUID.
- Java offline reserva al completar `/register`.
- Java premium reserva al completar el autologin premium de nLogin.
- Las comparaciones de nombre no distinguen mayusculas/minusculas.

## Cambio 1.0.4

La 1.0.3 podia agotar sus 20 intentos (~1 segundo) mientras nLogin todavia no habia creado/resuelto su `LoginRequest` para la sesion sin prefijo. 1.0.4:

- escucha `LoginRequestEvent` de nLogin;
- usa tanto `Identity.ofBedrock(...)` como la identidad BEDROCK canonica creada por el kernel de nLogin;
- localiza cuentas existentes por UUID Floodgate si `getAccount(ofBedrock)` no resuelve con prefijo vacio;
- usa `requestLogin(...)` antes de reintentar `forceLogin(...)` cuando hace falta;
- da hasta ~6 segundos solo como margen de seguridad (normalmente 0-2 ticks);
- si falla, imprime un diagnostico con `type`, `uniqueId`, `bedrockId` y `mojangId` de nLogin.

## Configuracion recomendada

Floodgate:

```yaml
username-prefix: ""
replace-spaces: true
```

nLogin Premium:

```yaml
autologin:
  bedrock:
    enable: false
    skip-register: true
    use-database-uuid: false
```

MDVIdentity se encarga del autologin Bedrock. Java premium/offline se mantienen bajo nLogin normalmente.

Para pruebas sin importar cuentas antiguas:

```yaml
migration:
  import-existing-nlogin-on-first-start: false
  legacy-bedrock-prefix: "_"
  write-conflicts-yml: true
  repair-verified-legacy-bedrock-aliases: false
```

## Compilar con GitHub Actions

El proyecto incluye `.github/workflows/build.yml`.

1. Sube el contenido del proyecto a un repositorio GitHub.
2. Abre **Actions**.
3. Ejecuta **Build MDVIdentity**.
4. Descarga el artifact `MDVIdentity-1.0.4`.

El JAR generado es:

```text
target/MDVIdentity-1.0.4.jar
```

Instalacion:

```text
plugins/MDVIdentity-1.0.4.jar
```

Requiere Java 21, Paper/Purpur 1.21.6, Floodgate y nLogin Premium.
