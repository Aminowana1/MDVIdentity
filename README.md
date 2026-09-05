# MDVIdentity 1.0.6

## Fix 1.0.6 - primer registro Bedrock y spawn REGISTER

Los jugadores Java que usan el flujo normal de nLogin reciben correctamente el spawn `REGISTER`.
Los jugadores Bedrock de MDVCRAFT se registran mediante `performRegister(...)` y `forceLogin(...)`,
por lo que nLogin puede aplicar `last-location` sobre la ubicacion vanilla inicial y enviarlos al
spawn de `world`.

Desde 1.0.6, solo cuando MDVIdentity crea por primera vez la cuenta interna Bedrock:

- usa `nLoginAPI#getSpawnLocation(SpawnType.REGISTER)` como destino;
- usa `JOIN` como fallback si REGISTER no existe;
- reaplica ese destino tras el `forceLogin` para ganar la carrera contra `last-location`;
- en todas las conexiones posteriores NO teletransporta al jugador y deja funcionar `last-location`.

Config nueva:

```yaml
bedrock-auth:
  first-registration:
    keep-at-register-spawn: true
    teleport-delay-ticks: 2
    safety-recheck-ticks: 10
```

MDVIdentity reserva nombres entre Java y Bedrock para MDVCRAFT y hace de puente entre Floodgate y nLogin usando `username-prefix: ""`.

## Cambio clave 1.0.5

El diagnostico real de 1.0.4 mostro esto para un jugador confirmado por Floodgate:

```text
type=OFFLINE
uniqueId=<UUID offline de Java>
bedrockId=-
mojangId=-
```

Es decir: con prefijo Floodgate vacio, nLogin 2.0.19 crea su `LoginRequest` y su cuenta interna como **OFFLINE**, aunque Floodgate haya autenticado correctamente al jugador Bedrock. Por eso `forceLogin(Identity.ofBedrock(...))` nunca podia completar la sesion.

1.0.5 separa responsabilidades:

- **Floodgate + `identities.db`** son la autoridad real de plataforma y propiedad del nombre.
- **nLogin** solo se usa como capa de registro/limbo.
- Para un Bedrock ya verificado por Floodgate, MDVIdentity usa `Identity.ofOffline(nombre)` para hablar con la sesion que nLogin realmente creo.
- La cuenta interna de nLogin usa una password aleatoria que el jugador Bedrock nunca necesita conocer.
- Un Java con ese mismo nombre sigue bloqueado ANTES del login por MDVIdentity.
- Una cuenta nLogin con `mojangId` nunca se reutiliza como Bedrock.

Esto permite tener el nombre Bukkit limpio (`Pedro`, sin `_` ni `.`) sin depender del detector Bedrock de nLogin.

## Reglas de identidad

- Un nombre solo puede pertenecer a una identidad/plataforma.
- El primero que queda registrado gana.
- Bedrock se valida por Floodgate UUID/XUID.
- Java offline reserva al completar `/register`.
- Java premium reserva al completar el autologin premium de nLogin.
- Los nombres se comparan sin distinguir mayusculas/minusculas.

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

MDVIdentity se encarga del autologin Bedrock.

Para pruebas sin importar cuentas antiguas:

```yaml
migration:
  import-existing-nlogin-on-first-start: false
  legacy-bedrock-prefix: "_"
  write-conflicts-yml: true
  repair-verified-legacy-bedrock-aliases: false
```

**Produccion:** antes de abrir el servidor al publico, importa/reserva las cuentas Java antiguas para que una base `identities.db` vacia no permita reclamar nombres historicos.

## Compilar con GitHub Actions

El proyecto incluye `.github/workflows/build.yml`.

1. Sube el contenido del proyecto a GitHub.
2. Abre **Actions**.
3. Ejecuta **Build MDVIdentity**.
4. Descarga el artifact `MDVIdentity-1.0.6`.

JAR:

```text
target/MDVIdentity-1.0.6.jar
```

Instalacion:

```text
plugins/MDVIdentity-1.0.6.jar
```

Requiere Java 21, Paper/Purpur 1.21.6, Floodgate y nLogin Premium.
