# MDVIdentity 1.0.0

Plugin Bukkit/Paper/Purpur para MDVCRAFT que reserva nombres entre Java y Bedrock y puentea la autenticacion Bedrock de Floodgate con nLogin.

## Regla principal

Un nombre solo puede pertenecer a una plataforma:

- `Pedro` se registra primero por Bedrock -> Java `Pedro` queda bloqueado.
- `Axel` se registra primero por Java -> Bedrock `Axel` queda bloqueado.
- Java offline reserva el nombre solo cuando completa `/register`.
- Java premium reserva el nombre cuando nLogin confirma la autenticacion premium.
- Las comparaciones no distinguen mayusculas/minusculas.
- Bedrock usa UUID/XUID de Floodgate para impedir que otra cuenta Xbox reutilice una reserva Bedrock.

La reserva se guarda en `plugins/MDVIdentity/identities.db` (SQLite).

## Migracion desde tu prefijo actual `_`

Tu Floodgate actual usa:

```yaml
username-prefix: "_"
```

MDVIdentity importa las cuentas existentes de nLogin en su primer arranque. Solo si la cuenta tiene `bedrock_id` elimina el prefijo antiguo `_` de la reserva. Nunca toca un username Java que empiece por `_`.

Si ya existieran `Pedro` Java y `_Pedro` Bedrock, el importador compara la fecha de creacion de nLogin y deja como propietario al registro mas antiguo. El conflicto queda guardado en:

```text
plugins/MDVIdentity/conflicts.yml
```

## Config final recomendada

### Floodgate

Despues de instalar MDVIdentity, deja el nombre real sin prefijo:

```yaml
username-prefix: ""
replace-spaces: true
```

### nLogin Premium

Desactiva el autologin Bedrock propio de nLogin. MDVIdentity lo hace usando `Identity.ofBedrock(...)`, el UUID Floodgate y `forceLogin(...)`:

```yaml
autologin:
  bedrock:
    enable: false
    skip-register: true
    use-database-uuid: false
```

El resto de tu configuracion premium/offline puede seguir igual.

## Instalacion segura

1. Apaga el servidor.
2. Haz backup de `plugins/nLogin`, `plugins/floodgate` y de tus datos de jugadores.
3. Coloca `MDVIdentity-1.0.0.jar` en `plugins/`.
4. Cambia Floodgate a `username-prefix: ""`.
5. Desactiva `autologin.bedrock.enable` en nLogin.
6. Inicia el servidor.
7. Revisa consola. Debe aparecer `MDVIdentity listo` y el conteo JAVA/BEDROCK.
8. Ejecuta `/mdvidentity status` y `/mdvidentity conflicts`.

MDVIdentity bloquea nuevos logins mientras no haya terminado la importacion inicial, para que nadie pueda reclamar un nombre antiguo durante el arranque.

## Bedrock sin prefijo

En pre-login Floodgate ya permite consultar si el UUID pertenece a un jugador Bedrock. MDVIdentity usa esa informacion antes de dejarlo entrar.

Si el nombre esta libre, Bedrock lo reserva atomica e inmediatamente. Si el nombre ya es JAVA, se rechaza la conexion.

Al entrar, el plugin:

1. Comprueba si nLogin ya lo autentico.
2. Busca la cuenta por `Identity.ofBedrock(nombre, floodgateUuid)`.
3. Si no existe, crea una cuenta nLogin con password interno aleatorio.
4. Ejecuta `forceLogin(..., false)`.

El jugador Bedrock nunca ve ni necesita esa password.

## Carreras simultaneas

La columna `name_key` es `PRIMARY KEY` en SQLite. Por eso solo puede existir un propietario para `pedro`.

Ejemplo: Java y Bedrock intentan reclamar `Pedro` casi al mismo tiempo. El primero que consigue registrar/reservar el nombre queda como propietario; el otro es cancelado o expulsado.

## Comandos

```text
/mdvidentity status
/mdvidentity info <nombre>
/mdvidentity conflicts
/mdvidentity import
/mdvidentity release <nombre>
/mdvidentity reload
```

Permiso:

```text
mdvidentity.admin
```

`release` solo elimina la reserva de MDVIdentity. No borra la cuenta de nLogin.

## Compilar con GitHub Actions

Sube todo este proyecto a un repositorio GitHub y ejecuta:

`Actions -> Build MDVIdentity -> Run workflow`

El workflow usa Java 21 + Maven y sube como artifact:

```text
MDVIdentity-1.0.0.jar
```

Tambien puedes compilar localmente con:

```bash
mvn clean package
```

El JAR queda en `target/MDVIdentity-1.0.0.jar`.

## Dependencias

- Purpur/Paper 1.21.6
- nLogin Premium 2.0.x con API 10.4
- Floodgate 2.2.5
- Java 21

Las APIs de Paper, nLogin y Floodgate son `provided`; no se empaquetan dentro del plugin.
