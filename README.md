# Union LAN

Conecta varios dispositivos Android de tu **misma red local** y accede a sus
terminales por nombre. Una invitación permite incorporar cada dispositivo
copiando un solo comando en Termux. Si cambia su IP, Union LAN busca su clave
SSH y recupera el acceso.

Un dispositivo actúa como **central**: guarda los nombres y se conecta a los
demás. Los otros ejecutan el servidor SSH en Termux. Desde esa conexión puedes
entrar también a su Debian con `proot-distro`.

## Requisitos

- Dos o más dispositivos conectados a la misma LAN o Wi-Fi.
- Termux instalado en los dispositivos Android.
- Debian en `proot-distro` instalado en el dispositivo central.
- Python 3.9 o posterior y OpenSSH en el central; se instalan abajo.
- Acceso a Internet durante la descarga inicial y la instalación de paquetes.

El acceso entre dispositivos utiliza la red local. No requiere root de
Android ni abrir puertos en el router. Si la red Wi-Fi aísla sus clientes,
deberás permitir la comunicación entre los dispositivos.

## 1. Preparar el dispositivo central

En **Termux** del dispositivo que usarás como central, entra a tu Debian:

```bash
proot-distro login debian
```

Después, **dentro de Debian**, ejecuta como su usuario root:

```bash
apt update
apt install -y git python3 openssh-client
git clone https://github.com/Yextep/union-lan.git ~/union-lan
cd ~/union-lan
./union-lan invitar movil2
```

Los siguientes comandos del proyecto también se ejecutan **dentro del Debian
central**, desde la carpeta `~/union-lan`.

## 2. Incorporar el otro dispositivo

El central mostrará un comando de descarga y registro.

1. En el otro dispositivo, abre **Termux, fuera de Debian**. Si estás en Debian,
   ejecuta `exit` para volver a Termux.
2. Copia y pega **completo** el comando que te mostró el central.
3. Espera la confirmación de incorporación en ambos dispositivos.

Mantén abierta la terminal del central mientras se incorpora el dispositivo.
La invitación dura 30 minutos, sirve para una incorporación y se cancela con
`Ctrl+C`. El comando comprueba la integridad del instalador antes de ejecutarlo.

El instalador se encarga de:

- Instalar OpenSSH y curl cuando faltan.
- Autorizar la clave pública del central sin borrar otras claves existentes.
- Arrancar SSH en el puerto `8022`.
- Registrar el usuario, la dirección IP y la clave del servidor.
- Preparar el inicio de SSH al abrir una terminal Bash de Termux.

El central verifica la identidad del servidor y prueba el acceso SSH antes
de guardar el dispositivo. Las claves privadas permanecen en cada dispositivo.
El resto de dispositivos no necesita clonar este repositorio.

Para añadir más dispositivos, genera otra invitación con un nombre distinto:

```bash
./union-lan invitar movil3
./union-lan invitar tablet
```

Ejecuta una invitación a la vez. Copia su comando en el dispositivo correspondiente
y espera la confirmación antes de generar la siguiente.

## 3. Acceder por nombre

Desde el Debian central:

```bash
# Entrar al Termux remoto
ssh movil2

# Entrar al Debian remoto, si ya está instalado
ssh -t movil2 'proot-distro login debian'

# Ver los dispositivos incorporados
./union-lan listar
```

Para cerrar la sesión remota, ejecuta `exit`.

También puedes transferir archivos:

```bash
scp archivo.txt movil2:~/
sftp movil2
```

Cada dispositivo conserva su propio sistema, almacenamiento y aplicaciones.
El central permite acceder a ellos; no combina automáticamente su RAM ni sus CPU.

## Qué ocurre cuando cambia una IP

Union LAN guarda la identidad SSH del dispositivo. Al conectar consulta la IP
guardada; si falla o esa dirección pertenece ahora a otro dispositivo, busca
**la misma clave SSH** en la LAN y actualiza la dirección. Nunca cambia la clave
registrada para aceptar otro dispositivo.

Por defecto, busca en el `/24` de la dirección local del central: por ejemplo,
`192.168.1.0/24`. Es un valor inicial, no una detección de la máscara del router.
Si tu red usa otra máscara, puedes indicarla:

```bash
./union-lan red 192.168.1.0/24
./union-lan buscar movil2

# Volver a la selección automática del /24 local
./union-lan red
```

Se admiten redes IPv4 locales de hasta **1024 direcciones en total**. Una
reserva DHCP en el router también evita que cambien las direcciones.

Una sesión abierta puede cortarse al reiniciar la red o cambiar la IP. Vuelve
a ejecutar `ssh movil2` para recuperar el acceso. El dispositivo debe seguir
en la LAN y tener SSH activo; el programa no conserva las sesiones abiertas.

El proyecto está limitado a redes locales: no incorpora VPN, conexión por
datos móviles ni acceso entre redes a través de Internet.

## Arrancar SSH al encender Android

El instalador prepara `~/.termux/boot/90-union-lan`. Para ejecutarlo al encender
el dispositivo, instala **Termux:Boot** de una fuente compatible con tu Termux
y abre esa app una vez. Consulta sus [instrucciones oficiales](https://github.com/termux/termux-boot).

Sin Termux:Boot, SSH arranca al abrir una terminal Bash de Termux. Android puede
detener Termux por restricciones de batería; si ocurre, permite su ejecución
en segundo plano en los ajustes del dispositivo.

## Problemas frecuentes

| Problema | Qué comprobar |
| --- | --- |
| El instalador dice que debe ejecutarse en Termux | Sal de Debian con `exit` en el dispositivo nuevo. |
| No se puede descargar el instalador | Comprueba que el central sigue mostrando la invitación y que ambos dispositivos están en la misma LAN. |
| La dirección del central no es la de tu Wi-Fi | Consulta la IP en los detalles de la red de Android y genera la invitación con `./union-lan invitar movil2 --ip-central 192.168.1.20`. La dirección es un ejemplo; usa la tuya. |
| La invitación caducó | Genera una nueva invitación con el mismo comando. |
| No se encuentra un dispositivo | Abre Termux en él para iniciar SSH, comprueba el Wi-Fi y la red de búsqueda. |
| No funciona después de reinstalar Termux | El servidor tiene otra identidad; incorpóralo con un nombre nuevo. |
| El nombre ya pertenece a otro dispositivo | Usa un nombre distinto para la nueva incorporación. |
| No entra al Debian remoto | Comprueba que `proot-distro login debian` funciona localmente en ese dispositivo. |

## Configuración y actualizaciones

El programa genera por usuario:

- `~/.ssh/union-lan_ed25519`: identidad privada del central.
- `~/.ssh/config.d/union-lan.conf`: alias SSH.
- `~/.config/union-lan/nodos.json`: inventario de dispositivos.
- `~/.config/union-lan/known_hosts`: claves de servidores verificados.

Estos archivos se guardan fuera del repositorio. No compartas la identidad
privada del central. La incorporación se realiza por HTTP en tu LAN de confianza
con un token aleatorio; las conexiones posteriores se realizan por SSH.

Para actualizar, desde la carpeta del proyecto:

```bash
git pull --ff-only
```

Mantén el proyecto en la misma carpeta: los alias SSH usan la ruta del programa.

## Pruebas

```bash
python3 -m unittest -v
```

Las pruebas cubren cambios de IP, rechazo de identidades ajenas, límites de
la búsqueda local, invitaciones caducadas y usadas simultáneamente, integridad
del instalador y conservación de las claves al repetir una instalación.
Se ha comprobado también la incorporación y el acceso a Debian entre dos
dispositivos Android con Termux, simulando después una IP guardada incorrecta.

## Licencia y créditos

Autor: **[Yextep](https://github.com/Yextep)**.

Union LAN se distribuye bajo **PolyForm Noncommercial License 1.0.0**, sujeta
a **Commons Clause License Condition v1.0**. Los textos completos están en
[LICENSE](LICENSE); los avisos de atribución están en [NOTICE](NOTICE).

Puedes usar, modificar y compartir el proyecto para los fines permitidos por
la licencia, incluidos los no comerciales. La licencia base también contiene
permisos específicos para ciertas organizaciones e instituciones. **Commons
Clause excluye la venta** del software y de productos o servicios cuyo valor
derive íntegra o sustancialmente de su funcionalidad, según su definición.

Cuando distribuyas el código original o una versión modificada, debes conservar
los términos de licencia, la condición Commons Clause y los avisos obligatorios
que atribuyen el proyecto a **Yextep**. Puedes añadir créditos por tus cambios
sin quitar los créditos originales.

La publicación del código no concede permiso general de comercialización.
Es un proyecto de código disponible con restricciones comerciales, no una
licencia de código abierto aprobada por la OSI. Este resumen no sustituye los
términos completos de [LICENSE](LICENSE).
