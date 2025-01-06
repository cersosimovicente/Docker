# Tutorial de iptables

`iptables` es una utilidad en Linux que permite configurar reglas para controlar el tráfico de red. Permite filtrar, redirigir y gestionar paquetes a nivel de red.

## Índice
1. [Introducción a iptables](#introducción-a-iptables)
2. [Estructura de las reglas de iptables](#estructura-de-las-reglas-de-iptables)
3. [Cadenas de iptables](#cadenas-de-iptables)
4. [Reglas y acciones comunes](#reglas-y-acciones-comunes)
5. [Ejercicios prácticos](#ejercicios-prácticos)

---

## 1. Introducción a iptables

`iptables` es una herramienta que gestiona el filtrado de paquetes en un sistema Linux. Funciona sobre la capa de red del sistema operativo, lo que le permite controlar el tráfico entrante y saliente, permitiendo o bloqueando conexiones según las reglas configuradas.

### Instalación de iptables

Para instalar `iptables` en una distribución basada en Debian o Ubuntu:

```bash
sudo apt update
sudo apt install iptables
```

## 2. Estructura de las reglas de iptables

Las reglas de iptables están formadas por:

- **Cadenas (Chains)**: Se refiere a los conjuntos de reglas que procesan los paquetes. Las cadenas más comunes son:
  - `INPUT`: Para los paquetes que llegan al sistema.
  - `OUTPUT`: Para los paquetes enviados desde el sistema.
  - `FORWARD`: Para los paquetes que atraviesan el sistema (no destinados a él).

- **Reglas**: Son las instrucciones específicas que se ejecutan en cada paquete. Una regla puede ser permitir o denegar el tráfico basado en diferentes criterios.

- **Acciones**: Existen diferentes acciones que se pueden tomar:
  - `ACCEPT`: Permite el paquete.
  - `DROP`: Bloquea el paquete sin notificar al origen.
  - `REJECT`: Bloquea el paquete y notifica al origen.

- **Filtros**: Se basan en parámetros como la dirección IP, el puerto, el protocolo, etc.

### Ejemplo básico:

```bash
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

## 3. Cadenas de iptables

Las cadenas son los diferentes puntos de filtrado de paquetes en `iptables`. Las tres principales son:

- **INPUT**: Filtra los paquetes que van dirigidos a tu sistema.
- **OUTPUT**: Filtra los paquetes que salen de tu sistema.
- **FORWARD**: Filtra los paquetes que atraviesan tu sistema (por ejemplo, cuando actúa como un enrutador).

### Ejemplo de uso de cadenas

```bash
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT  # Permitir acceso HTTP
sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT # Permitir consultas DNS
```
## 4. Reglas y acciones comunes

Algunas reglas comunes son:

### Permitir acceso por puerto específico

```bash
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT    # HTTP
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT   # HTTPS
```

