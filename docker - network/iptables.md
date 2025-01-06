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

Cadenas (Chains): Se refiere a los conjuntos de reglas que procesan los paquetes. Las cadenas más comunes son:

INPUT: Para los paquetes que llegan al sistema.
OUTPUT: Para los paquetes enviados desde el sistema.
FORWARD: Para los paquetes que atraviesan el sistema (no destinados a él).
Reglas: Son las instrucciones específicas que se ejecutan en cada paquete. Una regla puede ser permitir o denegar el tráfico basado en diferentes criterios.

Acciones: Existen diferentes acciones que se pueden tomar:

ACCEPT: Permite el paquete.
DROP: Bloquea el paquete sin notificar al origen.
REJECT: Bloquea el paquete y notifica al origen.
Filtros: Se basan en parámetros como la dirección IP, el puerto, el protocolo, etc.

Ejemplo básico:
bash
Copiar código
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
Este comando permite el tráfico de red entrante a través del puerto 22 (usado por SSH).

3. Cadenas de iptables
Las cadenas son los diferentes puntos de filtrado de paquetes en iptables. Las tres principales son:

INPUT: Filtra los paquetes que van dirigidos a tu sistema.
OUTPUT: Filtra los paquetes que salen de tu sistema.
FORWARD: Filtra los paquetes que atraviesan tu sistema (por ejemplo, cuando actúa como un enrutador).
Ejemplo de uso de cadenas
bash
Copiar código
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT  # Permitir acceso HTTP
sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT # Permitir consultas DNS
4. Reglas y acciones comunes
Algunas reglas comunes son:

Permitir acceso por puerto específico:
bash
Copiar código
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT    # HTTP
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT   # HTTPS
Bloquear una IP específica:
bash
Copiar código
sudo iptables -A INPUT -s 192.168.1.100 -j DROP   # Bloquear una IP
Limitar el número de conexiones:
bash
Copiar código
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 5 -j DROP
Este ejemplo limita a 5 conexiones SSH por minuto.

Ver las reglas activas:
bash
Copiar código
sudo iptables -L   # Muestra todas las reglas activas
5. Ejercicios prácticos
Ejercicio 1: Permitir tráfico HTTP y HTTPS
Permitir el tráfico HTTP (puerto 80) y HTTPS (puerto 443) en el servidor.
Comandos:

bash
Copiar código
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT   # Permitir HTTP
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT  # Permitir HTTPS
Explicación: Estos comandos permiten el tráfico entrante hacia el servidor en los puertos 80 y 443, utilizados por HTTP y HTTPS, respectivamente.

Ejercicio 2: Bloquear todo el tráfico, excepto SSH
Bloquear todo el tráfico de entrada, pero permitir conexiones SSH en el puerto 22.
Comandos:

bash
Copiar código
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT  # Permitir SSH
sudo iptables -A INPUT -j DROP  # Bloquear todo lo demás
Explicación: Este conjunto de reglas bloquea todo el tráfico de entrada, pero permite conexiones SSH para que puedas gestionar remotamente el servidor.

Ejercicio 3: Limitar el acceso a un servicio
Limitar el número de intentos de conexión al puerto 22 (SSH) a 3 intentos cada 60 segundos.
Comandos:

bash
Copiar código
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 3 -j REJECT
Explicación: La primera regla marca las conexiones entrantes al puerto 22. La segunda regla rechaza las conexiones que superen los 3 intentos en 60 segundos.

Ejercicio 4: Bloquear tráfico de una IP específica
Bloquear el acceso a tu servidor desde una dirección IP específica (por ejemplo, 192.168.1.100).
Comando:

bash
Copiar código
sudo iptables -A INPUT -s 192.168.1.100 -j DROP
Explicación: Esta regla bloquea todo el tráfico de la IP 192.168.1.100, impidiendo que se conecte al servidor.

Ejercicio 5: Permitir tráfico DNS y bloquear todo lo demás
Permitir tráfico DNS en el puerto 53 y bloquear todo el resto del tráfico entrante.
Comandos:

bash
Copiar código
sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT   # Permitir DNS
sudo iptables -A INPUT -j DROP                        # Bloquear todo lo demás
Explicación: Este conjunto de reglas permite el tráfico DNS (puerto 53) y bloquea el resto del tráfico entrante.

Comandos útiles
Limpiar reglas:
bash
Copiar código
sudo iptables -F   # Elimina todas las reglas
Guardar las reglas:
bash
Copiar código
sudo iptables-save > /etc/iptables/rules.v4  # Guarda las reglas en un archivo
Restaurar reglas:
bash
Copiar código
sudo iptables-restore < /etc/iptables/rules.v4  # Restaura las reglas desde un archivo
Conclusión
Con iptables, puedes configurar un firewall robusto para proteger tu servidor. Este tutorial cubre lo básico, pero existen muchísimas más opciones avanzadas para personalizar el tráfico de red según tus necesidades.

Es importante recordar que las reglas de iptables son procesadas de arriba hacia abajo, por lo que el orden de las reglas es crucial. Siempre prueba tus reglas en un entorno controlado antes de implementarlas en producción.

bash
Copiar código

Este tutorial cubre conceptos clave y ejercicios prácticos para empezar con **iptables**. Puedes ir ajustando los ejercicios de acuerdo a tus necesidades para experimentar más con la herramienta.



