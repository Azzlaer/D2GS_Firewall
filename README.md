# D2GS_Firewall

Una actualización del firewall original [PythonFirewallD2GS](https://github.com/jcerutti/PythonFirewallD2GS) creada para proteger el proceso `D2GS.exe`.  
Con este sistema puedes filtrar paquetes, banear IPs, gestionar flood, login/cheats y monitorizar el proceso del servidor.

## Requisitos previos

- Python 3.11 o superior.  
- Bibliotecas Python necesarias:  
  ```bash
  pip install pydivert
  pip install psutil
  ```  
  (Ejecuta con privilegios de administrador en Windows y asegúrate de marcar “Add Python to PATH”).  
- Ejecuta con privilegios de administrador el archivo `firewall.bat` para que el firewall comience su operación.  

## Configuración

Edita el archivo `config.json` para ajustar los parámetros del firewall:

| Parámetro                     | Descripción |
|------------------------------|-------------|
| `BAN_DURATION`               | Tiempo en minutos que una IP queda baneada temporalmente por enviar paquetes “flood”. |
| `MAX_TEMP_BANS`              | Número máximo de baneos temporales permitidos para una IP antes de un baneo permanente. |
| `TIME_FOR_MAX_PACKETS`       | Intervalo en segundos para contabilizar paquetes de tipo “flood”. |
| `MAX_PACKETS_THRESHOLD`      | Número de paquetes “flood” permitidos durante el intervalo anterior antes de considerar malicioso. |
| `BLOCKED_PACKET_THRESHOLD`   | Número máximo de paquetes maliciosos antes de ban permanente. |
| `BLOCKED_PORT`               | Puerto que el firewall bloquea (por defecto el puerto de D2GS). |
| `LOGIN_PORT`                 | Puerto de login de PvPGN (normalmente no cambies). |
| `FIREWALL_RESTART`           | `true` o `false`: si el firewall debe reiniciarse tras ciertas horas para liberar memoria. |
| `FIREWALL_RESTART_HOURS`     | Número de horas tras las cuales se reinicia el firewall (ej: `24`). |
| `PROCESS_MONITOR`            | `true` o `false`: si debe monitorizar el proceso `D2GS.exe`. |
| `PROCESS_NAME`               | Nombre del ejecutable que se monitoriza (normalmente `D2GS.exe`). |
| `PROCESS_PATH`               | Ruta completa del ejecutable (usa doble `\\` en Windows). |

## Payloads (códigos hex que se filtran)

- `payloads.json` → Paquetes maliciosos que **nunca** deben llegar al proceso D2GS.  
- `payloads_login.json` → Códigos que disparan un baneo temporal (ej: detección de cheats al login).  
- `payloads_flood.json` → Paquetes que pueden pasar pero en exceso son considerados “flood”.  

Dentro de cada uno se pueden usar dos tipos de filtros:  
- `starting_with`: Si el paquete comienza con ese código, se detecta.  
- `fixed`: El paquete debe coincidir exactamente con ese código para que se detecte.  
Consulta `EXAMPLE_payloads.json` para ver ejemplos.  

## Baneos permanentes de IPs

Edita el archivo `permaban_ips.json` para ver o remover IPs baneadas permanentemente. Por ejemplo:  
```json
{"172.21.41.6": 1, "186.71.42.3": 1}
```  
Si quieres remover la IP `172.21.41.6`, simplemente deja:  
```json
{"186.71.42.3": 1}
```

## Ejecución

1. Asegúrate de que Python y las librerías estén instaladas.  
2. Edita `config.json`, `payloads*.json` y `permaban_ips.json` según tus necesidades.  
3. Ejecuta con privilegios de administrador el archivo `firewall.bat`.  
4. Monitoriza el log o comportamiento si lo deseas (puede estar en la consola o la salida que se configure).  

## Créditos

Este proyecto está basado en la obra de MayhemARG y los foros de [pvpgn.pro](https://forums.pvpgn.pro) — gracias por sentar las bases.  
La versión original “PythonFirewallD2GS” fue creada por jcerutti.  

## Licencia

*(Aquí deberías indicar bajo qué licencia está publicado este proyecto — si aún no lo has hecho, se recomienda añadir un LICENSE en el repositorio.)*  

## Contacto

Para dudas o sugerencias puedes contactarme (inserta tu correo o medio).  
¡Gracias por usar esta herramienta!
