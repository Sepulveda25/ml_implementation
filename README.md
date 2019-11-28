# Deteccion de intrusiones utilizando Machine Learning

[Volver a documento raíz](https://gitlab.unc.edu.ar/csirt/csirt-docs/tree/master#csirt-docs)

En el siguiente documento se detalla como instalar y poner en funcionamiento el Sistema de Detecciones de Intrusiones implementado con tecnicas de Machine Learning.

## 1. Requerimientos

Se detallan los requisitos necesarios para la instalacion del sistema.

### Requerimientos de Hardware

El hardware necesario es dependiente del enlace el cual se quiere monitorear.
El sistema fue probado monitoreando un enlace de 300 Mb/s (promedio) en una maquina virtual con las siguientes especificaciones:

+ Núcleos CPU: 4
+ RAM: 8
+ Almacenamiento: 50 Gb

Tambien es importante destacar que el sistema puede funcionar en serie (monitoreando el enlace de entrada de nuestro host) o en paralelo (monitoreando otro enlace).
En el segundo caso, es necesario tener en nuestro servidor, un mirror del enlace a monitorear.

### Requerimientos de software

El sistema esta diseñado para trabajar en sistema operativo Debian o Ubuntu. Se desconoce si funciona para otros SOs.
El unico prerequisito de software es tener instalado Python3.

#### Instalando requerimientos

Puede instalar las dependencias utilizando los siguientes comandos:

```bash
sudo apt-get install python3-pip
sudo apt-get install tcpdump
sudo apt-get install libpcap-dev
sudo apt-get install inotify-tools
sudo apt-get install python3-venv

sudo apt-get install \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg2 \
    software-properties-common
```