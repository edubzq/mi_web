# coding=utf-8
#!/usr/bin/env python3

import socket
import selectors    #https://docs.python.org/3/library/selectors.html
import select
import types        # Para definir el tipo de datos data
import argparse     # Leer parametros de ejecución
import os           # Obtener ruta y extension
from datetime import datetime, timedelta # Fechas de los mensajes HTTP
import time         # Timeout conexión
import sys          # sys.exit
import re           # Analizador sintáctico
import logging      # Para imprimir logs



BUFSIZE = 8192 # Tamaño máximo del buffer que se puede utilizar
TIMEOUT_CONNECTION = 20 # Timout para la conexión persistente
MAX_ACCESOS = 10

# Extensiones admitidas (extension, name in HTTP)
filetypes = {"gif":"image/gif", "jpg":"image/jpg", "jpeg":"image/jpeg", "png":"image/png", "htm":"text/htm", 
             "html":"text/html", "css":"text/css", "js":"text/js"}

# Configuración de logging
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s.%(msecs)03d] [%(levelname)-7s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()


def send_message(cs, data):
    """ Esta función envía datos (data) a través del socket cs
        Devuelve el número de bytes enviados.
    """
    msg_cod = data.encode() #encode() sin parametros? O habría que poner .encode('utf-8') por ejemplo.
    cs.send(msg_cod)
    return len(msg_cod)


def recive_message(cs):
    """ Esta función recibe datos a través del socket cs
        Leemos la información que nos llega. recv() devuelve un string con los datos.
    """
    return cs.recv(BUFSIZE).decode() #¿Hay que hacer decode?



def close_conection(cs):
    """ Esta función cierra una conexión activa.
    """
    cs.close()


def process_cookies(headers,  cs):
    """ Esta función procesa la cookie cookie_counter
        1. Se analizan las cabeceras en headers para buscar la cabecera Cookie
        2. Una vez encontrada una cabecera Cookie se comprueba si el valor es cookie_counter
        3. Si no se encuentra cookie_counter , se devuelve 1
        4. Si se encuentra y tiene el valor MAX_ACCESSOS se devuelve MAX_ACCESOS
        5. Si se encuentra y tiene un valor 1 <= x < MAX_ACCESOS se incrementa en 1 y se devuelve el valor
    """
    pattern = re.compile(r'Cookie: cookie_counter=(\d+)') #Patron para el matching
    cookie_h = None #Header empieza como None 
    for header in headers:
        aux = re.fullmatch(pattern, header) #Buscamos un match
        if (aux != None ): cookie_h = aux

    if not cookie_h: return 1 #Si no encontramos match retorno 1

    counter = int(cookie_h.group(1)) #coockie_h.group(1) hace refencia a '(\d+)' de la RE

    if counter == MAX_ACCESOS: return MAX_ACCESOS

    counter+= 1
    return counter

    
def error_response (cs, code, message) : # ADDED.
    """Esta función envia un mensaje de error (code + message) por el socket (cs)
    """
    response = f"HTTP/1.1 {code} {message}\r\n" 
    response+="Date: {}\r\n".format(datetime.utcnow())
    response += "Server: CustomServer\r\n"
    response += "Connection: close\r\n"
    response += "\r\n"
    response += f"<html><body><h1>{code} {message}</h1></body></html>"
    cs.send(response.encode())
    #Habría que cerrar la conexión con un close()? Al ser un error?
    cs.close()


def process_web_request(cs, webroot):
    """ Procesamiento principal de los mensajes recibidos.
        Típicamente se seguirá un procedimiento similar al siguiente (aunque el alumno puede modificarlo si lo desea)

        * Bucle para esperar hasta que lleguen datos en la red a través del socket cs con select()

            * Se comprueba si hay que cerrar la conexión por exceder TIMEOUT_CONNECTION segundos
              sin recibir ningún mensaje o hay datos. Se utiliza select.select

            * Si no es por timeout y hay datos en el socket cs.
                * Leer los datos con recv.
                * Analizar que la línea de solicitud y comprobar está bien formateada según HTTP 1.1
                    * Devuelve una lista con los atributos de las cabeceras.
                    * Comprobar si la versión de HTTP es 1.1
                    * Comprobar si es un método GET o POST. Si no devolver un error Error 405 "Method Not Allowed".
                    * Leer URL y eliminar parámetros si los hubiera
                    * Comprobar si el recurso solicitado es /, En ese caso el recurso es index.html
                    * Construir la ruta absoluta del recurso (webroot + recurso solicitado)
                    * Comprobar que el recurso (fichero) existe, si no devolver Error 404 "Not found"
                    * Analizar las cabeceras. Imprimir cada cabecera y su valor. Si la cabecera es Cookie comprobar
                      el valor de cookie_counter para ver si ha llegado a MAX_ACCESOS.
                      Si se ha llegado a MAX_ACCESOS devolver un Error "403 Forbidden"
                    * Obtener el tamaño del recurso en bytes.
                    * Extraer extensión para obtener el tipo de archivo. Necesario para la cabecera Content-Type
                    * Preparar respuesta con código 200. Construir una respuesta que incluya: la línea de respuesta y
                      las cabeceras Date, Server, Connection, Set-Cookie (para la cookie cookie_counter),
                      Content-Length y Content-Type.
                    * Leer y enviar el contenido del fichero a retornar en el cuerpo de la respuesta.
                    * Se abre el fichero en modo lectura y modo binario
                        * Se lee el fichero en bloques de BUFSIZE bytes (8KB)
                        * Cuando ya no hay más información para leer, se corta el bucle

            * Si es por timeout, se cierra el socket tras el período de persistencia.
                * NOTA: Si hay algún error, enviar una respuesta de error con una pequeña página HTML que informe del error.
    """
    while True:
        try:
            rsublist, wsublist, xsublist = select.select([cs], [], [], TIMEOUT_CONNECTION)

            if not rsublist:
                error_response(cs, 408, "Request Timeout") #No hay cambios en el descriptor y se envia un 'Request Timeout'
                break

            rcv_msg = recive_message(cs)
            request_line = rcv_msg.split('\r\n')[0] #Obtener la linea de solicitud

            #Comprobar que la linea de solicitud es correcta

            rq_line_ok = re.fullmatch(r'(GET|POST|PUT|DELETE)\s(/.*)\s(HTTP 1.1)', request_line) #RE para el formato de la linea de solicitud
            if not rq_line_ok:
                error_response(cs, 400, "Bad Request")
                break

            #Compruebo que lo que obtengo es get o post y no put o delete
            method = rq_line_ok.group(0)
            
            if method not in ['GET', 'POST']:
                error_response(cs, 405, "Method not Allowed")
                break

            url = rq_line_ok.group(1).split('?')[0] #Obtiene la URL y elimina los 'query parameters'
            
            if url == '/': url = '/index.html'

            resource_path = os.path.join(webroot, url[1:]) #Ruta del recurso solicitado
            rsc_path_ok = os.path.isfile(resource_path)
            if not rsc_path_ok:
                error_response(cs, 404, "Not Found")
                break




        
        except Exception as e:
            print(f"Error: {e}")
            error_response(cs, 500, "Internal Server Error") #500 Error interno del servidor
            break


def main():
    """ Función principal del servidor
    """

    try:

        # Argument parser para obtener la ip y puerto de los parámetros de ejecución del programa. IP por defecto 0.0.0.0
        parser = argparse.ArgumentParser()
        parser.add_argument("-p", "--port", help="Puerto del servidor", type=int, required=True)
        parser.add_argument("-ip", "--host", help="Dirección IP del servidor o localhost", required=True)
        parser.add_argument("-wb", "--webroot", help="Directorio base desde donde se sirven los ficheros (p.ej. /home/user/mi_web)")
        parser.add_argument('--verbose', '-v', action='store_true', help='Incluir mensajes de depuración en la salida')
        args = parser.parse_args()


        if args.verbose:
            logger.setLevel(logging.DEBUG)

        logger.info('Enabling server in address {} and port {}.'.format(args.host, args.port))

        logger.info("Serving files from {}".format(args.webroot))

        """ Funcionalidad a realizar
        * Crea un socket TCP (SOCK_STREAM)
        * Permite reusar la misma dirección previamente vinculada a otro proceso. Debe ir antes de sock.bind
        * Vinculamos el socket a una IP y puerto elegidos

        * Escucha conexiones entrantes

        * Bucle infinito para mantener el servidor activo indefinidamente
            - Aceptamos la conexión

            - Creamos un proceso hijo

            - Si es el proceso hijo se cierra el socket del padre y procesar la petición con process_web_request()

            - Si es el proceso padre cerrar el socket que gestiona el hijo.
        """
    except KeyboardInterrupt:
        True

if __name__== "__main__":
    main()
