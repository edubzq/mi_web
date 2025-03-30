# coding=utf-8
# !/usr/bin/env python3

import socket
import selectors  # https://docs.python.org/3/library/selectors.html
import select
import types  # Para definir el tipo de datos data
import argparse  # Leer parametros de ejecución
import os  # Obtener ruta y extension
from datetime import datetime, timedelta  # Fechas de los mensajes HTTP
import time  # Timeout conexión
import sys  # sys.exit
import re  # Analizador sintáctico
import logging  # Para imprimir logs

BUFSIZE = 8192  # Tamaño máximo del buffer que se puede utilizar
TIMEOUT_CONNECTION = 20  # Timout para la conexión persistente
MAX_ACCESOS = 10

# Extensiones admitidas (extension, name in HTTP)
filetypes = {"gif": "image/gif", "jpg": "image/jpg", "jpeg": "image/jpeg", "png": "image/png", "htm": "text/htm",
             "html": "text/html", "css": "text/css", "js": "text/js"}

# Configuración de logging
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s.%(msecs)03d] [%(levelname)-7s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()


def send_message(cs, data):
    """ Esta función envía datos (data) a través del socket cs
        Devuelve el número de bytes enviados.
    """
    logging.info("Entrando en send_message")
    # NOTE Alfredo: el valor de enconding es utf-8 por defecto
    cs.send(data)
    logging.info("Saliendo en send_message")
    return len(data)


def recive_message(cs):
    """ Esta función recibe datos a través del socket cs
        Leemos la información que nos llega. recv() devuelve un string con los datos.
    """
    return cs.recv(BUFSIZE).decode('utf-8', 'replace')  # ¿Hay que hacer decode?


def close_conection(cs):
    """ Esta función cierra una conexión activa.
    """
    cs.close()


def process_cookies(headers, cs):
    """ Esta función procesa la cookie cookie_counter
        1. Se analizan las cabeceras en headers para buscar la cabecera Cookie
        2. Una vez encontrada una cabecera Cookie se comprueba si el valor es cookie_counter
        3. Si no se encuentra cookie_counter , se devuelve 1
        4. Si se encuentra y tiene el valor MAX_ACCESSOS se devuelve MAX_ACCESOS
        5. Si se encuentra y tiene un valor 1 <= x < MAX_ACCESOS se incrementa en 1 y se devuelve el valor
    """
    logging.info("entrando en cookie")
    pattern = re.compile(r'Cookie: cookie_counter=(\d+)') #Patron para el matching
    cookie_h = None #Header empieza como None 
    for header in headers: # NOTE: Esto se podría cambiar por un while
        aux = re.fullmatch(pattern, header) #Buscamos un match
        if aux: cookie_h = aux

    if not cookie_h: return 1 #Si no encontramos match retorno 1

    counter = int(cookie_h.group(1)) #coockie_h.group(1) hace refencia a '(\d+)' de la RE

    if counter == MAX_ACCESOS: return MAX_ACCESOS

    counter+= 1
    return counter


def error_response(cs, code, message):  # ADDED.
    """Esta función envia un mensaje de error (code + message) por el socket (cs)
    """
    response = "HTTP/1.1 {} {}\r\n".format(code, message)
    response += "Date: {}\r\n".format(datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT'))
    response += "Server: CustomServer\r\n"
    response += "Connection: close\r\n"
    response += "\r\n"
    response += "<html><body><h1> ERROR {} {}</h1></body></html>".format(code, message)
    cs.send(response.encode())
    # Habría que cerrar la conexión con un close()? Al ser un error?
    # cs.close()
    logging.info("Error")
    return 0


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
            """
            # Alternativa de internet
            lista_puertos = [cs]
            rsublist, wsublist, xsublist = select.select(lista_puertos, lista_puertos, [], TIMEOUT_CONNECTION)
            # Resto código: https://es.stackoverflow.com/questions/240662/creaci%C3%B3n-de-sockets-tcp-usando-select
            """
            logging.info("Entrando en el select")
            rsublist, wsublist, xsublist = select.select([cs], [], [], TIMEOUT_CONNECTION)
            logging.info("Select {}".format(rsublist))
            if not rsublist:
                error_response(cs, 408,
                               "Request Timeout")  # No hay cambios en el descriptor y se envia un 'Request Timeout'
                return

            logging.info("a")
            rcv_msg = recive_message(cs)
            logging.info("b")
            request_line = rcv_msg.split('\r\n')[0]  # Obtener la linea de solicitud
            logging.info("Mensaje RCV: {}".format(rcv_msg))
            logging.info("Request line: {}".format(request_line))
            # Comprobar que la linea de solicitud es correcta

            # NOTE: Cambio la forma de escribir de HTTP 1.1 a HTTP/1.1 porque así las enviaba firefox
            rq_line_ok = re.fullmatch(r'(GET|POST|PUT|DELETE)\s(/.*)\s(HTTP/.+)',
                                      request_line)  # RE para el formato de la linea de solicitud
            logging.info("rq_line_ok: {}".format(rq_line_ok))

            # if rq_line_ok is None:
            if not rq_line_ok:
                error_response(cs, 400, "Bad Request")
                return

            # Comprobar que sea la version HTTP 1.1
            v_http = rq_line_ok.group(3)
            logging.info("v_http {}".format(v_http))
            if v_http != 'HTTP/1.1':
                error_response(cs, 505, "HTTP Version Not Supported")
                return

            # Comprobar que el metodo es correcto
            method = rq_line_ok.group(1)
            logging.info("method {}".format(method))
            if method not in ['GET', 'POST']:
                error_response(cs, 405, "Method not Allowed")
                return

            url = rq_line_ok.group(2).split('?')[0]  # Obtiene la URL y elimina los 'query parameters'
            logging.info("URL {}".format(url))
            if url == '/':
                url = '/index.html'

            resource_path = os.path.join(webroot, url[1:])  # Ruta del recurso solicitado
            logging.info("resource_path {}".format(resource_path))
            rsc_path_ok = os.path.isfile(resource_path)
            logging.info("rsc_path_ok {}".format(rsc_path_ok))

            # Comprobar que la URL existe
            if not rsc_path_ok:
                error_response(cs, 404, "Not Found")
                return

            headers = rcv_msg.split('\r\n\r\n')[0].split('\r\n')[1:]
            logging.info("headers {}".format(headers))
            if url == "/index.html":
                cookie = process_cookies(headers, cs)  # NOTE: se ha añadido parámetro
                logging.info("cookie {}".format(cookie))
                if cookie == MAX_ACCESOS:
                    error_response(cs, 403, "Forbidden")
                    return

            rsc_size = os.stat(resource_path).st_size
            logging.info("rsc_size {}".format(rsc_size))
            f_extension = os.path.splitext(resource_path)[1].split('.')[
                1]  # Sin el '.' ya que en el dic de extensiones estan sin '.'
            logging.info("f_extension {}".format(f_extension))
            content_type = filetypes.get(f_extension,
                                         'application/octet-stream')  # application/octet-stream es la respuesta default para una extensión que no está en el dic
            logging.info("content_type {}".format(content_type))

            # Construimos la respuesta
            filepath = os.path.basename(resource_path)
            with open(filepath, "rb") as file:
                file_data = file.read()
                content_length = len(file_data)

            response = "HTTP/1.1 200 OK\r\n"
            response += "Date: {}\r\n".format(
                datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')) 
            response += "Server: ST-Server\r\n"
            response += "Connection: keep-alive\r\n"  # ¿keep-alive o close?
            response += "Set-Cookie: cookie_counter={}\r\n".format(cookie)
            response += "Content-Length: {}\r\n".format(content_length)
            response += "Content-Type: {}\r\n".format(content_type)
            response += "\r\n"

            i_chunk_size = min(BUFSIZE, content_length)
            i_chunk_data = file_data[:i_chunk_size]
            send_message(cs, response.encode() + i_chunk_data)

            offset = i_chunk_size
            while offset < content_length:
                end = min(offset + BUFSIZE, content_length)
                send_message(cs, file_data[offset:end])
                offset = end
            """
            # Construimos la respuesta
            # NOTE: No sé por qué, aquí los f strings dan errores de compilación
            response = "HTTP/1.1 200 OK\r\n"
            response += "Date: {}\r\n".format(datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT'))
            # ¿Qué hay que poner como parámetro de 'strftime()'?
            response += "Server: ST-Server\r\n"
            response += "Connection: keep-alive\r\n"  # ¿keep-alive o close?
            response += "Set-Cookie: cookie_counter={}\r\n".format(cookie)
            response += "Content-Length: {}\r\n".format(rsc_size)
            response += "Content-Type: {}\r\n".format(content_type)
            response += "\r\n"

            logging.info("response {}".format(response))
            # Leer y enviar el contenido del fichero a retornar en el cuerpo de la respuesta //TODO
            fichero = os.path.basename(resource_path)
            logging.info("fichero {}".format(fichero))
            with open(fichero, "rb") as fichero:
                f_body = fichero.read()
                if rsc_size <= BUFSIZE:
                    send_message(cs, response.encode() + f_body)
                else:
                    chunk_size = min(BUFSIZE, rsc_size)
                    chunk = f_body[:chunk_size]
                    send_message(cs, response.encode()+chunk)

                    offset = chunk_size
                    while offset < rsc_size:
                        end = min(offset + BUFSIZE, rsc_size)
                        chunk = f_body[offset:end]
                        send_message(cs, chunk)
                        offset = end
                    chunk = "0\r\n\r\n".encode()
                    send_message(cs, chunk)
            """
            #input()  # Para pausar
        except Exception as e:
            print("Error: {}".format(e))
            error_response(cs, 500, "Internal Server Error")  # 500 Error interno del servidor
            break

    return 0


def main():
    """ Función principal del servidor
    """

    try:

        # Argument parser para obtener la ip y puerto de los parámetros de ejecución del programa. IP por defecto 0.0.0.0
        parser = argparse.ArgumentParser()
        parser.add_argument("-p", "--port", help="Puerto del servidor", type=int, required=True)
        parser.add_argument("-ip", "--host", help="Dirección IP del servidor o localhost", required=True)
        parser.add_argument("-wb", "--webroot",
                            help="Directorio base desde donde se sirven los ficheros (p.ej. /home/user/mi_web)")
        parser.add_argument('--verbose', '-v', action='store_true', help='Incluir mensajes de depuración en la salida')
        args = parser.parse_args()

        if args.verbose:
            logger.setLevel(logging.DEBUG)

        logger.info('Enabling server in address {} and port {}.'.format(args.host, args.port))

        logger.info("Serving files from {}".format(args.webroot))

        # Funcionalidad a realizar
        # Crea un socket TCP (SOCK_STREAM)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=0)

        # Permite reusar la misma dirección previamente vinculada a otro proceso. Debe ir antes de sock.bind
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Vinculamos el socket a una IP y puerto elegidos
        server_socket.bind((args.host, args.port))

        # Escucha conexiones entrantes
        server_socket.listen()
        logger.info("Server listening on {}:{}".format(args.host, args.port))
        try:
            # Bucle infinito para mantener el servidor activo indefinidamente
            while True:

                # - Aceptamos la conexión
                client_socket, client_address = server_socket.accept()
                logger.info("Accepted connection from {}".format(client_address))
                # - Creamos un proceso hijo
                pid = os.fork()
                # - Si es el proceso hijo se cierra el socket del padre y procesar la petición con process_web_request()
                if pid == 0:
                    server_socket.close()
                    process_web_request(client_socket, args.webroot)
                    client_socket.close()
                    os._exit(0)  # Esto no lo entiendo
                # - Si es el proceso padre cerrar el socket que gestiona el hijo.
                else:
                    client_socket.close()

        finally:
            logger.info("Server shutting down...")
            server_socket.close()

    except KeyboardInterrupt:
        return True


if __name__ == "__main__":
    main()
