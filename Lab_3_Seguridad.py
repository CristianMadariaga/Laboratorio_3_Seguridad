'''Lab 3 Seguridad Informatica
Integrantes: Cristian Madariaga, Christian De Jesus
Ayudante: Manuel Fuentes
Profesor: Manuel Alba

IMPORTANTE: Se requiere instalacion de libreria PyCryptodome'''
# -------------------------------------------------------------------------- #
#                                Importaciones                               #
# -------------------------------------------------------------------------- #
#!Ventana a utilizar tkinter
from time import sleep
from distutils.cmd import Command
from platform import java_ver
from select import select
import tkinter as tk
from tkinter.tix import Select
from tkinter import END, INSERT, filedialog
from secrets import token_bytes
from Crypto.Cipher import DES, DES3, AES

fields = 'Inserte valor P', 'Inserte valor G','Inserte valor a','Inserte valor b'
# -------------------------------------------------------------------------- #
#                                Diffie Hellman                              #
# -------------------------------------------------------------------------- #
#!Hacer Diffie Hellman
#*P = Llave publica cliente
#*G = Llave publica servidor
#*a = Llave privada cliente
#*b = Llave privada servidor
def Diffie (e):
    text.delete(1.0, END)
    fetch(e)
    P = int(valores[0])
    G = int(valores[1])
    a = int(valores[2])
    b = int(valores[3])
    
    generatedKey1 = int(pow(G,a,P))
    generatedKey2 = int(pow(G,b,P))
    
    ka = int(pow(generatedKey2,a,P))
    kb = int(pow(generatedKey1,b,P))
    text.insert(INSERT,'Su clave secreta 1 es: '+str(ka)+'\n')
    text.insert(INSERT,'Su clave secreta 2 es: '+str(kb)+'\n')
    
# -------------------------------------------------------------------------- #
#                           Funciones varias                                 #
# -------------------------------------------------------------------------- #
#!Función para obtener archivo
def GetFile():
    file_path = filedialog.askopenfilename(title = "Seleccione archivo de entrada",
                                                filetypes=[("Archivo de Texto","*.txt")])
    return file_path

#!Retornar valores ingresados por el usuario
valores = []
def fetch(entries):
    valores.clear()
    for entry in entries:
        field = entry[0]
        text  = entry[1].get()
        valores.append(text)

#!Generacion de los cuadros de ingreso de texto
def makeform(root, fields):
    entries = []
    for field in fields:
        row = tk.Frame(root)
        lab = tk.Label(row, width=15, text=field, anchor='w')
        ent = tk.Entry(row)
        row.pack(side=tk.TOP, padx=5, pady=5)
        lab.pack(side=tk.LEFT)
        ent.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)
        entries.append((field, ent))
    return entries
# -------------------------------------------------------------------------- #
#                                  Cifrado                                   #
# -------------------------------------------------------------------------- #
#!Llaves generadas con libreraria de bytes
key = token_bytes(8)
key2 = token_bytes(24)
key3 = token_bytes(16)
#!Encriptacion segun opcion escogida
def encrypt():
    text.delete(1.0, END)
    path = GetFile()
    #!Seleccion 1 --> DES
    if path != '' and var.get()==1:
        with open(path) as opened_file:
            content = opened_file.read()
            cipher = DES.new(key, DES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(content.encode('ascii'))
            text.insert(INSERT,'Mensaje encriptado con DES exitosamente\n')
            text.insert(INSERT,'\nSu mensaje cifrado es: '+str(ciphertext)+'\n')
            text.insert(INSERT,'\nDescifrando mensaje...\n')
            #!Proceso de descifrado
            decipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
            plaintext = decipher.decrypt(ciphertext)
            with open('MensajeRecibido.txt', 'w') as salida:
                salida.write(plaintext.decode('ascii'))
                text.insert(INSERT,'\nMensaje descifrado y guardado en MensajeRecibido.txt\n')
    #!Seleccion 2 --> DES3
    elif path != '' and var.get()==2:
        with open(path) as opened_file:
            content = opened_file.read()
            cipher = DES3.new(key2, DES3.MODE_EAX)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(content.encode('ascii'))
            text.insert(INSERT,'Mensaje encriptado con 3DES exitosamente\n')
            text.insert(INSERT,'\nSu mensaje cifrado es: '+str(ciphertext)+'\n')
            text.insert(INSERT,'\nDescifrando mensaje...\n')
            #!Proceso de descifrado
            decipher = DES3.new(key2, DES3.MODE_EAX, nonce=nonce)
            plaintext = decipher.decrypt(ciphertext)
            with open('MensajeRecibido.txt', 'w') as salida:
                salida.write(plaintext.decode('ascii'))
                text.insert(INSERT,'\nMensaje descifrado y guardado en MensajeRecibido.txt\n')
    #!Seleccion 3 --> AES
    elif path != '' and var.get()==3:
        with open(path) as opened_file:
            content = opened_file.read()
            cipher = AES.new(key3, AES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext, tag= cipher.encrypt_and_digest(content.encode('ascii'))
            text.insert(INSERT,'Mensaje encriptado con AES exitosamente\n')
            text.insert(INSERT,'\nSu mensaje cifrado es: '+str(ciphertext)+'\n')
            text.insert(INSERT,'\nDescifrando mensaje...\n')
            #!Proceso de descifrado
            decipher = AES.new(key3, DES3.MODE_EAX, nonce=nonce)
            plaintext = decipher.decrypt(ciphertext)
            with open('MensajeRecibido.txt', 'w') as salida:
                salida.write(plaintext.decode('ascii'))
                text.insert(INSERT,'\nMensaje descifrado y guardado en MensajeRecibido.txt\n')
    elif var.get()==0:
        text.insert(INSERT, 'No ha seleccionado metodo de encriptacion\n')
    else:
        text.insert(INSERT, 'No ha seleccionado archivo\n')
# -------------------------------------------------------------------------- #
#                        Orden de la ventana (interfaz)                      #
# -------------------------------------------------------------------------- #
if __name__ == '__main__':
    root = tk.Tk()
    root.geometry("1080x720")
    root.resizable(False, False)
    root.title("Seguridad Informatica - Laboratorio 3")

    #!Fondo de pantalla
    bg = tk.PhotoImage(file = "fondo.png")
    label1 = tk.Label(root, image = bg)
    label1.place(x = -2, y = 0)
    ents = makeform(root, fields)
    root.bind('<Return>', (lambda event, e=ents: fetch(e)))
    
    #!Botones para opciones
    orden = tk.Frame(root).pack(side=tk.TOP, padx=5, pady=5)
    var = tk.IntVar()
    opcion1 = tk.Radiobutton(orden, text="DES", variable=var, value=1)
    opcion1.pack(side=tk.TOP, padx=5, pady=5)
    opcion2 = tk.Radiobutton(orden, text="3DES", variable=var, value=2)
    opcion2.pack(side=tk.TOP, padx=5, pady=5)
    opcion3 = tk.Radiobutton(orden, text="AES", variable=var, value=3)
    opcion3.pack(side=tk.TOP, padx=5, pady=5)
    text = tk.Text(orden, height = 10, width = 60)
    text.pack(side=tk.TOP, padx=5, pady=5)
    
    #!Botones de accion
    b1 = tk.Button(root, text='Cifrar Archivo', command=encrypt).pack(side=tk.TOP,
                                                                     padx=5, pady=5)
    b2 = tk.Button(root, text='Calcular Clave Diffie',
                  command=(lambda e=ents: Diffie(e))).pack(side=tk.TOP, padx=5, pady=5)
    b3 = tk.Button(root, text='Salir', command=root.quit).pack(side=tk.TOP, padx=5, pady=5)

    root.mainloop()