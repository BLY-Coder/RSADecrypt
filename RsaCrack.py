#!/usr/bin/python3


from Crypto.PublicKey import RSA
from pwn import *

def def_handler(sig,frame):
	print("[!] Saliendo...")
	sys.exit(1)

# Cntrl + C

signal.signal(signal.SIGINT, def_handler)


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def generatePrivateKey():

	with open("decoder.pub","r") as f: # Abre la clave publica con permisos de lectura y la almacena en f.
		key = RSA.ImportKey(f.read())

	log.info("n -> %s" % key.n) # Saca n de la clave publica \ n = p * q
	log.info("e -> %s" % key.e) # Saca e de la clave publica

	p = "Numero primo1" # Sacar de la factorizacion de n
	q = "Numero primo2" # Sacar de la factorizacion de n

	n = key.n # Almacenar en variable n
	e = key.e # Almacenar en variable e

        log.info("p -> %s" % key.p)
        log.info("q -> %s" % key.q)

	m = n-(p+q-1) # Hay que sacar el valor de M para poder Hallar el valor de D
	d=modinv(e,m) # Hace la funcion modular multiplicativa inversa...

	log.info("m -> %s" % key.m)

	finalKey = RSA.construct((n, e, d, p, q)) #Construlle la CLAVE RSA
	print(finalKey.exportKey().decode) # Muestra la CLAVE RSA


if __name__ == '__main__':

	generatePrivateKey()
