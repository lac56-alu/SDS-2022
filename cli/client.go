/*
Cliente
*/
package cli

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sdshttp/srv"
	"sdshttp/util"
	"syscall"

	"golang.org/x/term"
)

// chk comprueba y sale si hay errores (ahorra escritura en programas sencillos)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

type User struct {
	Nombre   string `json:"nombre"`
	Username string `json:"userName"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func login() {
	fmt.Println("Username: ")
	var usernameLogin string
	fmt.Scanln(&usernameLogin)

	fmt.Println("\nContraseña: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))

	if err != nil {
		fmt.Println("\n¡ERROR CONTRASEÑA!")
	}
	pass := string(bytePassword)
	fmt.Printf("\nContraseña: %q", pass)
}

func registro(client *http.Client) {
	var usuario User = User{}

	fmt.Println("Nombre: ")
	fmt.Scanln(&usuario.Nombre)

	fmt.Println("Username: ")
	fmt.Scanln(&usuario.Username)

	fmt.Println("Email: ")
	fmt.Scanln(&usuario.Email)

	var passwordRegister string
	var passwordConfirmRegister string

	for ok := true; ok; ok = (passwordConfirmRegister != passwordRegister) {
		if passwordConfirmRegister != passwordRegister {
			fmt.Println("\n Las contraseñas deben coincidir...")
		}
		fmt.Println("Contraseña: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))

		if err != nil {
			fmt.Println("\n¡ERROR CONTRASEÑA!")
		}
		passwordRegister = string(bytePassword)

		fmt.Println("Confirmar Contraseña: ")
		bytePassword2, err := term.ReadPassword(int(syscall.Stdin))

		if err != nil {
			fmt.Println("\n¡ERROR CONTRASEÑA!")
		}
		passwordConfirmRegister = string(bytePassword2)
	}

	hash := sha512.Sum512([]byte(passwordRegister))
	pass := hash[:32] // una mitad para el login (256 bits)
	//keyData := hash[32:64] // la otra para los datos (256 bits)
	usuario.Password = util.Encode64(pass)

	fmt.Printf("\nContraseña: %q", pass)

	jsonEnviar, errJSON := json.Marshal(usuario)
	if errJSON != nil {
		panic("\n¡ERROR CIFRAR JSON!")
	}

	respuestaServidor, errorServidor := client.Post("http://localhost:10443/register", "application/json; charset=utf-8", bytes.NewBuffer(jsonEnviar))

	if errorServidor != nil {
		panic("\n¡ERROR SERVIDOR RESPUESTA!")
	}

}

func menuInicio(client *http.Client) {
	fmt.Println(" 1. Login")
	fmt.Println(" 2. Registro\n")

	var eleccion int
	fmt.Scanln(&eleccion)

	switch eleccion {
	case 1:
		login()
	case 2:
		registro(client)
	default:
		fmt.Println(" >>> Elige una de las opciones")
		menuInicio(client)
	}
}

// Run gestiona el modo cliente
func Run() {
	/* creamos un cliente especial que no comprueba la validez de los certificados
	esto es necesario por que usamos certificados autofirmados (para pruebas) */
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	menuInicio(client)

	// hash con SHA512 de la contraseña
	keyClient := sha512.Sum512([]byte("contraseña del cliente"))
	keyLogin := keyClient[:32]  // una mitad para el login (256 bits)
	keyData := keyClient[32:64] // la otra para los datos (256 bits)

	// generamos un par de claves (privada, pública) para el servidor
	pkClient, err := rsa.GenerateKey(rand.Reader, 1024)
	chk(err)
	pkClient.Precompute() // aceleramos su uso con un precálculo

	pkJSON, err := json.Marshal(&pkClient) // codificamos con JSON
	chk(err)

	keyPub := pkClient.Public()           // extraemos la clave pública por separado
	pubJSON, err := json.Marshal(&keyPub) // y codificamos con JSON
	chk(err)

	// ** ejemplo de registro
	data := url.Values{}                      // estructura para contener los valores
	data.Set("cmd", "register")               // comando (string)
	data.Set("user", "usuario")               // usuario (string)
	data.Set("pass", util.Encode64(keyLogin)) // "contraseña" a base64

	// comprimimos y codificamos la clave pública
	data.Set("pubkey", util.Encode64(util.Compress(pubJSON)))

	// comprimimos, ciframos y codificamos la clave privada
	data.Set("prikey", util.Encode64(util.Encrypt(util.Compress(pkJSON), keyData)))

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	r.Body.Close()             // hay que cerrar el reader del body
	fmt.Println()

	// ** ejemplo de login
	data = url.Values{}
	data.Set("cmd", "login")                                  // comando (string)
	data.Set("user", "usuario")                               // usuario (string)
	data.Set("pass", util.Encode64(keyLogin))                 // contraseña (a base64 porque es []byte)
	r, err = client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	resp := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // decodificamos la respuesta para utilizar sus campos más adelante
	fmt.Println(resp)                     // imprimimos por pantalla
	r.Body.Close()                        // hay que cerrar el reader del body

	// ** ejemplo de data sin utilizar el token correcto
	badToken := make([]byte, 16)
	_, err = rand.Read(badToken)
	chk(err)

	data = url.Values{}
	data.Set("cmd", "data")                    // comando (string)
	data.Set("user", "usuario")                // usuario (string)
	data.Set("pass", util.Encode64(keyLogin))  // contraseña (a base64 porque es []byte)
	data.Set("token", util.Encode64(badToken)) // token incorrecto
	r, err = client.PostForm("https://localhost:10443", data)
	chk(err)
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	r.Body.Close()             // hay que cerrar el reader del body
	fmt.Println()

	// ** ejemplo de data con token correcto
	data = url.Values{}
	data.Set("cmd", "data")                      // comando (string)
	data.Set("user", "usuario")                  // usuario (string)
	data.Set("pass", util.Encode64(keyLogin))    // contraseña (a base64 porque es []byte)
	data.Set("token", util.Encode64(resp.Token)) // token correcto
	r, err = client.PostForm("https://localhost:10443", data)
	chk(err)
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	r.Body.Close()             // hay que cerrar el reader del body
	fmt.Println()

}