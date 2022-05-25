/*
Cliente
*/
package cli

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"encoding/json"
	"fmt"
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
	Nombre     string `json:"nombre"`
	Username   string `json:"userName"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	keyData    string `json:"keyData"`
	publicKey  string `json:"publicKey"`
	privateKey string `json:"privateKey"`
}

var UserNameGlobal string

func login(client *http.Client) {
	var usuario User = User{}
	fmt.Print("Username: ")
	var usernameLogin string
	fmt.Scanln(&usernameLogin)

	fmt.Print("Contraseña: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fmt.Println("\n¡ERROR CONTRASEÑA!")
	}
	passs := string(bytePassword)
	hash := sha512.Sum512([]byte(passs))
	pass := hash[:32] // una mitad para el login (256 bits)
	//keyData := hash[32:64] // la otra para los datos (256 bits)
	usuario.Password = util.Encode64(pass)
	usuario.Username = util.Encode64([]byte(usernameLogin))
	data := url.Values{}
	data.Set("cmd", "login")
	data.Set("userName", usuario.Username)
	data.Set("pass", usuario.Password)
	r, _ := client.PostForm("https://localhost:10443", data)
	respuesta := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&respuesta)
	if respuesta.Ok == true {
		fmt.Println("Bienvenido " + usernameLogin)
		UserNameGlobal = usernameLogin
		menuSecundario(client)
	} else {
		fmt.Println(respuesta.Msg)
	}
	r.Body.Close()
}

func registro(client *http.Client) {
	var usuario User = User{}

	fmt.Print("Nombre: ")
	fmt.Scanln(&usuario.Nombre)

	fmt.Print("Username: ")
	fmt.Scanln(&usuario.Username)

	fmt.Print("Email: ")
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
	pass := hash[:32]      // una mitad para el login (256 bits)
	keyData := hash[32:64] // la otra para los datos (256 bits)
	usuario.Password = util.Encode64(pass)

	pkClient, err := rsa.GenerateKey(rand.Reader, 1024)
	chk(err)
	pkClient.Precompute() // aceleramos su uso con un precálculo

	pkJSON, err := json.Marshal(&pkClient) // codificamos con JSON
	chk(err)

	keyPub := pkClient.Public()           // extraemos la clave pública por separado
	pubJSON, err := json.Marshal(&keyPub) // y codificamos con JSON
	chk(err)

	// comprimimos y codificamos la clave pública
	usuario.publicKey = util.Encode64(util.Compress(pubJSON))
	usuario.privateKey = util.Encode64(util.Encrypt(util.Compress(pkJSON), keyData))

	usuario.keyData = util.Encode64(keyData)

	data := url.Values{} // estructura para contener los valores
	data.Set("cmd", "registro")
	data.Set("nombre", util.Encode64([]byte(usuario.Nombre)))
	data.Set("username", util.Encode64([]byte(usuario.Username)))
	data.Set("pass", usuario.Password)
	data.Set("email", util.Encode64([]byte(usuario.Email)))
	data.Set("keyData", usuario.keyData)
	data.Set("publicKey", usuario.publicKey)
	data.Set("privateKey", usuario.privateKey)

	r, errorServidor := client.PostForm("https://localhost:10443", data)

	respuesta := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&respuesta)

	if errorServidor != nil {
		panic("\n¡ERROR SERVIDOR RESPUESTA!")
	} else {
		fmt.Println(respuesta.Msg)
	}
	r.Body.Close()
}
func crearFichero(client *http.Client) {
	fmt.Print("Nombre Fichero: ")
	var fichero string
	fmt.Scanln(&fichero)
	fmt.Print("Texto: ")
	var texto string
	reader := bufio.NewReader(os.Stdin)
	texto, _ = reader.ReadString('\n')

	data := url.Values{}
	data.Set("cmd", "create")
	data.Set("userName", util.Encode64([]byte(UserNameGlobal)))
	data.Set("NombreFichero", fichero)
	data.Set("Texto", texto)

	r, _ := client.PostForm("https://localhost:10443", data)
	if r.StatusCode == 200 {
		fmt.Println("Fichero guardado con exito")
	} else {
		if r.StatusCode == 201 {
			fmt.Println("No ha sido posible crear el fichero")
		}
	}
}
func subirFichero(client *http.Client) {
	/*
		1) pasarle la ubicacion del archivo y el nombre
		2) copiamos tanto el nombre como el fichero como el contenido en un fichero
		en el servidor
	*/
	fmt.Print("Nombre Fichero: ")
	var fichero string
	fmt.Scanln(&fichero)
	fmt.Print("Ubicacion del fichero: ")
	var ubi string
	fmt.Scanln(&ubi)

	data := url.Values{}
	data.Set("cmd", "subir")
	data.Set("userName", util.Encode64([]byte(UserNameGlobal)))
	data.Set("NombreFichero", fichero)
	data.Set("Ubicacion", ubi)

	r, _ := client.PostForm("https://localhost:10443", data)
	if r.StatusCode == 200 {
		fmt.Println("Fichero guardado con exito en el servidor")
	} else {
		if r.StatusCode == 203 {
			fmt.Println("No ha encontrado el fichero para subir")
		} else {
			if r.StatusCode == 205 {
				fmt.Println("No existe la ubicacion introducida")
			} else {
				if r.StatusCode == 204 {
					fmt.Println("No se ha podido leer fichero introducido")
				} else {
					fmt.Println("No se ha podido subir fichero al servidor")
				}
			}
		}
	}
}
func listarFichero(client *http.Client) {
	/*
		1) buscar la carpeta del usuario == userName
		2) guardar array o vector los nombre de todos los ficheros que tenga
		3) mostrar todos los nombres
	*/
	data := url.Values{}
	data.Set("cmd", "listar")
	data.Set("userName", util.Encode64([]byte(UserNameGlobal)))
	r, _ := client.PostForm("https://localhost:10443", data)

	if r.StatusCode == 205 {
		fmt.Println("No existe carpeta con el nombre de usuario")
	} else {
		respuesta := srv.Resp{}
		json.NewDecoder(r.Body).Decode(&respuesta)
		fmt.Print(respuesta.Msg)
	}
}
func verFichero(client *http.Client) {
	/*
		1) metemos el nombre del fichero que queremos ver
		2) buscamos en la carpeta ese nombre
		3) sacamos por pantalla el nombre del fichero y el contenido
	*/
	fmt.Print("Nombre Fichero: ")
	var fichero string
	fmt.Scanln(&fichero)
	data := url.Values{}
	data.Set("cmd", "ver")
	data.Set("userName", util.Encode64([]byte(UserNameGlobal)))
	data.Set("NombreFichero", fichero)

	r, _ := client.PostForm("https://localhost:10443", data)
	if r.StatusCode == 205 {
		fmt.Println("No existe carpeta con tu nombre en el servidor")
	} else {
		if r.StatusCode == 203 {
			fmt.Println("No existe fichero con el nombre introducido")
		} else {
			respuesta := srv.Resp{}
			json.NewDecoder(r.Body).Decode(&respuesta)
			fmt.Println(respuesta.Msg)
		}
	}
	r.Body.Close()
}
func compartirFichero(client *http.Client) {
	/*
		1) pedimos el nombre del fichero que queremos compartir (comprobamos)
		2) pedimos del usuario al que se lo queremos compartir (comprobamos)
		3) copiamos el archivo desde el usuario origen al usuario destino
	*/
	fmt.Print("Nombre Fichero: ")
	var fichero string
	fmt.Scanln(&fichero)
	fmt.Print("UserName: ")
	var usern string
	fmt.Scanln(&usern)
	data := url.Values{}
	data.Set("cmd", "compartir")
	data.Set("userName", util.Encode64([]byte(UserNameGlobal)))
	data.Set("usuario", util.Encode64([]byte(usern)))
	data.Set("NombreFichero", fichero)

	r, _ := client.PostForm("https://localhost:10443", data)
	if r.StatusCode == 203 {
		fmt.Println("No existe el usuario introducido")
	} else {
		if r.StatusCode == 206 {
			fmt.Println("No existe fichero con el nombre introducido")
		} else {
			fmt.Println("Fichero copiado correctamente")
		}
	}
	r.Body.Close()

}
func comentar(client *http.Client) {
	/*
		hay que darle acceso al archivo de la carpeta del usuario origen
		o hay que copiar el archivo del usuario origen al destino
		si es asi, como se harian los comentarios
		es bueno hacer un struct para controlar los archivos
		struct: id fichero, contenido, usuarios compartidos, comentarios
	*/
}
func descargar(client *http.Client) {
	/*
		1) pedimos el nombre del fichero (comprobamos dentro de la carpeta)
		2) pedimos la ubicacion donde quiere copiar el archivo
		3) copiamos el archivo en la ubicacion del usuario
	*/
	fmt.Print("Nombre Fichero: ")
	var fichero string
	fmt.Scanln(&fichero)
	fmt.Print("Ubicacion: ")
	var ubi string
	fmt.Scanln(&ubi)
	data := url.Values{}
	data.Set("cmd", "descargar")
	data.Set("userName", util.Encode64([]byte(UserNameGlobal)))
	data.Set("Ubi", ubi)
	data.Set("NombreFichero", fichero)

	r, _ := client.PostForm("https://localhost:10443", data)
	if r.StatusCode == 205 {
		fmt.Println("No existe su carpeta en el sevidor")
	} else {
		if r.StatusCode == 206 {
			fmt.Println("No existe fichero con el nombre introducido")
		} else {
			if r.StatusCode == 204 {
				fmt.Println("No existe la ubicacion introducida")
			} else {
				if r.StatusCode == 201 {
					fmt.Println("No se ha podido guardar el fichero")
				} else {
					fmt.Println("Fichero descargado correctamente")
				}
			}
		}
	}
	r.Body.Close()

}

func menuSecundario(client *http.Client) {
	volver := false
	var eleccion int
	for volver == false {
		fmt.Println(" 1. Crear Fichero")
		fmt.Println(" 2. Subir Fichero")
		fmt.Println(" 3. Listar ficheros")
		fmt.Println(" 4. Ver Fichero")
		fmt.Println(" 5. Compartir Fichero")
		fmt.Println(" 6. Comentar")
		fmt.Println(" 7. Descargar Fichero")
		fmt.Println(" 8. Volver al menu principal")
		fmt.Print("Opcion: ")
		fmt.Scanln(&eleccion)

		switch eleccion {
		case 1:
			crearFichero(client)
			break
		case 2:
			subirFichero(client)
			break
		case 3:
			listarFichero(client)
			break
		case 4:
			verFichero(client)
			break
		case 5:
			compartirFichero(client)
			break
		case 6:
			comentar(client)
			break
		case 7:
			descargar(client)
			break
		case 8:
			volver = true
			break
		default:
			fmt.Println(" >>> Elige una de las opciones")
			menuSecundario(client)
		}

	}
	menuInicio(client)
}
func menuInicio(client *http.Client) {

	salir := false
	var eleccion int
	for salir == false {
		fmt.Println(" 1. Login")
		fmt.Println(" 2. Registro")
		fmt.Println(" 3. Salir")
		fmt.Print("Opcion: ")
		fmt.Scanln(&eleccion)

		switch eleccion {
		case 1:
			login(client)
			break
		case 2:
			registro(client)
			break
		case 3:
			salir = true
			break
		default:
			fmt.Println(" >>> Elige una de las opciones")
			menuInicio(client)
			break
		}
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
	fmt.Println("\n --------------------------------------------------------------------------------------- \n")
}
