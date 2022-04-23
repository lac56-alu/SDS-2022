/*
Cliente
*/
package cli

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

/*type respuestaServer struct {
	Ok    bool   `json:"Ok"`
	Msg   string `json:"Msg"`
	Token string `json:"Token"`
}*/
var UserNameGlobal string

func login(client *http.Client) {
	var usuario User = User{}
	fmt.Print("Username: ")
	var usernameLogin string
	fmt.Scanln(&usernameLogin)

	fmt.Print("\nContraseña: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fmt.Println("\n¡ERROR CONTRASEÑA!")
	}
	passs := string(bytePassword)
	//fmt.Printf("\nContraseña: %q", passs)
	hash := sha512.Sum512([]byte(passs))
	pass := hash[:32] // una mitad para el login (256 bits)
	//keyData := hash[32:64] // la otra para los datos (256 bits)
	usuario.Password = util.Encode64(pass)
	usuario.Username = usernameLogin
	data := url.Values{}
	data.Set("cmd", "login")
	data.Set("userName", usuario.Username)
	data.Set("pass", usuario.Password)
	r, _ := client.PostForm("https://localhost:10443", data)
	if r.StatusCode == 202 {
		fmt.Println("No existe usuario con datos introducidos")
	} else {
		if r.StatusCode == 203 {
			fmt.Println("Credenciales Invalidas")
		} else {
			if r.StatusCode == 200 {
				UserNameGlobal = usernameLogin
				menuSecundario(client)
			}
		}
	}
	/*io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	r.Body.Close()             // hay que cerrar el reader del body
	fmt.Println()*/
}

func registro(client *http.Client) bool {
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

	/*
		fmt.Printf("\nContraseña: %q", pass)

		jsonEnviar, errJSON := json.Marshal(usuario)
		if errJSON != nil {
			panic("\n¡ERROR CIFRAR JSON!")
		}

		respuestaServidor, errorServidor := client.Post("http://localhost:10443/register", "application/json; charset=utf-8", bytes.NewBuffer(jsonEnviar))
	*/

	data := url.Values{} // estructura para contener los valores
	data.Set("cmd", "prueba")
	data.Set("nombre", util.Encode64([]byte(usuario.Nombre)))
	data.Set("username", util.Encode64([]byte(usuario.Username)))
	data.Set("pass", usuario.Password)
	data.Set("email", util.Encode64([]byte(usuario.Email)))
	//data.Set("keyData", usuario.keyData)
	data.Set("publicKey", usuario.publicKey)
	data.Set("privateKey", usuario.privateKey)

	//pkJSON, err := json.Marshal(&pkClient) // codificamos con JSON
	//chk(err)

	r, errorServidor := client.PostForm("https://localhost:10443", data)
	//io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)

	//tokenUsuario := util.Decode64(r.Header.Get("Authoritation"))

	respuesta := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&respuesta)
	//fmt.Println()

	fmt.Println("\n --------------------------------------------------------------------------------------- \n")

	if errorServidor != nil {
		panic("\n¡ERROR SERVIDOR RESPUESTA!")
	}

	//defer r.Body.Close()

	if r.StatusCode == 400 {
		fmt.Println("\n ALGO SALIÓ MAL.... \n")
		return false
	}

	if r.StatusCode == 200 {
		fmt.Println("\n ¡TE HAS REGISTRADO DE FORMA CORRECTA! \n")
		fmt.Printf("\n Token: %q", respuesta.Token)
		return true
	}
	//fmt.Println(bodyString)
	r.Body.Close() // hay que cerrar el reader del body
	return false
}
func crearFichero(client *http.Client) {
	fmt.Print("Nombre Fichero: ")
	var fichero string
	fmt.Scanln(&fichero)
	fmt.Print("Texto: ")
	var texto string
	fmt.Scanln(&texto)

	data := url.Values{} // estructura para contener los valores
	data.Set("cmd", "create")
	data.Set("username", UserNameGlobal)
	data.Set("NombreFichero", fichero)
	data.Set("Texto", util.Encode64([]byte(texto)))

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

}
func listarFichero(client *http.Client) {

}
func verFichero(client *http.Client) {

}
func compartirFichero(client *http.Client) {

}
func comentar(client *http.Client) {
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
		fmt.Println(" 7. Volver al menu principal")
		fmt.Print("Opcion: ")
		fmt.Scanln(&eleccion)

		switch eleccion {
		case 1:
			crearFichero(client)
		case 2:
			subirFichero(client)
		case 3:
			listarFichero(client)
		case 4:
			verFichero(client)
		case 5:
			compartirFichero(client)
		case 6:
			comentar(client)
		case 7:
			volver = true
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
	/*
			// hash con SHA512 de la contraseña
			keyClient := sha512.Sum512([]byte("contraseña del cliente"))
			keyLogin := keyClient[:32]  // una mitad para el login (256 bits)
			keyData := keyClient[32:64] // la otra para los datos (256 bits)

		// hash con SHA512 de la contraseña
		/*keyClient := sha512.Sum512([]byte("contraseña del cliente"))
		keyLogin := keyClient[:32]  // una mitad para el login (256 bits)
		keyData := keyClient[32:64] // la otra para los datos (256 bits)

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
	*/
}
