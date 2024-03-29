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

type CurrentUser struct {
	Username string `json:"userName"`
	Token    []byte `json:"Token"`
	KeyData  []byte `json:"KeyData"`
}

var usuarioActivo CurrentUser = CurrentUser{}

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
	pass := hash[:32]      // una mitad para el login (256 bits)
	keyData := hash[32:64] // la otra para los datos (256 bits)
	usuario.Password = util.Encode64(pass)
	usuario.Username = usernameLogin
	data := url.Values{}
	data.Set("cmd", "login")
	data.Set("userName", usuario.Username)
	data.Set("pass", usuario.Password)
	r, _ := client.PostForm("https://localhost:10443", data)
	respuesta := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&respuesta)

	if r.StatusCode == 404 {
		fmt.Println("No existe usuario con datos introducidos")
	} else {
		if r.StatusCode == 401 {
			fmt.Println("Credenciales Invalidas")
		} else {
			if r.StatusCode == 200 {
				fmt.Println("¡Inicio sesion correcto!")
				UserNameGlobal = usuario.Username
				usuarioActivo.Username = usuario.Username
				usuarioActivo.Token = respuesta.Token
				usuarioActivo.KeyData = keyData

				menuSecundario(client)
			}
		}
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
	data.Set("nombre", util.Encode64(util.Encrypt([]byte(usuario.Nombre), keyData)))
	data.Set("username", usuario.Username)
	data.Set("pass", usuario.Password)
	data.Set("email", util.Encode64(util.Encrypt([]byte(usuario.Email), keyData)))

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

func verificarLogIn(client *http.Client) bool {
	var verificar bool = false
	data := url.Values{}
	data.Set("cmd", "verificar")
	data.Set("userName", usuarioActivo.Username)
	data.Set("token", util.Encode64(usuarioActivo.Token))

	r, _ := client.PostForm("https://localhost:10443", data)
	respuesta := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&respuesta)

	if r.StatusCode == 402 {
		fmt.Println("\nTu token ha expirado, realice de nuevo el LogIn")
	} else if r.StatusCode == 200 {
		fmt.Println("\nEsta autorizado")
		verificar = true
	}

	r.Body.Close()
	return verificar
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
	data.Set("userName", usuarioActivo.Username)
	data.Set("NombreFichero", fichero)
	data.Set("Texto", util.Encode64(util.Encrypt([]byte(texto), usuarioActivo.KeyData)))

	r, _ := client.PostForm("https://localhost:10443", data)
	if r.StatusCode == 200 {
		fmt.Println("Fichero guardado con exito")
	} else {
		if r.StatusCode == 201 {
			fmt.Println("No ha sido posible crear el fichero")
		} else {
			if r.StatusCode == 404 {
				fmt.Println("No se ha encontrado al usuario")
			}
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
	var text string
	fmt.Scanln(&ubi)
	path := ubi
	_, erro := os.Stat(path)
	if os.IsNotExist(erro) {
		fmt.Println("No existe la ubicacion introducida")
		return
	}
	f, err := os.Open(path + "\\" + fichero + ".txt")
	if err != nil {
		fmt.Println("No ha encontrado el fichero para subir")
		return
	} else {
		text = ""
		escan := bufio.NewScanner(f)
		for escan.Scan() {
			text += escan.Text()
		}
		f.Close()
	}

	data := url.Values{}
	data.Set("cmd", "create")
	data.Set("userName", usuarioActivo.Username)
	data.Set("NombreFichero", fichero)
	data.Set("Texto", util.Encode64(util.Encrypt([]byte(text), usuarioActivo.KeyData)))

	r, _ := client.PostForm("https://localhost:10443", data)
	if r.StatusCode == 200 {
		fmt.Println("Fichero guardado con exito")
	} else {
		if r.StatusCode == 201 {
			fmt.Println("No ha sido posible crear el fichero")
		} else {
			if r.StatusCode == 404 {
				fmt.Println("No se ha encontrado al usuario")
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
	data.Set("userName", usuarioActivo.Username)
	r, _ := client.PostForm("https://localhost:10443", data)

	if r.StatusCode == 205 {
		fmt.Println("No existe carpeta con el nombre de usuario")
	} else {
		respuesta := srv.Resp{}
		json.NewDecoder(r.Body).Decode(&respuesta)
		fmt.Println(respuesta.Msg)
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
	data.Set("userName", usuarioActivo.Username)
	data.Set("NombreFichero", fichero)

	r, _ := client.PostForm("https://localhost:10443", data)
	if r.StatusCode == 205 {
		fmt.Println("No existe carpeta con tu nombre en el servidor")
	} else {
		if r.StatusCode == 203 {
			fmt.Println("No existe fichero con el nombre introducido")
		} else {
			respuesta := srv.LecturaFic{}
			json.NewDecoder(r.Body).Decode(&respuesta)
			textoCifrado := respuesta.Content
			textoBien := util.Encode64(util.Decrypt(util.Decode64(textoCifrado), usuarioActivo.KeyData))
			auxTexto := string(util.Decode64(textoBien))
			fmt.Println("El contenido del fichero es: ", auxTexto)
			//Coments
			comentsCifrado := respuesta.Coments
			fmt.Println("Los comentarios existentes: ")
			var auxxTexto string
			for _, c := range comentsCifrado {
				if c == "" {
					auxxTexto = ""
				} else {
					comentsBien := util.Encode64(util.Decrypt(util.Decode64(c), usuarioActivo.KeyData))
					auxxTexto = string(util.Decode64(comentsBien))
				}
				fmt.Println(auxxTexto)
			}
			//users
			usersCifrado := respuesta.Users
			fmt.Println("Compartido con: ")
			//var auxxxTexto string
			for _, u := range usersCifrado {
				fmt.Println(u)
			}
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
	data.Set("userName", usuarioActivo.Username)
	data.Set("usuario", usern)
	data.Set("NombreFichero", fichero)

	r, _ := client.PostForm("https://localhost:10443", data)
	if r.StatusCode == 203 {
		fmt.Println("No existe el usuario introducido")
	} else {
		if r.StatusCode == 206 {
			fmt.Println("No existe fichero con el nombre introducido")
		} else {
			if r.StatusCode == 211 {
				fmt.Println("No existe carpeta con tu nombre")
			} else {
				fmt.Println("Fichero copiado correctamente")
			}
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
	fmt.Print("Nombre Fichero: ")
	var fichero string
	fmt.Scanln(&fichero)
	fmt.Print("Comentario: ")
	var comen string
	reader := bufio.NewReader(os.Stdin)
	comen, _ = reader.ReadString('\n')

	data := url.Values{}
	data.Set("cmd", "comentar")
	data.Set("userName", usuarioActivo.Username)
	data.Set("NombreFichero", fichero)
	data.Set("Comentario", util.Encode64(util.Encrypt([]byte(comen), usuarioActivo.KeyData)))

	r, _ := client.PostForm("https://localhost:10443", data)
	if r.StatusCode == 200 {
		fmt.Println("Comentario guardado con exito")
	} else {
		if r.StatusCode == 201 {
			fmt.Println("No se ha encontrado el fichero")
		} else {
			if r.StatusCode == 404 || r.StatusCode == 403 {
				fmt.Println("No se ha podido encontrar directorio")
			}
		}
	}
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
	data.Set("userName", usuarioActivo.Username)
	data.Set("NombreFichero", fichero)

	r, _ := client.PostForm("https://localhost:10443/", data)
	if r.StatusCode == 205 {
		fmt.Println("No existe su carpeta en el sevidor")
	} else {
		if r.StatusCode == 206 {
			fmt.Println("No existe fichero con el nombre introducido")
		} else {
			if r.StatusCode == 204 {
				fmt.Println("No se ha podido analizar el fichero")
			} else {
				respuesta := srv.Resp{}
				json.NewDecoder(r.Body).Decode(&respuesta)
				textoCifrado := respuesta.Msg
				textoBien := util.Encode64(util.Decrypt(util.Decode64(textoCifrado), usuarioActivo.KeyData))
				auxTexto := string(util.Decode64(textoBien))
				_, erro := os.Stat(ubi)
				if os.IsNotExist(erro) {
					fmt.Println("No existe la ubicacion introducida")
					return
				}
				f, err := os.Create(ubi + "/" + fichero + ".txt")

				if err != nil {
					fmt.Println("Error: No se ha podido guardar")
					return
				} else {
					f.WriteString(auxTexto)
					f.Close()
				}
				fmt.Println("Fichero descargado correctamente")

			}
		}
	}
	r.Body.Close()
}

func menuSecundario(client *http.Client) {
	volver := false
	var eleccion int
	for volver == false {
		if !verificarLogIn(client) {
			volver = true
			break
		}

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
			usuarioActivo = CurrentUser{}
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
