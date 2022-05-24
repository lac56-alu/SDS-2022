/*
Servidor
*/
package srv

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sdshttp/util"
	"time"

	"golang.org/x/crypto/argon2"
)

//Almacenamiento de datos
//var usuariosRegistrados []user
var claveServidor = ""

var KeysServer *rsa.PrivateKey

// chk comprueba y sale si hay errores (ahorra escritura en programas sencillos)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// ejemplo de tipo para un usuario
type user struct {
	Name     string            // nombre de usuario
	Username string            // nick del usuario
	Email    string            // email de usuario
	Hash     []byte            // hash de la contraseña
	Salt     []byte            // sal para la contraseña
	Token    []byte            // token de sesión
	Seen     time.Time         // última vez que fue visto
	Data     map[string]string // datos adicionales del usuario
}

/*type User1 struct {
	Nombre   string `json:"nombre"`
	Username string `json:"userName"`
	Email    string `json:"email"`
	Password string `json:"password"`
}*/

type respuestaServer struct {
	Ok    string `json:"Ok"`
	Msg   string `json:"Msg"`
	Token string `json:"token"`
}

// mapa con todos los usuarios
// (se podría serializar con JSON o Gob, etc. y escribir/leer de disco para persistencia)
var gUsers map[string]user

func ComprobarToken(us string, tk []byte) bool {
	var comprobarToken bool = false
	var comprobarUsuarioBool bool = false
	usLog := us
	//fmt.Println("\n Nombre del usuario: ", usLog)

	var u = user{}

	for name := range gUsers {
		var c = util.Encode64(util.Decrypt(util.Decode64(name), util.Decode64(claveServidor)))
		//fmt.Println("\n Variable del Decrypt: ", c)
		//fmt.Println("Variable LogIn: ", usLog)

		if usLog == c {
			u = gUsers[name]
			comprobarUsuarioBool = true
		}
	}

	if comprobarUsuarioBool {
		if (u.Token == nil) || (time.Since(u.Seen).Minutes() > 60) {
			return comprobarToken
		} else if bytes.EqualFold(u.Token, tk) {
			comprobarToken = true
		}
	}

	return comprobarToken
}

// gestiona el modo servidor
func Run(clave string) {
	gUsers = make(map[string]user) // inicializamos mapa de usuarios

	var err error
	KeysServer, err = rsa.GenerateKey(rand.Reader, 4096) // se puede observar como tarda un poquito en generar
	chk(err)
	KeysServer.Precompute()

	//Leemos y almacenamos la clave que va a usar el servidor
	claveServidor = clave
	fmt.Println("Clave Servidor: " + claveServidor)

	http.HandleFunc("/", handler) // asignamos un handler global

	//Mis llamadas
	http.HandleFunc("/register", registro)
	//http.HandleFunc("/login", login)

	// escuchamos el puerto 10443 con https y comprobamos el error
	chk(http.ListenAndServeTLS(":10443", "localhost.crt", "localhost.key", nil))
}

func handler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                                                   // es necesario parsear el formulario
	w.Header().Set("Content-Type", "application/json; charset=UTF-8") // cabecera estándar

	switch req.Form.Get("cmd") { // comprobamos comando desde el cliente
	case "login": // ** login
		var comprobarUsuarioBool bool = false
		usLog := req.Form.Get("userName")
		fmt.Println("\n Nombre del usuario: ", usLog)

		//comprobarUsername := util.Encode64(util.Encrypt(util.Decode64(usLog), util.Decode64(claveServidor)))
		//u, ok := gUsers[comprobarUsername] // ¿existe ya el usuario?
		var u = user{}

		for name := range gUsers {
			//var opa = util.Encode64(util.Decrypt(util.Decode64(usLog), util.Decode64(claveServidor)))
			var c = util.Encode64(util.Decrypt(util.Decode64(name), util.Decode64(claveServidor)))
			fmt.Println("\n Variable del Decrypt: ", c)
			fmt.Println("Variable LogIn: ", usLog)

			if usLog == c {
				//fmt.Println("\n Encuentra en el bucle")
				u = gUsers[name]
				comprobarUsuarioBool = true
			}
		}

		if !comprobarUsuarioBool {
			//fmt.Println("\n NO HA ENCONTRADO AL USUARIO")
			w.WriteHeader(404)
			response(w, false, "Usuario inexistente", nil)
			return
		} else {
			/*
				fmt.Println("\n Entra en el else, varible true")
				salt := util.Decrypt(u.Salt, util.Decode64(claveServidor))
				fmt.Println("\n Salt LogIn: ", salt)
			*/
			password := util.Decode64(req.Form.Get("pass")) // obtenemos la contraseña (keyLogin)
			hash := argon2.IDKey([]byte(password), u.Salt, 1, 64*1024, 4, 32)

			if !bytes.Equal(u.Hash, hash) { // comparamos
				w.WriteHeader(401)
				response(w, false, "Credenciales inválidas", nil)

			} else {
				u.Seen = time.Now()        // asignamos tiempo de login
				u.Token = make([]byte, 16) // token (16 bytes == 128 bits)
				rand.Read(u.Token)         // el token es aleatorio
				gUsers[u.Name] = u
				response(w, true, "Credenciales válidas", u.Token)
				w.WriteHeader(200)
			}
		}

	case "data": // ** obtener datos de usuario
		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "No autentificado", nil)
			return
		} else if (u.Token == nil) || (time.Since(u.Seen).Minutes() > 60) {
			// sin token o con token expirado
			response(w, false, "No autentificado", nil)
			return
		} else if !bytes.EqualFold(u.Token, util.Decode64(req.Form.Get("token"))) {
			// token no coincide
			response(w, false, "No autentificado", nil)
			return
		}

		datos, err := json.Marshal(&u.Data) //
		chk(err)
		u.Seen = time.Now()
		gUsers[u.Name] = u
		response(w, true, string(datos), u.Token)

	case "registro":
		nombreRegistro := req.Form.Get("nombre")
		usernameRegistro := req.Form.Get("username")
		passRegistro := req.Form.Get("pass")
		emailRegistro := req.Form.Get("email")
		keyDataRegistro := req.Form.Get("keyData")
		publicKeyRegistro := req.Form.Get("publicKey")
		privateKeyRegistro := req.Form.Get("privateKey")

		u := user{}
		u.Username = util.Encode64(util.Encrypt(util.Decode64(usernameRegistro), util.Decode64(claveServidor)))

		for name := range gUsers {
			var opa = util.Encode64(util.Decrypt(util.Decode64(u.Username), util.Decode64(claveServidor)))
			var c = util.Encode64(util.Decrypt(util.Decode64(name), util.Decode64(claveServidor)))
			fmt.Println("\nVARIBABLE u:", u.Username)
			fmt.Println("\nVARIBABLE opa:", opa)
			fmt.Println("\nVariable Almacen:", name)
			fmt.Println("\nVariable Decrypt:", c)

			if opa == c {
				response(w, false, "Usuario ya registrado", nil)
				return
			}
		}

		u.Name = util.Encode64(util.Encrypt(util.Decode64(nombreRegistro), util.Decode64(claveServidor)))
		u.Email = util.Encode64(util.Encrypt(util.Decode64(emailRegistro), util.Decode64(claveServidor)))
		u.Username = util.Encode64(util.Encrypt(util.Decode64(usernameRegistro), util.Decode64(claveServidor)))
		fmt.Println("\nTu nombre:", u.Name)
		fmt.Println("\nTu email:", u.Email)
		fmt.Println("\nTu contraseña:", u.Username)
		u.Salt = make([]byte, 16)                                                                                        // sal (16 bytes == 128 bits)
		rand.Read(u.Salt)                                                                                                // la sal es aleatoria
		u.Data = make(map[string]string)                                                                                 // reservamos mapa de datos de usuario
		u.Data["private"] = util.Encode64(util.Encrypt(util.Decode64(privateKeyRegistro), util.Decode64(claveServidor))) // clave privada
		u.Data["public"] = util.Encode64(util.Encrypt(util.Decode64(publicKeyRegistro), util.Decode64(claveServidor)))   // clave pública
		u.Data["keyData"] = util.Encode64(util.Encrypt(util.Decode64(keyDataRegistro), util.Decode64(claveServidor)))
		password := util.Decode64(passRegistro) // contraseña (keyLogin)
		// Argon2
		u.Hash = argon2.IDKey([]byte(password), u.Salt, 1, 64*1024, 4, 32)

		u.Seen = time.Now()        // asignamos tiempo de login
		u.Token = make([]byte, 16) // token (16 bytes == 128 bits)
		rand.Read(u.Token)         // el token es aleatorio
		gUsers[u.Username] = u
		response(w, true, string("Te has registrado correctamente"), u.Token)

		/*
			_, ok := gUsers[usernameRegistro] // ¿existe ya el usuario?
			if ok {
				response(w, false, "Usuario ya registrado", nil)
				return
			}

			u.Email = util.Encode64(util.Encrypt(util.Decode64(emailRegistro), util.Decode64(claveServidor)))
			u.Username = util.Encode64(util.Encrypt(util.Decode64(usernameRegistro), util.Decode64(claveServidor)))
			fmt.Println("Username Sin: " + usernameRegistro)
			fmt.Println("Username Encrypt: " + u.Username)

			u.Salt = make([]byte, 16)                                                                                        // sal (16 bytes == 128 bits)
			rand.Read(u.Salt)                                                                                                // la sal es aleatoria
			u.Data = make(map[string]string)                                                                                 // reservamos mapa de datos de usuario
			u.Data["private"] = util.Encode64(util.Encrypt(util.Decode64(privateKeyRegistro), util.Decode64(claveServidor))) // clave privada
			u.Data["public"] = util.Encode64(util.Encrypt(util.Decode64(publicKeyRegistro), util.Decode64(claveServidor)))   // clave pública
			u.Data["keyData"] = util.Encode64(util.Encrypt(util.Decode64(keyDataRegistro), util.Decode64(claveServidor)))
			password := util.Decode64(passRegistro) // contraseña (keyLogin)


			//u := user{}
			u.Name = nombreRegistro
			u.Email = emailRegistro
			u.Username = util.Encode64(util.Encrypt(util.Decode64(usernameRegistro), util.Decode64(claveServidor)))
			//u.Username = usernameRegistro
			u.Salt = make([]byte, 16)              // sal (16 bytes == 128 bits)
			rand.Read(u.Salt)                      // la sal es aleatoria
			u.Data = make(map[string]string)       // reservamos mapa de datos de usuario
			u.Data["private"] = privateKeyRegistro // clave privada
			u.Data["public"] = publicKeyRegistro   // clave pública
			u.Data["keyData"] = keyDataRegistro
			password := util.Decode64(passRegistro) // contraseña (keyLogin)
		*/
	case "create":
		var comprobarUsuarioBool bool = false
		usLog := string(util.Decode64(req.Form.Get("userName")))

		//comprobarUsername := util.Encode64(util.Encrypt(util.Decode64(usLog), util.Decode64(claveServidor)))
		//u, ok := gUsers[comprobarUsername] // ¿existe ya el usuario?
		var u = user{}

		for name := range gUsers {
			//var opa = util.Encode64(util.Decrypt(util.Decode64(usLog), util.Decode64(claveServidor)))
			var c = util.Encode64(util.Decrypt(util.Decode64(name), util.Decode64(claveServidor)))
			//fmt.Println("\n Variable del Decrypt: ", c)
			//fmt.Println("Variable Usuario: ", usLog)

			if usLog == c {
				u = gUsers[name]
				comprobarUsuarioBool = true
			}
		}

		if !comprobarUsuarioBool {
			//response(w, false, "Usuario inexistente", nil)
			w.WriteHeader(404)
			response(w, false, "Usuario inexistente", nil)
			return
		} else {
			//fmt.Println("\n Entra en el else")

			texto := req.Form.Get("Texto")
			nom := req.Form.Get("NombreFichero")
			us := u.Name
			//path := "C:\\ServidorSDS"
			path := "F:\\ServidorSDS"

			_, erro := os.Stat(path)

			if os.IsNotExist(erro) {
				erro = os.Mkdir(path, 0755)
			}
			path += "\\" + us
			_, ero := os.Stat(path)
			if os.IsNotExist(ero) {
				ero = os.Mkdir(path, 0755)
			}
			f, err := os.Create(path + "\\" + nom + ".txt")
			if err != nil {
				w.WriteHeader(201)
				fmt.Println("Error: ", path)
				return
			} else {
				fmt.Fprintln(f, texto)
				f.Close()
				w.WriteHeader(200)
			}
		}

		/*nombre := string(util.Decode64(req.Form.Get("userName")))
		u, ok := gUsers[nombre] // ¿existe ya el usuario?
		if !ok {
			//response(w, false, "Usuario inexistente", nil)
			fmt.Println("No se ha encontrado al usuario")
			w.WriteHeader(202)
			return
		} else {
			fmt.Println("Se ha encontrado usuario")

			texto := req.Form.Get("Texto")
			nom := req.Form.Get("NombreFichero")
			fmt.Println("Nombre encoded: " + u.Name)

			//path := "C:\\Users\\Adel\\Desktop\\2122\\SDS\\ficheros\\" + u.Name
			path := "F:\\ServidorSDS\\" + u.Name
			us := string(util.Decode64(u.Name))
			//path := "C:\\ServidorSDS"
			_, erro := os.Stat(path)
			if os.IsNotExist(erro) {
				erro = os.Mkdir(path, 0755)
			}
			path += "\\" + us
			_, ero := os.Stat(path)
			if os.IsNotExist(ero) {
				ero = os.Mkdir(path, 0755)
			}
			f, err := os.Create(path + "\\" + nom + ".txt")
			if err != nil {
				w.WriteHeader(201)
				fmt.Println(path)
				return
			} else {
				fmt.Fprintln(f, texto)
				f.Close()
				w.WriteHeader(200)
			}
		}
		*/
	case "subir":
		u, ok := gUsers[req.Form.Get("userName")] // ¿existe ya el usuario?
		if !ok {
			//response(w, false, "Usuario inexistente", nil)
			w.WriteHeader(202)
			return
		} else {
			ubi := req.Form.Get("Ubicacion")
			nom := req.Form.Get("NombreFichero")
			path := ubi
			_, erro := os.Stat(path)
			if os.IsNotExist(erro) {
				w.WriteHeader(205)
				return
			}
			f, err := os.Open(path + "\\" + nom + ".txt")
			if err != nil {
				w.WriteHeader(203)
			} else {
				text := ""
				escan := bufio.NewScanner(f)
				for escan.Scan() {
					text += escan.Text() + "\n"
				}
				f.Close()
				//pathh := "C:\\ServidorSDS"
				pathh := "F:\\ServidorSDS"
				_, erro := os.Stat(pathh)
				if os.IsNotExist(erro) {
					erro = os.Mkdir(pathh, 0755)
				}
				pathh += "\\" + string(util.Decode64(u.Name))
				_, ero := os.Stat(pathh)
				if os.IsNotExist(ero) {
					ero = os.Mkdir(pathh, 0755)
				}
				f, err := os.Create(pathh + "\\" + nom + ".txt")
				if err != nil {
					w.WriteHeader(201)
					return
				} else {
					fmt.Fprintln(f, util.Encode64([]byte(text)))
					f.Close()
					w.WriteHeader(200)
				}

			}

		}
	case "ver":
		u, ok := gUsers[req.Form.Get("userName")] // ¿existe ya el usuario?
		if !ok {
			//response(w, false, "Usuario inexistente", nil)
			w.WriteHeader(202)
			return
		} else {

			nom := req.Form.Get("NombreFichero")
			//path := "C:\\ServidorSDS\\" + string((util.Decode64(u.Name)))
			path := "F:\\ServidorSDS\\" + string((util.Decode64(u.Name)))
			_, erro := os.Stat(path)
			if os.IsNotExist(erro) {
				w.WriteHeader(205)
				return
			}
			f, err := os.Open(path + "\\" + nom + ".txt")
			if err != nil {
				w.WriteHeader(203)
			} else {
				text := ""
				escan := bufio.NewScanner(f)
				for escan.Scan() {
					text += escan.Text() + "\n"
				}
				f.Close()
				response(w, true, text, nil)
			}
		}
	case "compartir":
		u, ok := gUsers[req.Form.Get("userName")] // ¿existe ya el usuario?
		if !ok {
			//response(w, false, "Usuario inexistente", nil)
			w.WriteHeader(202)
			return
		} else {
			ud, ok := gUsers[req.Form.Get("usuario")]
			if !ok {
				w.WriteHeader(203)
				return
			} else {
				nom := req.Form.Get("NombreFichero")

				//path := "C:\\ServidorSDS\\" + string((util.Decode64(u.Name)))
				path := "F:\\ServidorSDS\\" + string((util.Decode64(u.Name)))
				_, erro := os.Stat(path)
				if os.IsNotExist(erro) {
					w.WriteHeader(205)
					return
				}
				f, err := os.Open(path + "\\" + nom + ".txt")
				if err != nil {
					w.WriteHeader(206)
				} else {
					text := ""
					escan := bufio.NewScanner(f)
					for escan.Scan() {
						text += escan.Text() + "\n"
					}
					f.Close()

					//path := "C:\\ServidorSDS"
					path := "F:\\ServidorSDS"
					_, erro := os.Stat(path)
					if os.IsNotExist(erro) {
						erro = os.Mkdir(path, 0755)
					}
					path += "\\" + string(util.Decode64(ud.Name))
					_, ero := os.Stat(path)
					if os.IsNotExist(ero) {
						ero = os.Mkdir(path, 0755)
					}
					f, err := os.Create(path + "\\" + nom + ".txt")
					if err != nil {
						w.WriteHeader(201)
						return
					} else {
						fmt.Fprintln(f, text)
						f.Close()
					}
				}
			}
		}
	case "verificar":
		us := req.Form.Get("userName")
		tk := req.Form.Get("token")
		comprobar := ComprobarToken(us, util.Decode64(tk))

		if !comprobar {
			w.WriteHeader(402)
			response(w, false, "Token Expirado", nil)
		} else {
			w.WriteHeader(200)
			response(w, true, "Token Correcto", nil)
		}

	default:
		response(w, false, "Comando no implementado", nil)
	}

}

// respuesta del servidor
// (empieza con mayúscula ya que se utiliza en el cliente también)
// (los variables empiezan con mayúscula para que sean consideradas en el encoding)
type Resp struct {
	Ok    bool   // true -> correcto, false -> error
	Msg   string // mensaje adicional
	Token []byte // token de sesión para utilizar por el cliente
}

// función para escribir una respuesta del servidor
func response(w io.Writer, ok bool, msg string, token []byte) {
	r := Resp{Ok: ok, Msg: msg, Token: token} // formateamos respuesta
	rJSON, err := json.Marshal(&r)            // codificamos en JSON
	chk(err)                                  // comprobamos error
	w.Write(rJSON)                            // escribimos el JSON resultante
}

//Mis llamadas
func registro(w http.ResponseWriter, req *http.Request) {

	/*var usuario User1
	json.NewDecoder(req.Body).Decode(&usuario)

	fmt.Printf("\nNombre Usuario: %q", usuario.Nombre)
	*/
}
