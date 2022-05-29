/*
Servidor
*/
package srv

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sdshttp/util"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

//Almacenamiento de datos
var claveServidor = ""

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

type fichero struct {
	Name        string
	duenyo      string
	contenido   string
	usuarios    []string
	comentarios []string
}

type respuestaServer struct {
	Ok    string `json:"Ok"`
	Msg   string `json:"Msg"`
	Token string `json:"token"`
}

// mapa con todos los usuarios
// (se podría serializar con JSON o Gob, etc. y escribir/leer de disco para persistencia)
var gUsers map[string]user
var gFicheros map[string]fichero

func ComprobarToken(us string, tk []byte) bool {
	var comprobarToken bool = false
	var comprobarUsuarioBool bool = false
	usLog := us
	fmt.Println("\n Nombre del usuario: ", usLog)

	var u = user{}

	for name := range gUsers {
		var c = util.Encode64(util.Decrypt(util.Decode64(name), util.Decode64(claveServidor)))

		if usLog == string(util.Decode64(c)) {
			u = gUsers[name]
			comprobarUsuarioBool = true
			break
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
	gFicheros = make(map[string]fichero)

	//Leemos y almacenamos la clave que va a usar el servidor
	claveServidor = clave
	fmt.Println("Clave Servidor: " + claveServidor)

	http.HandleFunc("/", handler) // asignamos un handler global

	//Mis llamadas
	//http.HandleFunc("/register", registro)
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

			if usLog == string(util.Decode64(c)) {
				//fmt.Println("\n Encuentra en el bucle")
				u = gUsers[name]
				comprobarUsuarioBool = true
				break
			}
		}

		if !comprobarUsuarioBool {
			//fmt.Println("\n NO HA ENCONTRADO AL USUARIO")
			w.WriteHeader(404)
			response(w, false, "Usuario inexistente", nil)
			return
		} else {
			password := util.Decode64(req.Form.Get("pass")) // obtenemos la contraseña (keyLogin)
			hash := argon2.IDKey([]byte(password), u.Salt, 1, 64*1024, 4, 32)

			if !bytes.Equal(u.Hash, hash) { // comparamos
				w.WriteHeader(401)
				response(w, false, "Credenciales inválidas", nil)

			} else {
				u.Seen = time.Now()        // asignamos tiempo de login
				u.Token = make([]byte, 16) // token (16 bytes == 128 bits)
				rand.Read(u.Token)         // el token es aleatorio
				gUsers[u.Username] = u
				//fmt.Println("\nToken del LogIn: ", u.Token)
				response(w, true, "Credenciales válidas", u.Token)
				w.WriteHeader(200)
			}
		}
	case "registro":
		nombreRegistro := req.Form.Get("nombre")
		usernameRegistro := req.Form.Get("username")
		passRegistro := req.Form.Get("pass")
		emailRegistro := req.Form.Get("email")
		publicKeyRegistro := req.Form.Get("publicKey")
		privateKeyRegistro := req.Form.Get("privateKey")

		u := user{}
		u.Username = util.Encode64(util.Encrypt([]byte(usernameRegistro), util.Decode64(claveServidor)))

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

		var aux = util.Encode64(util.Encrypt([]byte(usernameRegistro), util.Decode64(claveServidor)))
		for ok := true; ok; ok = strings.ContainsAny(aux, "/") {
			aux = util.Encode64(util.Encrypt([]byte(usernameRegistro), util.Decode64(claveServidor)))
		}
		u.Username = aux

		fmt.Println("\nTu nombre:", u.Name)
		fmt.Println("\nTu email:", u.Email)
		fmt.Println("\nTu contraseña:", u.Username)
		u.Salt = make([]byte, 16)                                                                                        // sal (16 bytes == 128 bits)
		rand.Read(u.Salt)                                                                                                // la sal es aleatoria
		u.Data = make(map[string]string)                                                                                 // reservamos mapa de datos de usuario
		u.Data["private"] = util.Encode64(util.Encrypt(util.Decode64(privateKeyRegistro), util.Decode64(claveServidor))) // clave privada
		u.Data["public"] = util.Encode64(util.Encrypt(util.Decode64(publicKeyRegistro), util.Decode64(claveServidor)))   // clave pública
		password := util.Decode64(passRegistro)                                                                          // contraseña (keyLogin)
		// Argon2
		u.Hash = argon2.IDKey([]byte(password), u.Salt, 1, 64*1024, 4, 32)

		u.Seen = time.Now()        // asignamos tiempo de login
		u.Token = make([]byte, 16) // token (16 bytes == 128 bits)
		rand.Read(u.Token)         // el token es aleatorio
		gUsers[u.Username] = u
		response(w, true, string("Te has registrado correctamente"), u.Token)

	case "create":
		var comprobarUsuarioBool bool = false
		usLog := req.Form.Get("userName")

		//comprobarUsername := util.Encode64(util.Encrypt(util.Decode64(usLog), util.Decode64(claveServidor)))
		//u, ok := gUsers[comprobarUsername] // ¿existe ya el usuario?
		var u = user{}

		for name := range gUsers {
			var c = util.Encode64(util.Decrypt(util.Decode64(name), util.Decode64(claveServidor)))

			if usLog == string(util.Decode64(c)) {
				u = gUsers[name]
				comprobarUsuarioBool = true
				break
			}
		}

		if !comprobarUsuarioBool {
			w.WriteHeader(404)
			response(w, false, "Usuario inexistente", nil)
			return
		} else {

			texto := req.Form.Get("Texto")
			nom := req.Form.Get("NombreFichero")
			us := u.Username
			path := "./ServidorSDS"

			_, erro := os.Stat(path)

			if os.IsNotExist(erro) {
				w.WriteHeader(404)
				erro = os.Mkdir(path, 0755)
			}
			path += "/" + us
			_, ero := os.Stat(path)
			if os.IsNotExist(ero) {
				w.WriteHeader(500)
				ero = os.Mkdir(path, 0755)
			}

			var aux = util.Encode64(util.Encrypt([]byte(nom), util.Decode64(claveServidor)))
			for ok := true; ok; ok = strings.ContainsAny(aux, "/") {
				aux = util.Encode64(util.Encrypt([]byte(nom), util.Decode64(claveServidor)))
			}

			f, err := os.Create(path + "/" + aux + ".txt")

			if err != nil {
				w.WriteHeader(201)
				fmt.Println("Error: ", path)
				return
			} else {
				f.WriteString(texto)
				f.Close()
				fi := fichero{}
				fi.duenyo = u.Username
				fi.contenido = texto
				fi.usuarios = append(fi.usuarios, "")
				fi.comentarios = append(fi.comentarios, "")
				fi.Name = aux
				gFicheros[fi.Name] = fi
				w.WriteHeader(200)
			}
		}
	case "subir":
		var comprobarUsuarioBool bool = false
		usLog := req.Form.Get("userName")
		fmt.Println("\n Nombre del usuario: ", usLog)
		var u = user{}

		for name := range gUsers {
			var c = util.Encode64(util.Decrypt(util.Decode64(name), util.Decode64(claveServidor)))

			if usLog == string(util.Decode64(c)) {
				u = gUsers[name]
				comprobarUsuarioBool = true
				break
			}
		}

		if !comprobarUsuarioBool {
			w.WriteHeader(404)
			response(w, false, "Usuario inexistente", nil)
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
				pathh := "./ServidorSDS/"
				_, erro := os.Stat(pathh)
				if os.IsNotExist(erro) {
					erro = os.Mkdir(pathh, 0755)
				}
				pathh += u.Username
				_, ero := os.Stat(pathh)
				if os.IsNotExist(ero) {
					ero = os.Mkdir(pathh, 0755)
				}
				aux := util.Encode64(util.Encrypt([]byte(nom), util.Decode64(claveServidor)))
				f, err := os.Create(pathh + "/" + string(aux) + ".txt")

				if err != nil {
					w.WriteHeader(201)
					return
				} else {
					fmt.Fprintln(f, util.Encode64(util.Encrypt([]byte(text), util.Decode64(claveServidor))))
					f.Close()
					fi := fichero{}
					fi.duenyo = u.Username
					fi.contenido = util.Encode64(util.Encrypt([]byte(text), util.Decode64(claveServidor)))
					fi.usuarios = append(fi.usuarios, "")
					fi.comentarios = append(fi.comentarios, "")
					fi.Name = aux
					gFicheros[fi.Name] = fi
					w.WriteHeader(200)
				}

			}
		}
	case "ver":
		var comprobarUsuarioBool bool = false
		var comprobarficheroBool bool = false
		usLog := req.Form.Get("userName")
		var u = user{}

		for name := range gUsers {
			var c = util.Encode64(util.Decrypt(util.Decode64(name), util.Decode64(claveServidor)))

			if usLog == string(util.Decode64(c)) {
				u = gUsers[name]
				comprobarUsuarioBool = true
				break
			}
		}

		if !comprobarUsuarioBool {
			w.WriteHeader(404)
			response(w, false, "Usuario inexistente", nil)
			return
		} else {
			nom := req.Form.Get("NombreFichero")
			path := "./ServidorSDS/" + u.Username
			_, erro := os.Stat(path)

			if os.IsNotExist(erro) {
				w.WriteHeader(205)
				return
			}

			listado, err := os.ReadDir(path)
			if err != nil {
				w.WriteHeader(211)
				return
			}

			var nombreFicheroCifrado string

			for i := 0; i < len(listado); i++ {
				longitudNombre := len(listado[i].Name()) - 4
				cadena := listado[i].Name()[0:longitudNombre]

				aux := util.Encode64(util.Decrypt(util.Decode64(cadena), util.Decode64(claveServidor)))
				aux2 := string(util.Decode64(aux))

				if nom == aux2 {
					nombreFicheroCifrado = listado[i].Name()
					break
				}
			}

			if nombreFicheroCifrado == "" {
				w.WriteHeader(203)
				return
			} else {
				f, err := os.Open(path + "/" + nombreFicheroCifrado)
				if err != nil {
					w.WriteHeader(203)
				} else {
					text := ""
					escan := bufio.NewScanner(f)
					for escan.Scan() {
						text += escan.Text()
					}
					f.Close()
					var fic = fichero{}

					for name := range gFicheros {
						var c = util.Encode64(util.Decrypt(util.Decode64(name), util.Decode64(claveServidor)))

						if nom == string(util.Decode64(c)) {
							fic = gFicheros[name]
							comprobarficheroBool = true
							break
						}
					}

					if !comprobarficheroBool {
						return
					} else {
						responseLectura(w, text, fic.usuarios, fic.comentarios)
					}
				}
			}

		}
	case "compartir":
		var comprobarUsuarioBool bool = false
		usLog := req.Form.Get("userName")
		var u = user{}

		for name := range gUsers {
			var c = util.Encode64(util.Decrypt(util.Decode64(name), util.Decode64(claveServidor)))

			if usLog == string(util.Decode64(c)) {
				u = gUsers[name]
				comprobarUsuarioBool = true
				break
			}
		}

		if !comprobarUsuarioBool {
			w.WriteHeader(404)
			response(w, false, "Usuario inexistente", nil)
			return
		} else {
			var comprobarUsuarioBooll bool = false
			var comprobarficheroBool bool = false
			usLogg := req.Form.Get("usuario")

			var ud = user{}

			for name := range gUsers {
				var c = util.Encode64(util.Decrypt(util.Decode64(name), util.Decode64(claveServidor)))

				if usLogg == string(util.Decode64(c)) {
					ud = gUsers[name]
					comprobarUsuarioBooll = true
					break
				}
			}

			if !comprobarUsuarioBooll {
				w.WriteHeader(203)
				return
			} else {
				nom := req.Form.Get("NombreFichero")
				path := "./ServidorSDS/" + u.Username
				_, erro := os.Stat(path)

				if os.IsNotExist(erro) {
					w.WriteHeader(205)
					return
				}

				listado, err := os.ReadDir(path)
				if err != nil {
					w.WriteHeader(211)
					return
				}

				var nombreFicheroCifrado string

				for i := 0; i < len(listado); i++ {
					longitudNombre := len(listado[i].Name()) - 4
					cadena := listado[i].Name()[0:longitudNombre]

					aux := util.Encode64(util.Decrypt(util.Decode64(cadena), util.Decode64(claveServidor)))
					aux2 := string(util.Decode64(aux))

					if nom == aux2 {
						nombreFicheroCifrado = listado[i].Name()
						break
					}
				}

				if nombreFicheroCifrado == "" {
					w.WriteHeader(206)
					return
				} else {
					f, err := os.Open(path + "/" + nombreFicheroCifrado)
					if err != nil {
						w.WriteHeader(210)
					} else {
						text := ""
						escan := bufio.NewScanner(f)
						for escan.Scan() {
							text += escan.Text()
						}
						f.Close()
						var fic = fichero{}

						for name := range gFicheros {
							var c = util.Encode64(util.Decrypt(util.Decode64(name), util.Decode64(claveServidor)))

							if nom == string(util.Decode64(c)) {
								fic = gFicheros[name]
								comprobarficheroBool = true
								break
							}
						}

						if !comprobarficheroBool {
							return
						} else {
							fic.usuarios = append(fic.usuarios, usLogg)
							gFicheros[fic.Name] = fic
							path := "./ServidorSDS"

							_, erro := os.Stat(path)

							if os.IsNotExist(erro) {
								w.WriteHeader(404)
								erro = os.Mkdir(path, 0755)
							}
							path += "/" + ud.Username
							_, ero := os.Stat(path)
							if os.IsNotExist(ero) {
								w.WriteHeader(500)
								ero = os.Mkdir(path, 0755)
							}

							f, err := os.Create(path + "/" + fic.Name + ".txt")

							if err != nil {
								w.WriteHeader(201)
								fmt.Println("Error: ", path)
								return
							} else {
								f.WriteString(fic.contenido)
								f.Close()
								w.WriteHeader(200)
							}
						}

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
	case "listar":
		var comprobarUsuarioBool bool = false
		usLog := req.Form.Get("userName")

		var u = user{}

		for name := range gUsers {
			var c = util.Encode64(util.Decrypt(util.Decode64(name), util.Decode64(claveServidor)))

			if usLog == string(util.Decode64(c)) {
				u = gUsers[name]
				comprobarUsuarioBool = true
				break
			}
		}

		if !comprobarUsuarioBool {
			w.WriteHeader(404)
			response(w, false, "Usuario inexistente", nil)
			return
		} else {
			path := "./ServidorSDS/" + u.Username
			_, erro := os.Stat(path)

			if os.IsNotExist(erro) {
				w.WriteHeader(205)
				return
			}

			listado, err := os.ReadDir(path)
			if err != nil {
				w.WriteHeader(211)
				return
			}

			var lista = "Tu lista de ficheros son: \n"
			for i := 0; i < len(listado); i++ {
				longitudNombre := len(listado[i].Name()) - 4
				cadena := listado[i].Name()[0:longitudNombre]

				aux := util.Encode64(util.Decrypt(util.Decode64(cadena), util.Decode64(claveServidor)))
				aux2 := string(util.Decode64(aux))
				lista += aux2 + "\n"
			}
			response(w, true, lista, nil)
		}
	case "descargar":
		var comprobarUsuarioBool bool = false
		usLog := req.Form.Get("userName")
		var u = user{}

		for name := range gUsers {
			var c = util.Encode64(util.Decrypt(util.Decode64(name), util.Decode64(claveServidor)))

			if usLog == string(util.Decode64(c)) {
				u = gUsers[name]
				comprobarUsuarioBool = true
				break
			}
		}

		if !comprobarUsuarioBool {
			w.WriteHeader(404)
			response(w, false, "Usuario inexistente", nil)
			return
		} else {
			nom := req.Form.Get("NombreFichero")
			path := "./ServidorSDS/" + u.Username
			_, erro := os.Stat(path)

			if os.IsNotExist(erro) {
				w.WriteHeader(205)
				return
			}

			listado, err := os.ReadDir(path)
			if err != nil {
				w.WriteHeader(211)
				return
			}

			var nombreFicheroCifrado string

			for i := 0; i < len(listado); i++ {
				longitudNombre := len(listado[i].Name()) - 4
				cadena := listado[i].Name()[0:longitudNombre]

				aux := util.Encode64(util.Decrypt(util.Decode64(cadena), util.Decode64(claveServidor)))
				aux2 := string(util.Decode64(aux))

				if nom == aux2 {
					nombreFicheroCifrado = listado[i].Name()
					break
				}
			}

			if nombreFicheroCifrado == "" {
				w.WriteHeader(206)
				return
			} else {
				f, err := os.Open(path + "/" + nombreFicheroCifrado)
				if err != nil {
					w.WriteHeader(204)
				} else {
					text := ""
					escan := bufio.NewScanner(f)
					for escan.Scan() {
						text += escan.Text()
					}
					f.Close()

					response(w, true, text, nil)
				}
			}

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

type LecturaFic struct {
	Coments []string
	Users   []string
	Content string
}

func responseLectura(w io.Writer, contenido string, usuarios []string, comentarios []string) {
	r := LecturaFic{Coments: comentarios, Users: usuarios, Content: contenido} // formateamos respuesta
	rJSON, err := json.Marshal(&r)                                             // codificamos en JSON
	chk(err)                                                                   // comprobamos error
	w.Write(rJSON)                                                             // escribimos el JSON resultante
}

// función para escribir una respuesta del servidor
func response(w io.Writer, ok bool, msg string, token []byte) {
	r := Resp{Ok: ok, Msg: msg, Token: token} // formateamos respuesta
	rJSON, err := json.Marshal(&r)            // codificamos en JSON
	chk(err)                                  // comprobamos error
	w.Write(rJSON)                            // escribimos el JSON resultante
}
