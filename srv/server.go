/*
Servidor
*/
package srv

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sdshttp/util"
	"time"

	"golang.org/x/crypto/scrypt"
)

//Almacenamiento de datos
//var usuariosRegistrados []user

// chk comprueba y sale si hay errores (ahorra escritura en programas sencillos)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// ejemplo de tipo para un usuario
type user struct {
	Name   string // nombre de usuario
	Email  string
	Nombre string
	Hash   []byte            // hash de la contraseña
	Salt   []byte            // sal para la contraseña
	Token  []byte            // token de sesión
	Seen   time.Time         // última vez que fue visto
	Data   map[string]string // datos adicionales del usuario
}

/*type User1 struct {
	Nombre   string `json:"nombre"`
	Username string `json:"userName"`
	Email    string `json:"email"`
	Password string `json:"password"`
}*/

// mapa con todos los usuarios
// (se podría serializar con JSON o Gob, etc. y escribir/leer de disco para persistencia)
var gUsers map[string]user

// gestiona el modo servidor
func Run() {
	gUsers = make(map[string]user) // inicializamos mapa de usuarios

	http.HandleFunc("/", handler) // asignamos un handler global

	//Mis llamadas
	http.HandleFunc("/register", registro)
	//http.HandleFunc("/login", login)

	// escuchamos el puerto 10443 con https y comprobamos el error
	chk(http.ListenAndServeTLS(":10443", "localhost.crt", "localhost.key", nil))
}

func handler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	switch req.Form.Get("cmd") { // comprobamos comando desde el cliente
	case "register": // ** registro
		_, ok := gUsers[req.Form.Get("userName")] // ¿existe ya el usuario?
		if ok {
			//response(w, false, "Usuario ya registrado", nil)
			w.WriteHeader(201)
			return
		} else {
			u := user{}
			u.Name = req.Form.Get("userName")
			u.Nombre = req.Form.Get("Nombre")
			u.Email = string(util.Decode64(req.Form.Get("email")))
			u.Salt = make([]byte, 16)                       // sal (16 bytes == 128 bits)
			rand.Read(u.Salt)                               // la sal es aleatoria
			u.Data = make(map[string]string)                // reservamos mapa de datos de usuario
			u.Data["private"] = req.Form.Get("prikey")      // clave privada
			u.Data["public"] = req.Form.Get("pubkey")       // clave pública
			password := util.Decode64(req.Form.Get("pass")) // contraseña (keyLogin)

			// "hasheamos" la contraseña con scrypt (argon2 es mejor)
			u.Hash, _ = scrypt.Key(password, u.Salt, 16384, 8, 1, 32)

			u.Seen = time.Now()        // asignamos tiempo de login
			u.Token = make([]byte, 16) // token (16 bytes == 128 bits)
			rand.Read(u.Token)         // el token es aleatorio

			gUsers[u.Name] = u
			//response(w, true, "Usuario registrado", u.Token)
			w.WriteHeader(200)
		}

	case "login": // ** login
		u, ok := gUsers[req.Form.Get("userName")] // ¿existe ya el usuario?
		if !ok {
			//response(w, false, "Usuario inexistente", nil)
			w.WriteHeader(202)
			return
		} else {
			password := util.Decode64(req.Form.Get("pass"))          // obtenemos la contraseña (keyLogin)
			hash, _ := scrypt.Key(password, u.Salt, 16384, 8, 1, 32) // scrypt de keyLogin (argon2 es mejor)
			if !bytes.Equal(u.Hash, hash) {                          // comparamos
				//response(w, false, "Credenciales inválidas", nil)
				w.WriteHeader(203)
			} else {
				u.Seen = time.Now()        // asignamos tiempo de login
				u.Token = make([]byte, 16) // token (16 bytes == 128 bits)
				rand.Read(u.Token)         // el token es aleatorio
				gUsers[u.Name] = u
				//response(w, true, "Credenciales válidas", u.Token)
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

	case "create":
		u, ok := gUsers[req.Form.Get("username")] // ¿existe ya el usuario?
		if !ok {
			//response(w, false, "Usuario inexistente", nil)
			w.WriteHeader(202)
			return
		} else {
			texto := req.Form.Get("Texto")
			nom := req.Form.Get("NombreFichero")
			fmt.Println(u.Name)
			path := "C:\\Users\\Adel\\Desktop\\2122\\SDS\\ficheros\\" + u.Name
			_, erro := os.Stat(path)
			if os.IsNotExist(erro) {
				erro = os.Mkdir(path, 0755)
			}
			f, err := os.Create(path + "\\" + nom + ".txt")
			if err != nil {
				w.WriteHeader(201)
				return
			} else {
				fmt.Fprintln(f, texto)
				f.Close()
				w.WriteHeader(200)
			}
		}
	case "lectura":

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
